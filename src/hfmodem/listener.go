// NNCP -- Node to Node copy, utilities for store-and-forward data exchange
// Copyright (C) 2026 Rhizomatica <rafael@rhizomatica.org>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program. If not, see <http://www.gnu.org/licenses/>.

//go:build !nohfmodem

package hfmodem

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

// HFListener listens for incoming HF modem connections on a VARA/Mercury TNC.
// It connects to the TNC once (persistent TCP session), sends initialization
// commands (including LISTEN ON), and waits for incoming CONNECTED events.
// Multiple HF radio sessions are handled within a single TNC TCP session,
// matching the behavior of the reference C client (mercury-connector/vara.c).
//
// The listener also supports outgoing calls via Dial(), which sends CONNECT
// on the existing TNC control channel. This is essential because Mercury/VARA
// TNCs only allow a single control client TCP connection — if a separate
// process connects, it kicks the existing client.
type HFListener struct {
	cfg      *addrConfig
	mu       sync.Mutex
	closed   bool
	acceptCh chan *HFConn
	closeCh  chan struct{}
	pttKeyer PTTKeyer

	// TNC session state (protected by tncMu)
	tncMu    sync.Mutex
	ctrlConn net.Conn // current TNC control connection (nil when not connected)

	// Dial synchronization: when non-nil, the next CONNECTED event is
	// routed to dialCh instead of acceptCh. Protected by mu.
	dialCh chan *HFConn
}

// hfListenerAddr implements net.Addr for the listener.
type hfListenerAddr struct {
	addr string
}

func (a hfListenerAddr) Network() string { return "hf" }
func (a hfListenerAddr) String() string  { return a.addr }

// NewListener creates an HF modem listener.
// addr format: vara://tnc_ip:port/?mycall=CALLSIGN&bw=2300
// (no remote callsign needed for listening)
func NewListener(addr string) (*HFListener, error) {
	cfg, err := parseAddr(addr)
	if err != nil {
		return nil, err
	}

	var ptt PTTKeyer
	if cfg.pttType != "" {
		ptt, err = NewPTTKeyer(cfg.pttType, cfg.pttAddr)
		if err != nil {
			return nil, fmt.Errorf("creating PTT keyer: %w", err)
		}
	}

	l := &HFListener{
		cfg:      cfg,
		pttKeyer: ptt,
		acceptCh: make(chan *HFConn),
		closeCh:  make(chan struct{}),
	}

	// Start Unix socket proxy so nncp-call can dial through this
	// listener's TNC connection instead of opening a competing one.
	l.startProxyServer()

	go l.listenLoop()
	return l, nil
}

// Accept blocks until an incoming HF connection arrives.
func (l *HFListener) Accept() (net.Conn, error) {
	select {
	case conn, ok := <-l.acceptCh:
		if !ok {
			return nil, net.ErrClosed
		}
		return conn, nil
	case <-l.closeCh:
		return nil, net.ErrClosed
	}
}

// Close shuts down the listener.
func (l *HFListener) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	close(l.closeCh)
	if l.pttKeyer != nil {
		l.pttKeyer.Close()
	}
	return nil
}

// Addr returns the listener's address.
func (l *HFListener) Addr() net.Addr {
	return hfListenerAddr{l.cfg.tncHost}
}

// CloseCh returns a channel that is closed when the listener shuts down.
func (l *HFListener) CloseCh() <-chan struct{} {
	return l.closeCh
}

// Dial initiates an outgoing HF call through the listener's existing TNC
// connection. This avoids creating a second TCP connection to the TNC,
// which would kick the listener (Mercury/VARA only allow one control client).
//
// addr format: vara://tnc_ip:port/REMOTE_CALL?mycall=X&bw=2300
// Only the remote callsign is extracted; the TNC connection is reused.
func (l *HFListener) Dial(addr string) (net.Conn, error) {
	cfg, err := parseAddr(addr)
	if err != nil {
		return nil, err
	}
	if cfg.remoteCall == "" {
		return nil, fmt.Errorf("remote callsign required for outbound connection")
	}

	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil, net.ErrClosed
	}
	l.mu.Unlock()

	l.tncMu.Lock()
	ctrl := l.ctrlConn
	l.tncMu.Unlock()
	if ctrl == nil {
		return nil, fmt.Errorf("TNC not connected")
	}

	// Set up channel to receive the CONNECTED event from controlReader
	dialCh := make(chan *HFConn, 1)
	l.mu.Lock()
	if l.dialCh != nil {
		l.mu.Unlock()
		return nil, fmt.Errorf("another dial is already in progress")
	}
	l.dialCh = dialCh
	l.mu.Unlock()

	defer func() {
		l.mu.Lock()
		l.dialCh = nil
		l.mu.Unlock()
	}()

	// Send CONNECT command on the existing control channel
	cmd := fmt.Sprintf("CONNECT %s %s", l.cfg.localCall, cfg.remoteCall)
	log.Printf("hfmodem: dial: sending %q", cmd)
	if err := sendCtrlCmd(ctrl, cmd); err != nil {
		return nil, fmt.Errorf("sending CONNECT: %w", err)
	}

	// Wait for CONNECTED response or failure
	select {
	case conn := <-dialCh:
		log.Printf("hfmodem: dial: connected to %s", cfg.remoteCall)
		return conn, nil
	case <-time.After(120 * time.Second):
		sendCtrlCmd(ctrl, "DISCONNECT")
		return nil, fmt.Errorf("dial to %s timed out", cfg.remoteCall)
	case <-l.closeCh:
		return nil, net.ErrClosed
	}
}

// listenLoop manages the TNC TCP connection lifecycle. It connects to the
// TNC, initializes it, and runs the control reader. If the TNC TCP
// connection drops, it reconnects after a delay. This matches the C
// reference client which connects to the TNC once at startup.
func (l *HFListener) listenLoop() {
	defer close(l.acceptCh)

	for {
		select {
		case <-l.closeCh:
			return
		default:
		}

		err := l.runTNCSession()
		l.mu.Lock()
		closed := l.closed
		l.mu.Unlock()
		if closed {
			return
		}
		if err != nil {
			log.Printf("hfmodem: listener: %v, reconnecting in 5s", err)
		}
		select {
		case <-l.closeCh:
			return
		case <-time.After(5 * time.Second):
		}
	}
}

// runTNCSession connects to the TNC, sends init commands, and runs the
// persistent control reader. Multiple HF radio sessions are handled within
// a single TNC TCP session. Returns only when the TCP connection drops or
// the listener is closed.
func (l *HFListener) runTNCSession() error {
	host, portStr, err := net.SplitHostPort(l.cfg.tncHost)
	if err != nil {
		return fmt.Errorf("parsing TNC address: %w", err)
	}
	ctrlPort, err := strconv.Atoi(portStr)
	if err != nil {
		return fmt.Errorf("parsing TNC port: %w", err)
	}
	dataPort := ctrlPort + 1

	ctrlConn, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:%d", host, ctrlPort), 10*time.Second)
	if err != nil {
		return fmt.Errorf("connecting to TNC control: %w", err)
	}

	dataConn, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:%d", host, dataPort), 10*time.Second)
	if err != nil {
		ctrlConn.Close()
		return fmt.Errorf("connecting to TNC data: %w", err)
	}

	log.Printf("hfmodem: listener: connected to TNC at %s", l.cfg.tncHost)

	// Store ctrlConn for Dial() to use
	l.tncMu.Lock()
	l.ctrlConn = ctrlConn
	l.tncMu.Unlock()

	// Start control reader BEFORE sending init commands.
	// This matches the C reference client which starts the RX thread
	// before the TX thread that sends commands.
	readerDone := make(chan struct{})
	go l.controlReader(ctrlConn, dataConn, readerDone)

	// Send initialization commands
	cmds := []string{
		fmt.Sprintf("MYCALL %s", l.cfg.localCall),
		"LISTEN ON",
		"PUBLIC OFF",
		"COMPRESSION OFF",
		fmt.Sprintf("BW%s", l.cfg.bw),
	}
	for _, cmd := range cmds {
		log.Printf("hfmodem: listener init: sending %q", cmd)
		if err := sendCtrlCmd(ctrlConn, cmd); err != nil {
			ctrlConn.Close()
			dataConn.Close()
			<-readerDone
			l.tncMu.Lock()
			l.ctrlConn = nil
			l.tncMu.Unlock()
			return fmt.Errorf("TNC init %q: %w", cmd, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	log.Printf("hfmodem: listener: initialized, waiting for connections")

	// Block until control reader exits (TCP dropped) or listener closed
	select {
	case <-readerDone:
		// Control reader exited — TCP connection dropped
		l.tncMu.Lock()
		l.ctrlConn = nil
		l.tncMu.Unlock()
		ctrlConn.Close()
		dataConn.Close()
		return fmt.Errorf("TNC connection lost")
	case <-l.closeCh:
		// Listener is shutting down — close TCP to unblock reader
		l.tncMu.Lock()
		l.ctrlConn = nil
		l.tncMu.Unlock()
		ctrlConn.Close()
		dataConn.Close()
		<-readerDone
		return nil
	}
}

// controlReader reads TNC control messages in a loop. Unlike the per-connection
// varaControlReader in vara.go, this reader does NOT exit on DISCONNECTED —
// it continues reading so the same TNC TCP session can handle multiple HF
// radio connections sequentially.
//
// When a Dial() is pending (l.dialCh != nil), CONNECTED events are routed
// to the dial channel instead of the accept channel.
func (l *HFListener) controlReader(
	ctrlConn, dataConn net.Conn,
	done chan struct{},
) {
	defer close(done)

	var currentConn *HFConn
	var connMu sync.Mutex

	scanner := bufio.NewScanner(ctrlConn)
	scanner.Split(scanCR)

	log.Printf("hfmodem: listener control reader started for %s", l.cfg.localCall)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		log.Printf("hfmodem: listener ctrl-raw: [%s]", line)

		switch {
		case strings.HasPrefix(line, "CONNECTED"):
			// Parse remote callsign from "CONNECTED CALLSIGN"
			remoteCall := ""
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				remoteCall = parts[1]
			}
			log.Printf("hfmodem: listener: connection established with %s", remoteCall)

			// Close any lingering previous connection
			connMu.Lock()
			if currentConn != nil {
				currentConn.mu.Lock()
				currentConn.connected = false
				currentConn.mu.Unlock()
				select {
				case <-currentConn.ctrlDone:
				default:
					close(currentConn.ctrlDone)
				}
			}
			connMu.Unlock()

			conn := &HFConn{
				ctrlConn:      ctrlConn,
				dataConn:      dataConn,
				modemType:     l.cfg.modemType,
				localCall:     l.cfg.localCall,
				ctrlDone:      make(chan struct{}),
				connectedCh:   make(chan struct{}),
				pttKeyer:      l.pttKeyer,
				listenerOwned: true,
				connected:     true,
				remoteAddr:    remoteCall,
				localAddr:     l.cfg.localCall,
			}
			close(conn.connectedCh) // already connected

			connMu.Lock()
			currentConn = conn
			connMu.Unlock()

			if l.pttKeyer != nil {
				if rsk, ok := l.pttKeyer.(RadioStatusKeyer); ok {
					rsk.SetConnected(true)
				}
			}

			// Route to Dial() if pending, otherwise to Accept()
			l.mu.Lock()
			dialCh := l.dialCh
			l.mu.Unlock()

			if dialCh != nil {
				dialCh <- conn
			} else {
				select {
				case l.acceptCh <- conn:
				case <-l.closeCh:
					return
				}
			}

		case strings.HasPrefix(line, "DISCONNECTED"):
			log.Printf("hfmodem: listener: disconnected, ready for next connection")
			connMu.Lock()
			c := currentConn
			currentConn = nil
			connMu.Unlock()
			if c != nil {
				c.mu.Lock()
				c.connected = false
				c.mu.Unlock()
				select {
				case <-c.ctrlDone:
				default:
					close(c.ctrlDone)
				}
			}
			if l.pttKeyer != nil {
				if rsk, ok := l.pttKeyer.(RadioStatusKeyer); ok {
					rsk.SetConnected(false)
				}
			}

		case strings.HasPrefix(line, "BUFFER"):
			connMu.Lock()
			c := currentConn
			connMu.Unlock()
			if c != nil {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if n, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
						c.mu.Lock()
						c.tncBuffer = n
						c.mu.Unlock()
					}
				}
			}

		case strings.HasPrefix(line, "PTT ON"):
			if l.pttKeyer != nil {
				if err := l.pttKeyer.KeyOn(); err != nil {
					log.Printf("hfmodem: PTT ON error: %v", err)
				}
			}

		case strings.HasPrefix(line, "PTT OFF"):
			if l.pttKeyer != nil {
				if err := l.pttKeyer.KeyOff(); err != nil {
					log.Printf("hfmodem: PTT OFF error: %v", err)
				}
			}

		case line == "IAMALIVE":
			// Watchdog keepalive, ignore

		case strings.HasPrefix(line, "SN"):
			log.Printf("hfmodem: %s", line)
			if l.pttKeyer != nil {
				if rsk, ok := l.pttKeyer.(RadioStatusKeyer); ok {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						if n, err := strconv.ParseInt(parts[1], 10, 32); err == nil {
							rsk.SetSNR(int32(n))
						}
					}
				}
			}

		case strings.HasPrefix(line, "BITRATE"):
			log.Printf("hfmodem: %s", line)
			if l.pttKeyer != nil {
				if rsk, ok := l.pttKeyer.(RadioStatusKeyer); ok {
					parts := strings.Fields(line)
					if len(parts) >= 2 {
						if n, err := strconv.ParseUint(parts[1], 10, 32); err == nil {
							rsk.SetBitrate(uint32(n))
						}
					}
				}
			}

		default:
			log.Printf("hfmodem: listener ctrl: %s", line)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("hfmodem: listener control reader error: %v", err)
	} else {
		log.Printf("hfmodem: listener control reader: EOF (TNC disconnected)")
	}

	// TNC TCP connection dropped — signal current connection if active
	connMu.Lock()
	c := currentConn
	currentConn = nil
	connMu.Unlock()
	if c != nil {
		c.mu.Lock()
		c.connected = false
		c.mu.Unlock()
		select {
		case <-c.ctrlDone:
		default:
			close(c.ctrlDone)
		}
	}
}
