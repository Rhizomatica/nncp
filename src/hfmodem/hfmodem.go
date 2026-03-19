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
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	MaxVARABuffer = 8192
	CallsignFile  = "/etc/nncp-callsign"
)

type ModemType int

const (
	ModemVARA    ModemType = iota
	ModemMercury           // VARA-compatible protocol
)

// HFConn wraps TCP control+data connections to a TNC into a single
// net.Conn-compatible byte stream for use as an NNCP transport.
type HFConn struct {
	ctrlConn  net.Conn
	dataConn  net.Conn
	modemType ModemType
	localCall string

	mu        sync.Mutex
	tncBuffer int64 // current TNC buffer level from BUFFER messages
	connected bool

	closed int32 // atomic

	listenerOwned bool // true if TCP connections belong to a listener

	writeDeadline time.Time

	ctrlDone    chan struct{} // closed when control reader goroutine exits
	connectedCh chan struct{} // closed when CONNECTED event received

	pttKeyer PTTKeyer

	remoteAddr string
	localAddr  string
}

// hfAddr implements net.Addr for HF modem connections.
type hfAddr struct {
	callsign string
}

func (a hfAddr) Network() string { return "hf" }
func (a hfAddr) String() string  { return a.callsign }

func (c *HFConn) LocalAddr() net.Addr  { return hfAddr{c.localAddr} }
func (c *HFConn) RemoteAddr() net.Addr { return hfAddr{c.remoteAddr} }

func (c *HFConn) Read(p []byte) (int, error) {
	if atomic.LoadInt32(&c.closed) != 0 {
		return 0, net.ErrClosed
	}
	return c.dataConn.Read(p)
}

func (c *HFConn) Write(p []byte) (int, error) {
	if atomic.LoadInt32(&c.closed) != 0 {
		return 0, net.ErrClosed
	}

	// Write in chunks to respect TNC buffer flow control.
	// The TNC reports its buffer level via BUFFER messages; we must not
	// queue more than MaxVARABuffer bytes at a time.
	totalWritten := 0
	for len(p) > 0 {
		chunk := p
		if len(chunk) > MaxVARABuffer {
			chunk = chunk[:MaxVARABuffer]
		}

		// Flow control: block while TNC buffer is too full for this chunk
		for {
			c.mu.Lock()
			bufLevel := c.tncBuffer
			c.mu.Unlock()

			if bufLevel+int64(len(chunk)) <= MaxVARABuffer {
				break
			}

			if !c.writeDeadline.IsZero() && time.Now().After(c.writeDeadline) {
				if totalWritten > 0 {
					return totalWritten, os.ErrDeadlineExceeded
				}
				return 0, os.ErrDeadlineExceeded
			}

			select {
			case <-c.ctrlDone:
				if totalWritten > 0 {
					return totalWritten, net.ErrClosed
				}
				return 0, net.ErrClosed
			default:
			}
			time.Sleep(100 * time.Millisecond)
		}

		n, err := c.dataConn.Write(chunk)
		if err == nil {
			c.mu.Lock()
			c.tncBuffer += int64(n)
			c.mu.Unlock()
		}
		totalWritten += n
		if err != nil {
			return totalWritten, err
		}
		p = p[n:]
	}
	return totalWritten, nil
}

func (c *HFConn) Close() error {
	if !atomic.CompareAndSwapInt32(&c.closed, 0, 1) {
		return nil
	}
	sendCtrlCmd(c.ctrlConn, "DISCONNECT")
	// Wait briefly for DISCONNECTED response
	select {
	case <-c.ctrlDone:
	case <-time.After(5 * time.Second):
	}
	if c.listenerOwned {
		// TCP connections and PTT keyer belong to the listener
		return nil
	}
	if c.pttKeyer != nil {
		c.pttKeyer.Close()
	}
	c.dataConn.Close()
	return c.ctrlConn.Close()
}

func (c *HFConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	c.SetWriteDeadline(t)
	return nil
}

func (c *HFConn) SetReadDeadline(t time.Time) error {
	return c.dataConn.SetReadDeadline(t)
}

func (c *HFConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	c.writeDeadline = t
	c.mu.Unlock()
	return nil
}

// sendCtrlCmd sends a CR-terminated command to the TNC control channel.
func sendCtrlCmd(conn net.Conn, cmd string) error {
	_, err := conn.Write([]byte(cmd + "\r"))
	return err
}

// readCallsignFile reads the local callsign from /etc/nncp-callsign.
func readCallsignFile() (string, error) {
	data, err := os.ReadFile(CallsignFile)
	if err != nil {
		return "", fmt.Errorf("reading callsign: %w", err)
	}
	cs := strings.TrimSpace(string(data))
	if cs == "" {
		return "", fmt.Errorf("empty callsign in %s", CallsignFile)
	}
	return cs, nil
}

// parseAddr parses an HF modem address URL.
// Format: vara://tnc_ip:control_port/REMOTE_CALL?mycall=X&bw=2300&p2p=true
//
//	or: mercury://tnc_ip:control_port/REMOTE_CALL?mycall=X&bw=2300
type addrConfig struct {
	modemType  ModemType
	tncHost    string // ip:control_port
	remoteCall string
	localCall  string
	bw         string // "500", "2300", "2750"
	p2p        bool
	pttType    string // "", "hermes", "hamlib"
	pttAddr    string // serial path or hamlib host:port
}

func parseAddr(addr string) (*addrConfig, error) {
	u, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("parsing HF address: %w", err)
	}

	cfg := &addrConfig{
		tncHost: u.Host,
		bw:      "2300",
	}

	switch u.Scheme {
	case "vara":
		cfg.modemType = ModemVARA
	case "mercury":
		cfg.modemType = ModemMercury
	default:
		return nil, fmt.Errorf("unsupported HF modem scheme: %s", u.Scheme)
	}

	cfg.remoteCall = strings.TrimPrefix(u.Path, "/")

	q := u.Query()
	if mc := q.Get("mycall"); mc != "" {
		cfg.localCall = mc
	} else {
		cs, err := readCallsignFile()
		if err != nil {
			return nil, err
		}
		cfg.localCall = cs
	}

	if bw := q.Get("bw"); bw != "" {
		cfg.bw = bw
	}
	if q.Get("p2p") == "true" {
		cfg.p2p = true
	}
	cfg.pttType = q.Get("ptt")
	cfg.pttAddr = q.Get("pttaddr")

	return cfg, nil
}

// NewConn establishes an outbound HF modem connection.
// If nncp-daemon is running with -hfmodem (and has created a proxy socket),
// the call is routed through the daemon's existing TNC connection.
// Otherwise, it connects directly to the TNC.
func NewConn(addr string) (net.Conn, error) {
	// Try proxy first — daemon may hold the TNC connection
	conn, err := proxyDial(addr)
	if err == nil {
		return conn, nil
	}

	// No proxy available — connect directly to TNC
	cfg, err := parseAddr(addr)
	if err != nil {
		return nil, err
	}
	if cfg.remoteCall == "" {
		return nil, fmt.Errorf("remote callsign required for outbound connection")
	}

	return varaConnect(cfg)
}
