// NNCP -- Node to Node copy, utilities for store-and-forward data exchange
// Copyright (C) 2016-2026 Sergey Matveev <stargrave@stargrave.org>
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
	"log"
	"net"
	"sync"
	"time"
)

// HFListener listens for incoming HF modem connections on a VARA/Mercury TNC.
// It connects to the TNC, sends initialization commands (including LISTEN ON),
// and waits for incoming CONNECTED events. Only one connection is active at
// a time (HF radio is single-channel).
type HFListener struct {
	cfg      *addrConfig
	mu       sync.Mutex
	closed   bool
	acceptCh chan *HFConn
	closeCh  chan struct{}
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

	l := &HFListener{
		cfg:      cfg,
		acceptCh: make(chan *HFConn),
		closeCh:  make(chan struct{}),
	}

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
	return nil
}

// Addr returns the listener's address.
func (l *HFListener) Addr() net.Addr {
	return hfListenerAddr{l.cfg.tncHost}
}

// listenLoop continuously connects to the TNC and waits for incoming
// connections. When a connection arrives (CONNECTED event), it delivers
// the HFConn via acceptCh, then waits for disconnection before
// re-entering the listening state.
func (l *HFListener) listenLoop() {
	defer close(l.acceptCh)

	for {
		select {
		case <-l.closeCh:
			return
		default:
		}

		conn, err := l.waitForIncoming()
		if err != nil {
			l.mu.Lock()
			closed := l.closed
			l.mu.Unlock()
			if closed {
				return
			}
			log.Printf("hfmodem: listener error: %v, retrying in 5s", err)
			select {
			case <-l.closeCh:
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}

		// Deliver the connection
		select {
		case l.acceptCh <- conn:
		case <-l.closeCh:
			conn.Close()
			return
		}

		// Wait for this connection to end before accepting another
		<-conn.ctrlDone
	}
}

// waitForIncoming connects to the TNC, initializes it with LISTEN ON,
// and blocks until a CONNECTED event arrives.
func (l *HFListener) waitForIncoming() (*HFConn, error) {
	conn, err := varaDial(l.cfg)
	if err != nil {
		return nil, fmt.Errorf("connecting to TNC: %w", err)
	}

	// Wait for CONNECTED event from the control reader
	// The control reader goroutine is already running from varaDial
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-l.closeCh:
			conn.ctrlConn.Close()
			conn.dataConn.Close()
			return nil, net.ErrClosed

		case <-conn.ctrlDone:
			// Control reader exited without connecting
			conn.ctrlConn.Close()
			conn.dataConn.Close()
			return nil, fmt.Errorf("TNC control connection lost")

		case <-ticker.C:
			conn.mu.Lock()
			isConn := conn.connected
			conn.mu.Unlock()
			if isConn {
				return conn, nil
			}
		}
	}
}
