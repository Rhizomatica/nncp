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
	"io"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const ProxySocketPath = "/tmp/nncp-hfmodem.sock"

// startProxyServer starts a Unix socket server on the HFListener.
// When nncp-call needs to make an outgoing HF call, it connects to this
// socket instead of opening a second TCP connection to the TNC (which
// would kick the daemon's connection — Mercury/VARA only allow one
// control client).
//
// Protocol:
//  1. Client sends: DIAL <hf-address-url>\n
//  2. Server responds: OK\n (success) or ERR <message>\n (failure)
//  3. After OK, the socket becomes a transparent data bridge to the TNC
func (l *HFListener) startProxyServer() {
	os.Remove(ProxySocketPath)
	ln, err := net.Listen("unix", ProxySocketPath)
	if err != nil {
		log.Printf("hfmodem: proxy: failed to listen on %s: %v", ProxySocketPath, err)
		return
	}
	// Allow all local users to connect
	os.Chmod(ProxySocketPath, 0666)
	log.Printf("hfmodem: proxy: listening on %s", ProxySocketPath)

	// Clean up when listener closes
	go func() {
		<-l.closeCh
		ln.Close()
		os.Remove(ProxySocketPath)
	}()

	// Accept loop
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				// Listener closed
				return
			}
			go l.handleProxyClient(conn)
		}
	}()
}

// handleProxyClient handles a single nncp-call connection on the Unix socket.
// It reads the DIAL command, initiates the HF call through the shared TNC
// connection, and bridges data bidirectionally.
func (l *HFListener) handleProxyClient(clientConn net.Conn) {
	log.Printf("hfmodem: proxy: client connected")

	// Read DIAL command (byte-by-byte to avoid buffering ahead)
	line, err := readLine(clientConn)
	if err != nil {
		log.Printf("hfmodem: proxy: read error: %v", err)
		clientConn.Close()
		return
	}
	if !strings.HasPrefix(line, "DIAL ") {
		log.Printf("hfmodem: proxy: invalid command: %s", line)
		clientConn.Write([]byte("ERR invalid command\n"))
		clientConn.Close()
		return
	}
	addr := strings.TrimPrefix(line, "DIAL ")
	log.Printf("hfmodem: proxy: dial request: %s", addr)

	// Dial through listener's shared TNC connection
	conn, err := l.Dial(addr)
	if err != nil {
		log.Printf("hfmodem: proxy: dial failed: %v", err)
		clientConn.Write([]byte(fmt.Sprintf("ERR %s\n", err)))
		clientConn.Close()
		return
	}
	hfc := conn.(*HFConn)

	if _, err := clientConn.Write([]byte("OK\n")); err != nil {
		log.Printf("hfmodem: proxy: write OK failed: %v", err)
		hfc.Close()
		clientConn.Close()
		return
	}
	log.Printf("hfmodem: proxy: bridging data")

	// Bridge data bidirectionally between client and TNC
	var wg sync.WaitGroup
	clientGone := make(chan struct{})

	// TNC -> Client
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(clientConn, hfc)
	}()

	// Client -> TNC (uses hfc.Write for flow control)
	wg.Add(1)
	go func() {
		defer wg.Done()
		io.Copy(hfc, clientConn)
		close(clientGone)
	}()

	// Wait for HF disconnect or client disconnect
	select {
	case <-hfc.ctrlDone:
		log.Printf("hfmodem: proxy: HF session ended")
	case <-clientGone:
		log.Printf("hfmodem: proxy: client disconnected")
	case <-l.closeCh:
		log.Printf("hfmodem: proxy: listener shutting down")
	}

	// Clean up: send DISCONNECT if needed, interrupt blocking I/O
	hfc.Close()
	clientConn.Close()
	hfc.dataConn.SetReadDeadline(time.Now())

	wg.Wait()

	// Clear deadline so dataConn is ready for the next session
	hfc.dataConn.SetReadDeadline(time.Time{})
	log.Printf("hfmodem: proxy: session complete")
}

// proxyDial connects to the daemon's proxy Unix socket and requests an
// outgoing HF call. Returns a net.Conn wrapping the Unix socket that
// transparently bridges to the TNC data channel.
//
// If the proxy socket doesn't exist (daemon not running with -hfmodem),
// returns an error so the caller can fall back to direct TNC connection.
func proxyDial(addr string) (net.Conn, error) {
	conn, err := net.DialTimeout("unix", ProxySocketPath, 5*time.Second)
	if err != nil {
		return nil, err
	}

	// Send dial request
	if _, err := conn.Write([]byte(fmt.Sprintf("DIAL %s\n", addr))); err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy: write dial request: %w", err)
	}

	// Read response (byte-by-byte to avoid buffering ahead)
	resp, err := readLine(conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("proxy: read response: %w", err)
	}

	if resp == "OK" {
		cfg, _ := parseAddr(addr)
		remoteCall := ""
		localCall := ""
		if cfg != nil {
			remoteCall = cfg.remoteCall
			localCall = cfg.localCall
		}
		log.Printf("hfmodem: proxy: connected to %s via daemon", remoteCall)
		return &proxyConn{
			Conn:       conn,
			remoteCall: remoteCall,
			localCall:  localCall,
		}, nil
	}

	conn.Close()
	if strings.HasPrefix(resp, "ERR ") {
		return nil, fmt.Errorf("proxy dial: %s", strings.TrimPrefix(resp, "ERR "))
	}
	return nil, fmt.Errorf("proxy dial: unexpected response: %s", resp)
}

// proxyConn wraps a Unix socket connection with HF-appropriate net.Addr values.
type proxyConn struct {
	net.Conn
	remoteCall string
	localCall  string
}

func (c *proxyConn) RemoteAddr() net.Addr { return hfAddr{c.remoteCall} }
func (c *proxyConn) LocalAddr() net.Addr  { return hfAddr{c.localCall} }

// readLine reads a single \n-terminated line from conn without buffering
// ahead. This is critical for the proxy handshake — any buffered data
// would be consumed from the data stream.
func readLine(conn net.Conn) (string, error) {
	var buf []byte
	b := make([]byte, 1)
	for {
		n, err := conn.Read(b)
		if n > 0 {
			if b[0] == '\n' {
				return strings.TrimRight(string(buf), "\r"), nil
			}
			buf = append(buf, b[0])
		}
		if err != nil {
			return string(buf), err
		}
		if len(buf) > 4096 {
			return string(buf), fmt.Errorf("line too long")
		}
	}
}
