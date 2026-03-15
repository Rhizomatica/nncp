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
// +build !nohfmodem

package hfmodem

import (
	"bufio"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// varaConnect dials a VARA/Mercury TNC, initializes it, and connects to
// a remote station. Returns a net.Conn wrapping the data channel.
func varaConnect(cfg *addrConfig) (*HFConn, error) {
	conn, err := varaDial(cfg)
	if err != nil {
		return nil, err
	}

	// Send CONNECT command
	cmd := fmt.Sprintf("CONNECT %s %s", conn.localCall, cfg.remoteCall)
	if err := sendCtrlCmd(conn.ctrlConn, cmd); err != nil {
		conn.ctrlConn.Close()
		conn.dataConn.Close()
		return nil, fmt.Errorf("sending CONNECT: %w", err)
	}

	// Wait for CONNECTED response or failure
	select {
	case <-conn.connectedCh:
		// Successfully connected
	case <-conn.ctrlDone:
		// Control reader exited (DISCONNECTED or error) before connecting
		conn.dataConn.Close()
		conn.ctrlConn.Close()
		return nil, fmt.Errorf("connection to %s failed", cfg.remoteCall)
	case <-time.After(120 * time.Second):
		conn.ctrlConn.Close()
		conn.dataConn.Close()
		return nil, fmt.Errorf("connection to %s timed out", cfg.remoteCall)
	}

	return conn, nil
}

// varaDial connects to TNC TCP ports, sends init commands, and starts
// the control reader goroutine. Does NOT send CONNECT.
func varaDial(cfg *addrConfig) (*HFConn, error) {
	// Parse host:port to get control and data ports
	host, portStr, err := net.SplitHostPort(cfg.tncHost)
	if err != nil {
		return nil, fmt.Errorf("parsing TNC address: %w", err)
	}
	ctrlPort, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("parsing TNC port: %w", err)
	}
	dataPort := ctrlPort + 1

	// Connect to control and data TCP ports
	ctrlConn, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:%d", host, ctrlPort), 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connecting to TNC control: %w", err)
	}

	dataConn, err := net.DialTimeout("tcp",
		fmt.Sprintf("%s:%d", host, dataPort), 10*time.Second)
	if err != nil {
		ctrlConn.Close()
		return nil, fmt.Errorf("connecting to TNC data: %w", err)
	}

	var ptt PTTKeyer
	if cfg.pttType != "" {
		ptt, err = NewPTTKeyer(cfg.pttType, cfg.pttAddr)
		if err != nil {
			ctrlConn.Close()
			dataConn.Close()
			return nil, fmt.Errorf("creating PTT keyer: %w", err)
		}
	}

	conn := &HFConn{
		ctrlConn:    ctrlConn,
		dataConn:    dataConn,
		modemType:   cfg.modemType,
		localCall:   cfg.localCall,
		remoteAddr:  cfg.remoteCall,
		localAddr:   cfg.localCall,
		ctrlDone:    make(chan struct{}),
		connectedCh: make(chan struct{}),
		pttKeyer:    ptt,
	}

	// Send initialization commands
	if err := varaInit(conn, cfg); err != nil {
		ctrlConn.Close()
		dataConn.Close()
		return nil, err
	}

	// Start control reader goroutine
	go varaControlReader(conn)

	return conn, nil
}

// varaInit sends the VARA/Mercury initialization command sequence.
func varaInit(conn *HFConn, cfg *addrConfig) error {
	cmds := []string{
		fmt.Sprintf("MYCALL %s", conn.localCall),
		"LISTEN ON",
		"PUBLIC OFF",
		"COMPRESSION OFF",
		fmt.Sprintf("BW%s", cfg.bw),
	}
	if cfg.p2p {
		cmds = append(cmds, "P2P SESSION")
	}

	for _, cmd := range cmds {
		if err := sendCtrlCmd(conn.ctrlConn, cmd); err != nil {
			return fmt.Errorf("TNC init command %q: %w", cmd, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
	return nil
}

// varaControlReader reads CR-delimited status messages from the TNC
// control channel and updates HFConn state accordingly.
func varaControlReader(conn *HFConn) {
	defer close(conn.ctrlDone)

	scanner := bufio.NewScanner(conn.ctrlConn)
	scanner.Split(scanCR)

	for scanner.Scan() {
		if atomic.LoadInt32(&conn.closed) != 0 {
			return
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		switch {
		case strings.HasPrefix(line, "CONNECTED"):
			conn.mu.Lock()
			conn.connected = true
			conn.mu.Unlock()
			select {
			case <-conn.connectedCh:
			default:
				close(conn.connectedCh)
			}
			log.Printf("hfmodem: connected: %s", line)
			if rsk, ok := conn.pttKeyer.(RadioStatusKeyer); ok {
				rsk.SetConnected(true)
			}

		case strings.HasPrefix(line, "DISCONNECTED"):
			conn.mu.Lock()
			conn.connected = false
			conn.mu.Unlock()
			log.Printf("hfmodem: disconnected")
			if rsk, ok := conn.pttKeyer.(RadioStatusKeyer); ok {
				rsk.SetConnected(false)
			}
			return

		case strings.HasPrefix(line, "BUFFER"):
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				if n, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
					conn.mu.Lock()
					old := conn.tncBuffer
					conn.tncBuffer = n
					conn.mu.Unlock()
					// If buffer drained, data was transmitted
					_ = old
				}
			}

		case strings.HasPrefix(line, "PTT ON"):
			if conn.pttKeyer != nil {
				if err := conn.pttKeyer.KeyOn(); err != nil {
					log.Printf("hfmodem: PTT ON error: %v", err)
				}
			}

		case strings.HasPrefix(line, "PTT OFF"):
			if conn.pttKeyer != nil {
				if err := conn.pttKeyer.KeyOff(); err != nil {
					log.Printf("hfmodem: PTT OFF error: %v", err)
				}
			}

		case line == "IAMALIVE":
			// Watchdog, ignore

		case strings.HasPrefix(line, "SN"):
			log.Printf("hfmodem: %s", line)
			if rsk, ok := conn.pttKeyer.(RadioStatusKeyer); ok {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if n, err := strconv.ParseInt(parts[1], 10, 32); err == nil {
						rsk.SetSNR(int32(n))
					}
				}
			}

		case strings.HasPrefix(line, "BITRATE"):
			log.Printf("hfmodem: %s", line)
			if rsk, ok := conn.pttKeyer.(RadioStatusKeyer); ok {
				parts := strings.Fields(line)
				if len(parts) >= 2 {
					if n, err := strconv.ParseUint(parts[1], 10, 32); err == nil {
						rsk.SetBitrate(uint32(n))
					}
				}
			}

		default:
			log.Printf("hfmodem: ctrl: %s", line)
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("hfmodem: control reader error: %v", err)
	}
}

// scanCR is a bufio.SplitFunc that splits on \r (carriage return),
// matching the VARA/Mercury TNC control protocol delimiter.
func scanCR(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	for i, b := range data {
		if b == '\r' {
			return i + 1, data[:i], nil
		}
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}
