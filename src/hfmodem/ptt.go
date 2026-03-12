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
// +build !nohfmodem

package hfmodem

import (
	"fmt"
	"net"
	"time"
)

// PTTKeyer controls push-to-talk on a radio.
type PTTKeyer interface {
	KeyOn() error
	KeyOff() error
	Close() error
}

// RadioStatusKeyer extends PTTKeyer with radio status updates.
// Implemented by keyers that can display connection status on the radio
// (e.g., Hermes sBitx controller).
type RadioStatusKeyer interface {
	PTTKeyer
	SetConnected(connected bool)
	SetBitrate(bitrate uint32)
	SetSNR(snr int32)
	SetBytesRx(bytes int32)
	SetBytesTx(bytes int32)
}

// NewPTTKeyer creates a PTT keyer based on the type string.
// Supported types:
//   - "hamlib"  — connects to rigctld TCP server (addr = "host:port", default "localhost:4532")
//   - "hermes" — uses Hermes sBitx radio controller SysV SHM interface (addr ignored)
func NewPTTKeyer(pttType, addr string) (PTTKeyer, error) {
	switch pttType {
	case "hamlib":
		return newHamlibKeyer(addr)
	case "hermes":
		return newHermesKeyer(addr)
	default:
		return nil, fmt.Errorf("unsupported PTT type: %s", pttType)
	}
}

// hamlibKeyer controls PTT via hamlib's rigctld TCP protocol.
// Sends "T 1\n" for key on and "T 0\n" for key off.
type hamlibKeyer struct {
	conn net.Conn
}

func newHamlibKeyer(addr string) (*hamlibKeyer, error) {
	if addr == "" {
		addr = "localhost:4532"
	}
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, fmt.Errorf("connecting to rigctld at %s: %w", addr, err)
	}
	return &hamlibKeyer{conn: conn}, nil
}

func (k *hamlibKeyer) KeyOn() error {
	_, err := k.conn.Write([]byte("T 1\n"))
	return err
}

func (k *hamlibKeyer) KeyOff() error {
	_, err := k.conn.Write([]byte("T 0\n"))
	return err
}

func (k *hamlibKeyer) Close() error {
	return k.conn.Close()
}
