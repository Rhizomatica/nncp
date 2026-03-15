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

//go:build nohfmodem
// +build nohfmodem

package hfmodem

import (
	"errors"
	"net"
)

var ErrNoHFModem = errors.New("HF modem support is not compiled in")

func NewConn(addr string) (net.Conn, error) {
	return nil, ErrNoHFModem
}

type HFListener struct{}

func NewListener(addr string) (*HFListener, error) {
	return nil, ErrNoHFModem
}

func (l *HFListener) Accept() (net.Conn, error) {
	return nil, ErrNoHFModem
}

func (l *HFListener) Close() error {
	return ErrNoHFModem
}

func (l *HFListener) Addr() net.Addr {
	return nil
}
