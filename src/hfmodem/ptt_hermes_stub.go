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

//go:build !nohfmodem && !linux
// +build !nohfmodem,!linux

package hfmodem

import "fmt"

func newHermesKeyer(_ string) (*hermesKeyer, error) {
	return nil, fmt.Errorf("hermes PTT keyer is only supported on Linux")
}

type hermesKeyer struct{}

func (k *hermesKeyer) KeyOn() error                { return nil }
func (k *hermesKeyer) KeyOff() error               { return nil }
func (k *hermesKeyer) Close() error                { return nil }
func (k *hermesKeyer) SetConnected(connected bool) {}
func (k *hermesKeyer) SetBitrate(bitrate uint32)   {}
func (k *hermesKeyer) SetSNR(snr int32)            {}
func (k *hermesKeyer) SetBytesRx(bytes int32)      {}
func (k *hermesKeyer) SetBytesTx(bytes int32)      {}
