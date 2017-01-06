/*
NNCP -- Node-to-Node CoPy
Copyright (C) 2016-2017 Sergey Matveev <stargrave@stargrave.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package nncp

import (
	"bytes"
	"testing"
	"testing/quick"

	"github.com/davecgh/go-xdr/xdr2"
)

func TestPktEncWrite(t *testing.T) {
	nodeOur, err := NewNodeGenerate()
	if err != nil {
		panic(err)
	}
	nodeTheir, err := NewNodeGenerate()
	if err != nil {
		panic(err)
	}
	f := func(path string, pathSize uint8, data [1 << 16]byte, size uint16) bool {
		dataR := bytes.NewReader(data[:])
		var ct bytes.Buffer
		if len(path) > int(pathSize) {
			path = path[:int(pathSize)]
		}
		pkt, err := NewPkt(PktTypeFile, path)
		if err != nil {
			panic(err)
		}
		err = PktEncWrite(nodeOur, nodeTheir.Their(), pkt, 123, int64(size), dataR, &ct)
		if err != nil {
			return false
		}
		var pktEnc PktEnc
		if _, err = xdr.Unmarshal(&ct, &pktEnc); err != nil {
			return false
		}
		if *pktEnc.Sender != *nodeOur.Id {
			return false
		}
		if pktEnc.Size != uint64(ct.Len()) {
			return false
		}
		return true
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestPktEncRead(t *testing.T) {
	node1, err := NewNodeGenerate()
	if err != nil {
		panic(err)
	}
	node2, err := NewNodeGenerate()
	if err != nil {
		panic(err)
	}
	f := func(path string, pathSize uint8, data [1 << 16]byte, size uint16) bool {
		dataR := bytes.NewReader(data[:])
		var ct bytes.Buffer
		if len(path) > int(pathSize) {
			path = path[:int(pathSize)]
		}
		pkt, err := NewPkt(PktTypeFile, path)
		if err != nil {
			panic(err)
		}
		err = PktEncWrite(node1, node2.Their(), pkt, 123, int64(size), dataR, &ct)
		if err != nil {
			return false
		}
		var pt bytes.Buffer
		nodes := make(map[NodeId]*Node)
		nodes[*node1.Id] = node1.Their()
		node, err := PktEncRead(node2, nodes, &ct, &pt)
		if err != nil {
			return false
		}
		if *node.Id != *node1.Id {
			return false
		}
		var pktBuf bytes.Buffer
		xdr.Marshal(&pktBuf, &pkt)
		return bytes.Compare(pt.Bytes(), append(pktBuf.Bytes(), data[:int(size)]...)) == 0
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}
