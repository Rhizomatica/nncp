// NNCP -- Node to Node copy, utilities for store-and-forward data exchange
// Copyright (C) 2016-2026 Sergey Matveev <stargrave@stargrave.org>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, version 3 of the License.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package nncp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"io"
	"os"
	"path/filepath"
	"testing"
	"testing/quick"
)

// v3WireBytes builds an NNCPPv3 plain packet byte by byte, the way NNCP up
// to 8.13.0 writes it, without going through the Pkt struct.
func v3WireBytes(typ PktType, nice uint8, path []byte) []byte {
	var b bytes.Buffer
	b.Write([]byte{'N', 'N', 'C', 'P', 'P', 0, 0, 3})
	var u [4]byte
	binary.BigEndian.PutUint32(u[:], uint32(typ))
	b.Write(u[:])
	binary.BigEndian.PutUint32(u[:], uint32(nice))
	b.Write(u[:])
	binary.BigEndian.PutUint32(u[:], uint32(len(path)))
	b.Write(u[:])
	// fixed-size opaque [255]byte, padded to a multiple of 4
	fixed := make([]byte, 256)
	copy(fixed, path)
	b.Write(fixed)
	return b.Bytes()
}

func TestPktReadV3Wire(t *testing.T) {
	f := func(path []byte, nice uint8) bool {
		if len(path) > MaxPathSize {
			path = path[:MaxPathSize]
		}
		raw := v3WireBytes(PktTypeExec, nice, path)
		if int64(len(raw)) != PktOverhead {
			return false
		}
		pkt, err := PktRead(bytes.NewReader(raw))
		if err != nil {
			return false
		}
		if pkt.Magic != MagicNNCPPv3.B || pkt.Type != PktTypeExec ||
			pkt.Nice != nice || !bytes.Equal(pkt.Path, path) {
			return false
		}
		if pkt.Overhead() != PktOverhead {
			return false
		}
		// what we write for a v3 recipient is byte-identical to NNCP 8.13.0
		var buf bytes.Buffer
		if _, err = PktMarshal(&buf, pkt, false); err != nil {
			return false
		}
		return bytes.Equal(buf.Bytes(), raw)
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func TestPktMarshalV4RoundTrip(t *testing.T) {
	f := func(path []byte, nice uint8) bool {
		if len(path) > MaxPathSize {
			path = path[:MaxPathSize]
		}
		pkt, err := NewPkt(PktTypeFile, nice, path)
		if err != nil {
			return false
		}
		var buf bytes.Buffer
		n, err := PktMarshal(&buf, pkt, true)
		if err != nil || int64(n) != PktV4Overhead(len(path)) {
			return false
		}
		got, err := PktRead(&buf)
		if err != nil {
			return false
		}
		return got.Magic == MagicNNCPPv4.B && got.Nice == nice &&
			bytes.Equal(got.Path, path) &&
			got.Overhead() == PktV4Overhead(len(path))
	}
	if err := quick.Check(f, nil); err != nil {
		t.Error(err)
	}
}

func v4Header(pathLen uint32) []byte {
	var b bytes.Buffer
	b.Write(MagicNNCPPv4.B[:])
	var u [4]byte
	binary.BigEndian.PutUint32(u[:], uint32(PktTypeFile))
	b.Write(u[:])
	binary.BigEndian.PutUint32(u[:], 0)
	b.Write(u[:])
	binary.BigEndian.PutUint32(u[:], pathLen)
	b.Write(u[:])
	return b.Bytes()
}

func TestPktReadV4PathBound(t *testing.T) {
	// exactly the limit is fine
	ok := append(v4Header(MaxPathSize), make([]byte, MaxPathSize+1)...)
	if _, err := PktRead(bytes.NewReader(ok)); err != nil {
		t.Fatalf("path of %d bytes rejected: %v", MaxPathSize, err)
	}
	// one byte over, with the data present
	over := append(v4Header(MaxPathSize+1), make([]byte, MaxPathSize+1)...)
	if _, err := PktRead(bytes.NewReader(over)); err == nil {
		t.Fatal("path over MaxPathSize accepted")
	}
	// a huge declared length must fail without trying to read or allocate it
	if _, err := PktRead(bytes.NewReader(v4Header(0x7fffffff))); err == nil {
		t.Fatal("2 GiB path length accepted")
	}
}

func TestPktMarshalRejectsLongPath(t *testing.T) {
	pkt := &PktV4{Type: PktTypeFile, Path: make([]byte, MaxPathSize+1)}
	for _, v4 := range []bool{false, true} {
		if _, err := PktMarshal(io.Discard, pkt, v4); err == nil {
			t.Errorf("v4=%v: path over MaxPathSize marshalled", v4)
		}
	}
}

// The recipient's pktv4 setting picks the plain packet format, and the
// payload size recovered from the encrypted size matches in both formats.
func TestPktEncWriteOptIn(t *testing.T) {
	our, err := NewNodeGenerate()
	if err != nil {
		t.Fatal(err)
	}
	their, err := NewNodeGenerate()
	if err != nil {
		t.Fatal(err)
	}
	nodes := map[NodeId]*Node{*our.Id: our.Their()}
	for _, v4 := range []bool{false, true} {
		for _, dataSize := range []int{0, 1, 1000, EncBlkSize, EncBlkSize + 1, 3 * EncBlkSize} {
			data := make([]byte, dataSize)
			if _, err = io.ReadFull(rand.Reader, data); err != nil {
				t.Fatal(err)
			}
			pkt, err := NewPkt(PktTypeExec, 0, []byte("rmail\x00root"))
			if err != nil {
				t.Fatal(err)
			}
			recipient := their.Their()
			recipient.PktV4 = v4
			var ct bytes.Buffer
			if _, _, err = PktEncWrite(
				our, recipient, pkt, 0, 0, MaxFileSize, 0,
				bytes.NewReader(data), &ct,
			); err != nil {
				t.Fatal(err)
			}
			encSize := int64(ct.Len())
			var pt bytes.Buffer
			if _, _, _, err = PktEncRead(their, nodes, &ct, &pt, true, nil); err != nil {
				t.Fatal(err)
			}
			got, err := PktRead(bytes.NewReader(pt.Bytes()))
			if err != nil {
				t.Fatal(err)
			}
			want := MagicNNCPPv3.B
			if v4 {
				want = MagicNNCPPv4.B
			}
			if got.Magic != want {
				t.Errorf("v4=%v: plain packet magic %v", v4, got.Magic)
			}
			if size := pktSizeWithoutEnc(encSize, got.Overhead()); size != int64(dataSize) {
				t.Errorf("v4=%v data=%d: payload size %d", v4, dataSize, size)
			}
		}
	}
}

func TestCfgDirPktV4(t *testing.T) {
	node, err := NewNodeGenerate()
	if err != nil {
		t.Fatal(err)
	}
	cfgRaw := `{
		spool: /tmp/spool
		log: /tmp/log
		self: {
			id: ` + Base32Codec.EncodeToString(node.Id[:]) + `
			exchpub: ` + Base32Codec.EncodeToString(node.ExchPub[:]) + `
			exchprv: ` + Base32Codec.EncodeToString(node.ExchPrv[:]) + `
			signpub: ` + Base32Codec.EncodeToString(node.SignPub[:]) + `
			signprv: ` + Base32Codec.EncodeToString(node.SignPrv[:]) + `
			noiseprv: ` + Base32Codec.EncodeToString(node.NoisePrv[:]) + `
			noisepub: ` + Base32Codec.EncodeToString(node.NoisePub[:]) + `
		}
		neigh: {
			self: {
				id: ` + Base32Codec.EncodeToString(node.Id[:]) + `
				exchpub: ` + Base32Codec.EncodeToString(node.ExchPub[:]) + `
				signpub: ` + Base32Codec.EncodeToString(node.SignPub[:]) + `
			}
			v4peer: {
				id: ` + Base32Codec.EncodeToString(node.Id[:]) + `
				exchpub: ` + Base32Codec.EncodeToString(node.ExchPub[:]) + `
				signpub: ` + Base32Codec.EncodeToString(node.SignPub[:]) + `
				pktv4: true
			}
			v3peer: {
				id: ` + Base32Codec.EncodeToString(node.Id[:]) + `
				exchpub: ` + Base32Codec.EncodeToString(node.ExchPub[:]) + `
				signpub: ` + Base32Codec.EncodeToString(node.SignPub[:]) + `
			}
		}
		areas: {
			v4area: {
				id: ` + Base32Codec.EncodeToString(node.Id[:]) + `
				subs: []
				pktv4: true
			}
		}
	}`
	cfg, err := CfgParse([]byte(cfgRaw))
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "cfg")
	if err = CfgToDir(dir, cfg); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(filepath.Join(dir, "neigh", "v4peer", "pktv4")); err != nil {
		t.Error("neigh pktv4 not saved")
	}
	if _, err = os.Stat(filepath.Join(dir, "neigh", "v3peer", "pktv4")); err == nil {
		t.Error("neigh pktv4 saved for a v3 peer")
	}
	back, err := DirToCfg(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !back.Neigh["v4peer"].PktV4 || back.Neigh["v3peer"].PktV4 {
		t.Error("neigh pktv4 did not round-trip")
	}
	if !back.Areas["v4area"].PktV4 {
		t.Error("area pktv4 did not round-trip")
	}
}
