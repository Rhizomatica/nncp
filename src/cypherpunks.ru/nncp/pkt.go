/*
NNCP -- Node to Node copy, utilities for store-and-forward data exchange
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
	"crypto/cipher"
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"hash"
	"io"

	"github.com/davecgh/go-xdr/xdr2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/twofish"
)

type PktType uint8

const (
	PktTypeFile PktType = iota
	PktTypeFreq PktType = iota
	PktTypeMail PktType = iota
	PktTypeTrns PktType = iota

	MaxPathSize = 1<<8 - 1

	DefaultNiceMail = 64
	DefaultNiceFreq = 64
	DefaultNiceFile = 196
)

var (
	MagicNNCPPv1 [8]byte = [8]byte{'N', 'N', 'C', 'P', 'P', 0, 0, 1}
	MagicNNCPEv1 [8]byte = [8]byte{'N', 'N', 'C', 'P', 'E', 0, 0, 1}
	BadMagic     error   = errors.New("Unknown magic number")
	BadPktType   error   = errors.New("Unknown packet type")

	PktOverhead    int64
	PktEncOverhead int64
)

type Pkt struct {
	Magic   [8]byte
	Type    PktType
	PathLen uint8
	Path    *[MaxPathSize]byte
}

type PktTbs struct {
	Magic     [8]byte
	Nice      uint8
	Recipient *NodeId
	Sender    *NodeId
	ExchPub   *[32]byte
}

type PktEnc struct {
	Magic   [8]byte
	Nice    uint8
	Sender  *NodeId
	ExchPub *[32]byte
	Sign    *[ed25519.SignatureSize]byte
}

func init() {
	pkt := Pkt{
		Type: PktTypeFile,
		Path: new([MaxPathSize]byte),
	}
	var buf bytes.Buffer
	n, err := xdr.Marshal(&buf, pkt)
	if err != nil {
		panic(err)
	}
	PktOverhead = 8 + blake2b.Size256 + int64(n) + blake2b.Size256
	buf.Reset()

	dummyId, err := NodeIdFromString("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	if err != nil {
		panic(err)
	}
	pktEnc := PktEnc{
		Magic:   MagicNNCPEv1,
		Nice:    123,
		Sender:  dummyId,
		ExchPub: new([32]byte),
		Sign:    new([ed25519.SignatureSize]byte),
	}
	n, err = xdr.Marshal(&buf, pktEnc)
	if err != nil {
		panic(err)
	}
	PktEncOverhead = int64(n)
}

func NewPkt(typ PktType, path string) (*Pkt, error) {
	pb := []byte(path)
	if len(pb) > MaxPathSize {
		return nil, errors.New("Too long path")
	}
	pkt := Pkt{
		Magic:   MagicNNCPPv1,
		Type:    typ,
		PathLen: uint8(len(pb)),
		Path:    new([MaxPathSize]byte),
	}
	copy(pkt.Path[:], pb)
	return &pkt, nil
}

func blake256() hash.Hash {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	return h
}

type DevZero struct{}

func (d DevZero) Read(b []byte) (n int, err error) {
	for n = 0; n < len(b); n++ {
		b[n] = 0
	}
	return
}

func PktEncWrite(our *NodeOur, their *Node, pkt *Pkt, nice uint8, size, padSize int64, data io.Reader, out io.Writer) error {
	pubEph, prvEph, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	var pktBuf bytes.Buffer
	if _, err := xdr.Marshal(&pktBuf, pkt); err != nil {
		return err
	}
	tbs := PktTbs{
		Magic:     MagicNNCPEv1,
		Nice:      nice,
		Recipient: their.Id,
		Sender:    our.Id,
		ExchPub:   pubEph,
	}
	var tbsBuf bytes.Buffer
	if _, err = xdr.Marshal(&tbsBuf, &tbs); err != nil {
		return err
	}
	signature := new([ed25519.SignatureSize]byte)
	copy(signature[:], ed25519.Sign(our.SignPrv, tbsBuf.Bytes()))
	pktEnc := PktEnc{
		Magic:   MagicNNCPEv1,
		Nice:    nice,
		Sender:  our.Id,
		ExchPub: pubEph,
		Sign:    signature,
	}
	if _, err = xdr.Marshal(out, &pktEnc); err != nil {
		return err
	}
	sharedKey := new([32]byte)
	curve25519.ScalarMult(sharedKey, prvEph, their.ExchPub)
	kdf := hkdf.New(blake256, sharedKey[:], nil, MagicNNCPEv1[:])

	keyEnc := make([]byte, 32)
	if _, err = io.ReadFull(kdf, keyEnc); err != nil {
		return err
	}
	keyAuth := make([]byte, 64)
	if _, err = io.ReadFull(kdf, keyAuth); err != nil {
		return err
	}

	ciph, err := twofish.NewCipher(keyEnc)
	if err != nil {
		return err
	}
	ctr := cipher.NewCTR(ciph, make([]byte, twofish.BlockSize))
	mac, err := blake2b.New256(keyAuth)
	if err != nil {
		return err
	}

	mw := io.MultiWriter(out, mac)
	ae := &cipher.StreamWriter{S: ctr, W: mw}
	usize := uint64(size)
	if _, err = xdr.Marshal(ae, &usize); err != nil {
		return err
	}
	ae.Close()
	out.Write(mac.Sum(nil))

	if _, err = io.ReadFull(kdf, keyEnc); err != nil {
		return err
	}
	if _, err = io.ReadFull(kdf, keyAuth); err != nil {
		return err
	}

	ciph, err = twofish.NewCipher(keyEnc)
	if err != nil {
		return err
	}
	ctr = cipher.NewCTR(ciph, make([]byte, twofish.BlockSize))
	mac, err = blake2b.New256(keyAuth)
	if err != nil {
		return err
	}

	mw = io.MultiWriter(out, mac)
	ae = &cipher.StreamWriter{S: ctr, W: mw}
	ae.Write(pktBuf.Bytes())
	if _, err = io.CopyN(ae, data, size); err != nil {
		return err
	}
	ae.Close()
	out.Write(mac.Sum(nil))

	if padSize > 0 {
		if _, err = io.ReadFull(kdf, keyEnc); err != nil {
			return err
		}
		ciph, err = twofish.NewCipher(keyEnc)
		if err != nil {
			return err
		}
		ctr = cipher.NewCTR(ciph, make([]byte, twofish.BlockSize))
		ae = &cipher.StreamWriter{S: ctr, W: out}
		if _, err = io.CopyN(ae, DevZero{}, padSize); err != nil {
			return err
		}
		ae.Close()
	}
	return nil
}

func TbsVerify(our *NodeOur, their *Node, pktEnc *PktEnc) (bool, error) {
	tbs := PktTbs{
		Magic:     MagicNNCPEv1,
		Nice:      pktEnc.Nice,
		Recipient: our.Id,
		Sender:    their.Id,
		ExchPub:   pktEnc.ExchPub,
	}
	var tbsBuf bytes.Buffer
	if _, err := xdr.Marshal(&tbsBuf, &tbs); err != nil {
		return false, err
	}
	return ed25519.Verify(their.SignPub, tbsBuf.Bytes(), pktEnc.Sign[:]), nil
}

func PktEncRead(our *NodeOur, nodes map[NodeId]*Node, data io.Reader, out io.Writer) (*Node, int64, error) {
	var pktEnc PktEnc
	_, err := xdr.Unmarshal(data, &pktEnc)
	if err != nil {
		return nil, 0, err
	}
	if pktEnc.Magic != MagicNNCPEv1 {
		return nil, 0, BadMagic
	}
	their, known := nodes[*pktEnc.Sender]
	if !known {
		return nil, 0, errors.New("Unknown sender")
	}
	verified, err := TbsVerify(our, their, &pktEnc)
	if err != nil {
		return nil, 0, err
	}
	if !verified {
		return their, 0, errors.New("Invalid signature")
	}
	sharedKey := new([32]byte)
	curve25519.ScalarMult(sharedKey, our.ExchPrv, pktEnc.ExchPub)
	kdf := hkdf.New(blake256, sharedKey[:], nil, MagicNNCPEv1[:])

	keyEnc := make([]byte, 32)
	if _, err = io.ReadFull(kdf, keyEnc); err != nil {
		return their, 0, err
	}
	keyAuth := make([]byte, 64)
	if _, err = io.ReadFull(kdf, keyAuth); err != nil {
		return their, 0, err
	}

	ciph, err := twofish.NewCipher(keyEnc)
	if err != nil {
		return their, 0, err
	}
	ctr := cipher.NewCTR(ciph, make([]byte, twofish.BlockSize))
	mac, err := blake2b.New256(keyAuth)
	if err != nil {
		return their, 0, err
	}

	tr := io.TeeReader(data, mac)
	ae := &cipher.StreamReader{S: ctr, R: tr}
	var usize uint64
	if _, err = xdr.Unmarshal(ae, &usize); err != nil {
		return their, 0, err
	}
	tag := make([]byte, blake2b.Size256)
	if _, err = io.ReadFull(data, tag); err != nil {
		return their, 0, err
	}
	if subtle.ConstantTimeCompare(mac.Sum(nil), tag) != 1 {
		return their, 0, errors.New("Unauthenticated size")
	}
	size := int64(usize)

	if _, err = io.ReadFull(kdf, keyEnc); err != nil {
		return their, size, err
	}
	if _, err = io.ReadFull(kdf, keyAuth); err != nil {
		return their, size, err
	}

	ciph, err = twofish.NewCipher(keyEnc)
	if err != nil {
		return their, size, err
	}
	ctr = cipher.NewCTR(ciph, make([]byte, twofish.BlockSize))
	mac, err = blake2b.New256(keyAuth)
	if err != nil {
		return their, size, err
	}

	tr = io.TeeReader(data, mac)
	ae = &cipher.StreamReader{S: ctr, R: tr}
	if _, err = io.CopyN(out, ae, PktOverhead+size-8-blake2b.Size256-blake2b.Size256); err != nil {
		return their, size, err
	}
	if _, err = io.ReadFull(data, tag); err != nil {
		return their, size, err
	}
	if subtle.ConstantTimeCompare(mac.Sum(nil), tag) != 1 {
		return their, size, errors.New("Unauthenticated payload")
	}
	return their, size, nil
}
