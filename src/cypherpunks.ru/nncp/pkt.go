/*
NNCP -- Node to Node copy, utilities for store-and-forward data exchange
Copyright (C) 2016-2019 Sergey Matveev <stargrave@stargrave.org>

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
	"crypto/rand"
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"

	"chacha20"
	"github.com/davecgh/go-xdr/xdr2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/curve25519"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/nacl/box"
)

type PktType uint8

const (
	EncBlkSize = 128 * (1 << 10)
	KDFXOFSize = 2*(32+64) + 32

	PktTypeFile PktType = iota
	PktTypeFreq PktType = iota
	PktTypeExec PktType = iota
	PktTypeTrns PktType = iota

	MaxPathSize = 1<<8 - 1

	NNCPBundlePrefix = "NNCP"
)

var (
	MagicNNCPPv2 [8]byte = [8]byte{'N', 'N', 'C', 'P', 'P', 0, 0, 2}
	MagicNNCPEv3 [8]byte = [8]byte{'N', 'N', 'C', 'P', 'E', 0, 0, 3}
	BadMagic     error   = errors.New("Unknown magic number")
	BadPktType   error   = errors.New("Unknown packet type")

	PktOverhead    int64
	PktEncOverhead int64
)

type Pkt struct {
	Magic   [8]byte
	Type    PktType
	Nice    uint8
	PathLen uint8
	Path    *[MaxPathSize]byte
}

type PktTbs struct {
	Magic     [8]byte
	Nice      uint8
	Sender    *NodeId
	Recipient *NodeId
	ExchPub   *[32]byte
}

type PktEnc struct {
	Magic     [8]byte
	Nice      uint8
	Sender    *NodeId
	Recipient *NodeId
	ExchPub   *[32]byte
	Sign      *[ed25519.SignatureSize]byte
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
		Magic:     MagicNNCPEv3,
		Nice:      123,
		Sender:    dummyId,
		Recipient: dummyId,
		ExchPub:   new([32]byte),
		Sign:      new([ed25519.SignatureSize]byte),
	}
	n, err = xdr.Marshal(&buf, pktEnc)
	if err != nil {
		panic(err)
	}
	PktEncOverhead = int64(n)
}

func NewPkt(typ PktType, nice uint8, path []byte) (*Pkt, error) {
	if len(path) > MaxPathSize {
		return nil, errors.New("Too long path")
	}
	pkt := Pkt{
		Magic:   MagicNNCPPv2,
		Type:    typ,
		Nice:    nice,
		PathLen: uint8(len(path)),
		Path:    new([MaxPathSize]byte),
	}
	copy(pkt.Path[:], path)
	return &pkt, nil
}

type DevZero struct{}

func (d DevZero) Read(b []byte) (n int, err error) {
	for n = 0; n < len(b); n++ {
		b[n] = 0
	}
	return
}

func ae(keyEnc *[32]byte, r io.Reader, w io.Writer) (int, error) {
	var blkCtr uint64
	ciphNonce := new([16]byte)
	ciphCtr := ciphNonce[8:]
	buf := make([]byte, EncBlkSize)
	var n int
	var written int
	var err error
	for {
		n, err = io.ReadFull(r, buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			if err != io.ErrUnexpectedEOF {
				return written + n, err
			}
		}
		written += n
		blkCtr++
		binary.BigEndian.PutUint64(ciphCtr, blkCtr)
		chacha20.XORKeyStream(buf[:n], buf[:n], ciphNonce, keyEnc)
		if _, err = w.Write(buf[:n]); err != nil {
			return written, err
		}
	}
	return written, nil
}

func PktEncWrite(
	our *NodeOur,
	their *Node,
	pkt *Pkt,
	nice uint8,
	size, padSize int64,
	data io.Reader,
	out io.Writer) error {
	pubEph, prvEph, err := box.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	var pktBuf bytes.Buffer
	if _, err := xdr.Marshal(&pktBuf, pkt); err != nil {
		return err
	}
	tbs := PktTbs{
		Magic:     MagicNNCPEv3,
		Nice:      nice,
		Sender:    our.Id,
		Recipient: their.Id,
		ExchPub:   pubEph,
	}
	var tbsBuf bytes.Buffer
	if _, err = xdr.Marshal(&tbsBuf, &tbs); err != nil {
		return err
	}
	signature := new([ed25519.SignatureSize]byte)
	copy(signature[:], ed25519.Sign(our.SignPrv, tbsBuf.Bytes()))
	pktEnc := PktEnc{
		Magic:     MagicNNCPEv3,
		Nice:      nice,
		Sender:    our.Id,
		Recipient: their.Id,
		ExchPub:   pubEph,
		Sign:      signature,
	}
	if _, err = xdr.Marshal(out, &pktEnc); err != nil {
		return err
	}
	sharedKey := new([32]byte)
	curve25519.ScalarMult(sharedKey, prvEph, their.ExchPub)
	kdf, err := blake2b.NewXOF(KDFXOFSize, sharedKey[:])
	if err != nil {
		return err
	}
	if _, err = kdf.Write(MagicNNCPEv3[:]); err != nil {
		return err
	}

	keyEnc := new([32]byte)
	if _, err = io.ReadFull(kdf, keyEnc[:]); err != nil {
		return err
	}
	keyAuth := make([]byte, 64)
	if _, err = io.ReadFull(kdf, keyAuth); err != nil {
		return err
	}
	mac, err := blake2b.New256(keyAuth)
	if err != nil {
		return err
	}

	sizeBuf := make([]byte, 8)
	binary.BigEndian.PutUint64(sizeBuf, uint64(size))
	chacha20.XORKeyStream(sizeBuf, sizeBuf, new([16]byte), keyEnc)
	if _, err = out.Write(sizeBuf); err != nil {
		return err
	}
	if _, err = mac.Write(sizeBuf); err != nil {
		return err
	}
	if _, err = out.Write(mac.Sum(nil)); err != nil {
		return err
	}

	if _, err = io.ReadFull(kdf, keyEnc[:]); err != nil {
		return err
	}
	if _, err = io.ReadFull(kdf, keyAuth); err != nil {
		return err
	}
	mac, err = blake2b.New256(keyAuth)
	if err != nil {
		return err
	}
	lr := io.LimitedReader{R: data, N: size}
	mr := io.MultiReader(&pktBuf, &lr)
	mw := io.MultiWriter(out, mac)
	fullSize := pktBuf.Len() + int(size)
	written, err := ae(keyEnc, mr, mw)
	if err != nil {
		return err
	}
	if written != fullSize {
		return io.ErrUnexpectedEOF
	}
	if _, err = out.Write(mac.Sum(nil)); err != nil {
		return err
	}
	if padSize > 0 {
		if _, err = io.ReadFull(kdf, keyEnc[:]); err != nil {
			return err
		}
		lr = io.LimitedReader{R: DevZero{}, N: padSize}
		written, err = ae(keyEnc, &lr, out)
		if err != nil {
			return err
		}
		if written != int(padSize) {
			return io.ErrUnexpectedEOF
		}
	}
	return nil
}

func TbsVerify(our *NodeOur, their *Node, pktEnc *PktEnc) (bool, error) {
	tbs := PktTbs{
		Magic:     MagicNNCPEv3,
		Nice:      pktEnc.Nice,
		Sender:    their.Id,
		Recipient: our.Id,
		ExchPub:   pktEnc.ExchPub,
	}
	var tbsBuf bytes.Buffer
	if _, err := xdr.Marshal(&tbsBuf, &tbs); err != nil {
		return false, err
	}
	return ed25519.Verify(their.SignPub, tbsBuf.Bytes(), pktEnc.Sign[:]), nil
}

func PktEncRead(
	our *NodeOur,
	nodes map[NodeId]*Node,
	data io.Reader,
	out io.Writer) (*Node, int64, error) {
	var pktEnc PktEnc
	_, err := xdr.Unmarshal(data, &pktEnc)
	if err != nil {
		return nil, 0, err
	}
	if pktEnc.Magic != MagicNNCPEv3 {
		return nil, 0, BadMagic
	}
	their, known := nodes[*pktEnc.Sender]
	if !known {
		return nil, 0, errors.New("Unknown sender")
	}
	if *pktEnc.Recipient != *our.Id {
		return nil, 0, errors.New("Invalid recipient")
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
	kdf, err := blake2b.NewXOF(KDFXOFSize, sharedKey[:])
	if err != nil {
		return their, 0, err
	}
	if _, err = kdf.Write(MagicNNCPEv3[:]); err != nil {
		return their, 0, err
	}

	keyEnc := new([32]byte)
	if _, err = io.ReadFull(kdf, keyEnc[:]); err != nil {
		return their, 0, err
	}
	keyAuth := make([]byte, 64)
	if _, err = io.ReadFull(kdf, keyAuth); err != nil {
		return their, 0, err
	}
	mac, err := blake2b.New256(keyAuth)
	if err != nil {
		return their, 0, err
	}

	sizeBuf := make([]byte, 8)
	if _, err = io.ReadFull(data, sizeBuf); err != nil {
		return their, 0, err
	}
	if _, err = mac.Write(sizeBuf); err != nil {
		return their, 0, err
	}
	tag := make([]byte, blake2b.Size256)
	if _, err = io.ReadFull(data, tag); err != nil {
		return their, 0, err
	}
	if subtle.ConstantTimeCompare(mac.Sum(nil), tag) != 1 {
		return their, 0, errors.New("Unauthenticated size")
	}
	chacha20.XORKeyStream(sizeBuf, sizeBuf, new([16]byte), keyEnc)
	size := int64(binary.BigEndian.Uint64(sizeBuf))

	if _, err = io.ReadFull(kdf, keyEnc[:]); err != nil {
		return their, size, err
	}
	if _, err = io.ReadFull(kdf, keyAuth); err != nil {
		return their, size, err
	}
	mac, err = blake2b.New256(keyAuth)
	if err != nil {
		return their, 0, err
	}

	fullSize := PktOverhead + size - 8 - 2*blake2b.Size256
	lr := io.LimitedReader{R: data, N: fullSize}
	tr := io.TeeReader(&lr, mac)
	written, err := ae(keyEnc, tr, out)
	if err != nil {
		return their, int64(written), err
	}
	if written != int(fullSize) {
		return their, int64(written), io.ErrUnexpectedEOF
	}
	if _, err = io.ReadFull(data, tag); err != nil {
		return their, size, err
	}
	if subtle.ConstantTimeCompare(mac.Sum(nil), tag) != 1 {
		return their, size, errors.New("Unauthenticated payload")
	}
	return their, size, nil
}
