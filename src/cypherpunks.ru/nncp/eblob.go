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
	"io"

	"cypherpunks.ru/balloon"
	"github.com/davecgh/go-xdr/xdr2"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/twofish"
)

const (
	DefaultS = 1 << 20 / 32
	DefaultT = 1 << 4
	DefaultP = 2
)

var (
	MagicNNCPBv1 [8]byte = [8]byte{'N', 'N', 'C', 'P', 'B', 0, 0, 1}
)

type EBlob struct {
	Magic [8]byte
	SCost uint32
	TCost uint32
	PCost uint32
	Salt  *[32]byte
	Blob  []byte
	MAC   *[blake2b.Size256]byte
}

// Create an encrypted blob. sCost -- memory space requirements, number
// of hash-output sized (32 bytes) blocks. tCost -- time requirements,
// number of rounds. pCost -- number of parallel jobs.
func NewEBlob(sCost, tCost, pCost int, password, data []byte) ([]byte, error) {
	salt := new([32]byte)
	var err error
	if _, err = rand.Read(salt[:]); err != nil {
		return nil, err
	}
	key := balloon.H(blake256, password, salt[:], sCost, tCost, pCost)
	kdf := hkdf.New(blake256, key, nil, MagicNNCPBv1[:])
	keyEnc := make([]byte, 32)
	if _, err = io.ReadFull(kdf, keyEnc); err != nil {
		return nil, err
	}
	keyAuth := make([]byte, 64)
	if _, err = io.ReadFull(kdf, keyAuth); err != nil {
		return nil, err
	}
	ciph, err := twofish.NewCipher(keyEnc)
	if err != nil {
		return nil, err
	}
	ctr := cipher.NewCTR(ciph, make([]byte, twofish.BlockSize))
	mac, err := blake2b.New256(keyAuth)
	if err != nil {
		return nil, err
	}
	var blob bytes.Buffer
	mw := io.MultiWriter(&blob, mac)
	ae := &cipher.StreamWriter{S: ctr, W: mw}
	if _, err = ae.Write(data); err != nil {
		return nil, err
	}
	macTag := new([blake2b.Size256]byte)
	mac.Sum(macTag[:0])
	eblob := EBlob{
		Magic: MagicNNCPBv1,
		SCost: uint32(sCost),
		TCost: uint32(tCost),
		PCost: uint32(pCost),
		Salt:  salt,
		Blob:  blob.Bytes(),
		MAC:   macTag,
	}
	var eblobRaw bytes.Buffer
	if _, err = xdr.Marshal(&eblobRaw, &eblob); err != nil {
		return nil, err
	}
	return eblobRaw.Bytes(), nil
}

func DeEBlob(eblobRaw, password []byte) ([]byte, error) {
	var eblob EBlob
	var err error
	if _, err = xdr.Unmarshal(bytes.NewReader(eblobRaw), &eblob); err != nil {
		return nil, err
	}
	if eblob.Magic != MagicNNCPBv1 {
		return nil, BadMagic
	}
	key := balloon.H(
		blake256,
		password,
		eblob.Salt[:],
		int(eblob.SCost),
		int(eblob.TCost),
		int(eblob.PCost),
	)
	kdf := hkdf.New(blake256, key, nil, MagicNNCPBv1[:])
	keyEnc := make([]byte, 32)
	if _, err = io.ReadFull(kdf, keyEnc); err != nil {
		return nil, err
	}
	keyAuth := make([]byte, 64)
	if _, err = io.ReadFull(kdf, keyAuth); err != nil {
		return nil, err
	}
	ciph, err := twofish.NewCipher(keyEnc)
	if err != nil {
		return nil, err
	}
	ctr := cipher.NewCTR(ciph, make([]byte, twofish.BlockSize))
	mac, err := blake2b.New256(keyAuth)
	if err != nil {
		return nil, err
	}
	var blob bytes.Buffer
	tr := io.TeeReader(bytes.NewReader(eblob.Blob), mac)
	ae := &cipher.StreamReader{S: ctr, R: tr}
	if _, err = io.Copy(&blob, ae); err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(mac.Sum(nil), eblob.MAC[:]) != 1 {
		return nil, errors.New("Unauthenticated blob")
	}
	return blob.Bytes(), nil
}
