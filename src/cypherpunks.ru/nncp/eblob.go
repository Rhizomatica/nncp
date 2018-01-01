/*
NNCP -- Node to Node copy, utilities for store-and-forward data exchange
Copyright (C) 2016-2018 Sergey Matveev <stargrave@stargrave.org>

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
	"errors"
	"hash"
	"io"

	"chacha20"
	"cypherpunks.ru/balloon"
	"github.com/davecgh/go-xdr/xdr2"
	"golang.org/x/crypto/blake2b"
)

const (
	DefaultS = 1 << 20 / 32
	DefaultT = 1 << 4
	DefaultP = 2
)

var (
	MagicNNCPBv2 [8]byte = [8]byte{'N', 'N', 'C', 'P', 'B', 0, 0, 2}
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

func blake256() hash.Hash {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	return h
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
	kdf, err := blake2b.NewXOF(32+64, key)
	if err != nil {
		return nil, err
	}
	if _, err = kdf.Write(MagicNNCPBv2[:]); err != nil {
		return nil, err
	}
	keyEnc := new([32]byte)
	if _, err = io.ReadFull(kdf, keyEnc[:]); err != nil {
		return nil, err
	}
	keyAuth := make([]byte, 64)
	if _, err = io.ReadFull(kdf, keyAuth); err != nil {
		return nil, err
	}
	mac, err := blake2b.New256(keyAuth)
	if err != nil {
		return nil, err
	}
	chacha20.XORKeyStream(data, data, new([16]byte), keyEnc)
	if _, err = mac.Write(data); err != nil {
		return nil, err
	}
	macTag := new([blake2b.Size256]byte)
	mac.Sum(macTag[:0])
	eblob := EBlob{
		Magic: MagicNNCPBv2,
		SCost: uint32(sCost),
		TCost: uint32(tCost),
		PCost: uint32(pCost),
		Salt:  salt,
		Blob:  data,
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
	if eblob.Magic != MagicNNCPBv2 {
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
	kdf, err := blake2b.NewXOF(32+64, key)
	if err != nil {
		return nil, err
	}
	if _, err = kdf.Write(MagicNNCPBv2[:]); err != nil {
		return nil, err
	}
	keyEnc := new([32]byte)
	if _, err = io.ReadFull(kdf, keyEnc[:]); err != nil {
		return nil, err
	}
	keyAuth := make([]byte, 64)
	if _, err = io.ReadFull(kdf, keyAuth); err != nil {
		return nil, err
	}
	mac, err := blake2b.New256(keyAuth)
	if err != nil {
		return nil, err
	}
	if _, err = mac.Write(eblob.Blob); err != nil {
		return nil, err
	}
	if subtle.ConstantTimeCompare(mac.Sum(nil), eblob.MAC[:]) != 1 {
		return nil, errors.New("Unauthenticated blob")
	}
	chacha20.XORKeyStream(eblob.Blob, eblob.Blob, new([16]byte), keyEnc)
	return eblob.Blob, nil
}
