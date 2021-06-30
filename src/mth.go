/*
NNCP -- Node to Node copy, utilities for store-and-forward data exchange
Copyright (C) 2016-2021 Sergey Matveev <stargrave@stargrave.org>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, version 3 of the License.

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
	"errors"
	"io"

	"lukechampine.com/blake3"
)

const (
	MTHBlockSize = 128 * 1024
	MTHSize      = 32
)

var (
	MTHLeafKey = blake3.Sum256([]byte("NNCP MTH LEAF"))
	MTHNodeKey = blake3.Sum256([]byte("NNCP MTH NODE"))
)

type MTHEventType uint8

const (
	MTHEventAppend  MTHEventType = iota
	MTHEventPrepend MTHEventType = iota
	MTHEventFold    MTHEventType = iota
)

type MTHEvent struct {
	Type  MTHEventType
	Level int
	Ctr   int
	Hsh   []byte
}

type MTH struct {
	size        int64
	PrependSize int64
	skip        int64
	skipped     bool
	hasher      *blake3.Hasher
	hashes      [][MTHSize]byte
	buf         *bytes.Buffer
	finished    bool
	Events      chan MTHEvent
	PktName     string
}

func MTHNew(size, offset int64) *MTH {
	mth := MTH{
		hasher: blake3.New(MTHSize, MTHLeafKey[:]),
		buf:    bytes.NewBuffer(make([]byte, 0, 2*MTHBlockSize)),
	}
	if size == 0 {
		return &mth
	}
	prepends := int(offset / MTHBlockSize)
	skip := MTHBlockSize - (offset - int64(prepends)*MTHBlockSize)
	if skip == MTHBlockSize {
		skip = 0
	} else if skip > 0 {
		prepends++
	}
	prependSize := int64(prepends * MTHBlockSize)
	if prependSize > size {
		prependSize = size
	}
	if offset+skip > size {
		skip = size - offset
	}
	mth.size = size
	mth.PrependSize = prependSize
	mth.skip = skip
	mth.hashes = make([][MTHSize]byte, prepends, 1+size/MTHBlockSize)
	return &mth
}

func (mth *MTH) Reset() { panic("not implemented") }

func (mth *MTH) Size() int { return MTHSize }

func (mth *MTH) BlockSize() int { return MTHBlockSize }

func (mth *MTH) Write(data []byte) (int, error) {
	if mth.finished {
		return 0, errors.New("already Sum()ed")
	}
	n, err := mth.buf.Write(data)
	if err != nil {
		return n, err
	}
	if mth.skip > 0 && int64(mth.buf.Len()) >= mth.skip {
		mth.buf.Next(int(mth.skip))
		mth.skip = 0
	}
	for mth.buf.Len() >= MTHBlockSize {
		if _, err = mth.hasher.Write(mth.buf.Next(MTHBlockSize)); err != nil {
			return n, err
		}
		h := new([MTHSize]byte)
		mth.hasher.Sum(h[:0])
		mth.hasher.Reset()
		mth.hashes = append(mth.hashes, *h)
		if mth.Events != nil {
			mth.Events <- MTHEvent{
				MTHEventAppend,
				0, len(mth.hashes) - 1,
				mth.hashes[len(mth.hashes)-1][:],
			}
		}
	}
	return n, err
}

func (mth *MTH) PrependFrom(r io.Reader) (int, error) {
	if mth.finished {
		return 0, errors.New("already Sum()ed")
	}
	var err error
	buf := make([]byte, MTHBlockSize)
	var i, n, read int
	fullsize := mth.PrependSize
	les := LEs{{"Pkt", mth.PktName}, {"FullSize", fullsize}, {"Size", 0}}
	for mth.PrependSize >= MTHBlockSize {
		n, err = io.ReadFull(r, buf)
		read += n
		mth.PrependSize -= MTHBlockSize
		if err != nil {
			return read, err
		}
		if _, err = mth.hasher.Write(buf); err != nil {
			panic(err)
		}
		mth.hasher.Sum(mth.hashes[i][:0])
		mth.hasher.Reset()
		if mth.Events != nil {
			mth.Events <- MTHEvent{MTHEventPrepend, 0, i, mth.hashes[i][:]}
		}
		if mth.PktName != "" {
			les[len(les)-1].V = int64(read)
			Progress("check", les)
		}
		i++
	}
	if mth.PrependSize > 0 {
		n, err = io.ReadFull(r, buf[:mth.PrependSize])
		read += n
		if err != nil {
			return read, err
		}
		if _, err = mth.hasher.Write(buf[:mth.PrependSize]); err != nil {
			panic(err)
		}
		mth.hasher.Sum(mth.hashes[i][:0])
		mth.hasher.Reset()
		if mth.Events != nil {
			mth.Events <- MTHEvent{MTHEventPrepend, 0, i, mth.hashes[i][:]}
		}
		if mth.PktName != "" {
			les[len(les)-1].V = fullsize
			Progress("check", les)
		}
	}
	return read, nil
}

func (mth *MTH) Sum(b []byte) []byte {
	if mth.finished {
		return append(b, mth.hashes[0][:]...)
	}
	if mth.buf.Len() > 0 {
		b := mth.buf.Next(MTHBlockSize)
		if _, err := mth.hasher.Write(b); err != nil {
			panic(err)
		}
		h := new([MTHSize]byte)
		mth.hasher.Sum(h[:0])
		mth.hasher.Reset()
		mth.hashes = append(mth.hashes, *h)
		if mth.Events != nil {
			mth.Events <- MTHEvent{
				MTHEventAppend,
				0, len(mth.hashes) - 1,
				mth.hashes[len(mth.hashes)-1][:],
			}
		}
	}
	switch len(mth.hashes) {
	case 0:
		h := new([MTHSize]byte)
		if _, err := mth.hasher.Write(nil); err != nil {
			panic(err)
		}
		mth.hasher.Sum(h[:0])
		mth.hasher.Reset()
		mth.hashes = append(mth.hashes, *h)
		if mth.Events != nil {
			mth.Events <- MTHEvent{MTHEventAppend, 0, 0, mth.hashes[0][:]}
		}
		fallthrough
	case 1:
		mth.hashes = append(mth.hashes, mth.hashes[0])
		if mth.Events != nil {
			mth.Events <- MTHEvent{MTHEventAppend, 0, 1, mth.hashes[1][:]}
		}
	}
	mth.hasher = blake3.New(MTHSize, MTHNodeKey[:])
	level := 1
	for len(mth.hashes) != 1 {
		hashesUp := make([][MTHSize]byte, 0, 1+len(mth.hashes)/2)
		pairs := (len(mth.hashes) / 2) * 2
		for i := 0; i < pairs; i += 2 {
			if _, err := mth.hasher.Write(mth.hashes[i][:]); err != nil {
				panic(err)
			}
			if _, err := mth.hasher.Write(mth.hashes[i+1][:]); err != nil {
				panic(err)
			}
			h := new([MTHSize]byte)
			mth.hasher.Sum(h[:0])
			mth.hasher.Reset()
			hashesUp = append(hashesUp, *h)
			if mth.Events != nil {
				mth.Events <- MTHEvent{
					MTHEventFold,
					level, len(hashesUp) - 1,
					hashesUp[len(hashesUp)-1][:],
				}
			}
		}
		if len(mth.hashes)%2 == 1 {
			hashesUp = append(hashesUp, mth.hashes[len(mth.hashes)-1])
			if mth.Events != nil {
				mth.Events <- MTHEvent{
					MTHEventAppend,
					level, len(hashesUp) - 1,
					hashesUp[len(hashesUp)-1][:],
				}
			}
		}
		mth.hashes = hashesUp
		level++
	}
	mth.finished = true
	if mth.Events != nil {
		close(mth.Events)
	}
	return append(b, mth.hashes[0][:]...)
}
