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
	"hash"
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
	Level int64
	Ctr   int64
	Hsh   []byte
}

type MTH interface {
	hash.Hash
	PrependFrom(r io.Reader) (int64, error)
	SetPktName(n string)
	PrependSize() int64
	Events() chan MTHEvent
}

type MTHFat struct {
	size        int64
	prependSize int64
	skip        int64
	skipped     bool
	hasher      *blake3.Hasher
	hashes      [][MTHSize]byte
	buf         *bytes.Buffer
	finished    bool
	events      chan MTHEvent
	pktName     string
}

func MTHFatNew(size, offset int64) MTH {
	mth := MTHFat{
		hasher: blake3.New(MTHSize, MTHLeafKey[:]),
		buf:    bytes.NewBuffer(make([]byte, 0, 2*MTHBlockSize)),
	}
	if size == 0 {
		return &mth
	}
	prepends := offset / MTHBlockSize
	skip := MTHBlockSize - (offset - prepends*MTHBlockSize)
	if skip == MTHBlockSize {
		skip = 0
	} else if skip > 0 {
		prepends++
	}
	prependSize := prepends * MTHBlockSize
	if prependSize > size {
		prependSize = size
	}
	if offset+skip > size {
		skip = size - offset
	}
	mth.size = size
	mth.prependSize = prependSize
	mth.skip = skip
	mth.hashes = make([][MTHSize]byte, prepends, 1+size/MTHBlockSize)
	return &mth
}

func (mth *MTHFat) Events() chan MTHEvent {
	mth.events = make(chan MTHEvent)
	return mth.events
}

func (mth *MTHFat) SetPktName(pktName string) { mth.pktName = pktName }

func (mth *MTHFat) PrependSize() int64 { return mth.prependSize }

func (mth *MTHFat) Reset() { panic("not implemented") }

func (mth *MTHFat) Size() int { return MTHSize }

func (mth *MTHFat) BlockSize() int { return MTHBlockSize }

func (mth *MTHFat) Write(data []byte) (int, error) {
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
		if mth.events != nil {
			mth.events <- MTHEvent{
				MTHEventAppend,
				0, int64(len(mth.hashes) - 1),
				mth.hashes[len(mth.hashes)-1][:],
			}
		}
	}
	return n, err
}

func (mth *MTHFat) PrependFrom(r io.Reader) (int64, error) {
	if mth.finished {
		return 0, errors.New("already Sum()ed")
	}
	var err error
	buf := make([]byte, MTHBlockSize)
	var n int
	var i, read int64
	fullsize := mth.prependSize
	les := LEs{{"Pkt", mth.pktName}, {"FullSize", fullsize}, {"Size", 0}}
	for mth.prependSize >= MTHBlockSize {
		n, err = io.ReadFull(r, buf)
		read += int64(n)
		mth.prependSize -= MTHBlockSize
		if err != nil {
			return read, err
		}
		if _, err = mth.hasher.Write(buf); err != nil {
			panic(err)
		}
		mth.hasher.Sum(mth.hashes[i][:0])
		mth.hasher.Reset()
		if mth.events != nil {
			mth.events <- MTHEvent{MTHEventPrepend, 0, i, mth.hashes[i][:]}
		}
		if mth.pktName != "" {
			les[len(les)-1].V = read
			Progress("check", les)
		}
		i++
	}
	if mth.prependSize > 0 {
		n, err = io.ReadFull(r, buf[:mth.prependSize])
		read += int64(n)
		if err != nil {
			return read, err
		}
		if _, err = mth.hasher.Write(buf[:mth.prependSize]); err != nil {
			panic(err)
		}
		mth.hasher.Sum(mth.hashes[i][:0])
		mth.hasher.Reset()
		if mth.events != nil {
			mth.events <- MTHEvent{MTHEventPrepend, 0, i, mth.hashes[i][:]}
		}
		if mth.pktName != "" {
			les[len(les)-1].V = fullsize
			Progress("check", les)
		}
	}
	return read, nil
}

func (mth *MTHFat) Sum(b []byte) []byte {
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
		if mth.events != nil {
			mth.events <- MTHEvent{
				MTHEventAppend,
				0, int64(len(mth.hashes) - 1),
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
		if mth.events != nil {
			mth.events <- MTHEvent{MTHEventAppend, 0, 0, mth.hashes[0][:]}
		}
		fallthrough
	case 1:
		mth.hashes = append(mth.hashes, mth.hashes[0])
		if mth.events != nil {
			mth.events <- MTHEvent{MTHEventAppend, 0, 1, mth.hashes[1][:]}
		}
	}
	mth.hasher = blake3.New(MTHSize, MTHNodeKey[:])
	level := int64(1)
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
			if mth.events != nil {
				mth.events <- MTHEvent{
					MTHEventFold,
					level, int64(len(hashesUp) - 1),
					hashesUp[len(hashesUp)-1][:],
				}
			}
		}
		if len(mth.hashes)%2 == 1 {
			hashesUp = append(hashesUp, mth.hashes[len(mth.hashes)-1])
			if mth.events != nil {
				mth.events <- MTHEvent{
					MTHEventAppend,
					level, int64(len(hashesUp) - 1),
					hashesUp[len(hashesUp)-1][:],
				}
			}
		}
		mth.hashes = hashesUp
		level++
	}
	mth.finished = true
	if mth.events != nil {
		close(mth.events)
	}
	return append(b, mth.hashes[0][:]...)
}

type MTHSeqEnt struct {
	l int64
	h [MTHSize]byte
}

type MTHSeq struct {
	hasherLeaf *blake3.Hasher
	hasherNode *blake3.Hasher
	hashes     []MTHSeqEnt
	buf        *bytes.Buffer
	events     chan MTHEvent
	ctrs       []int64
	finished   bool
}

func MTHSeqNew() *MTHSeq {
	mth := MTHSeq{
		hasherLeaf: blake3.New(MTHSize, MTHLeafKey[:]),
		hasherNode: blake3.New(MTHSize, MTHNodeKey[:]),
		buf:        bytes.NewBuffer(make([]byte, 0, 2*MTHBlockSize)),
		ctrs:       make([]int64, 1, 2),
	}
	return &mth
}

func (mth *MTHSeq) Reset() { panic("not implemented") }

func (mth *MTHSeq) Size() int { return MTHSize }

func (mth *MTHSeq) BlockSize() int { return MTHBlockSize }

func (mth *MTHSeq) PrependFrom(r io.Reader) (int64, error) {
	panic("must not reach that code")
}

func (mth *MTHSeq) Events() chan MTHEvent {
	mth.events = make(chan MTHEvent)
	return mth.events
}

func (mth *MTHSeq) SetPktName(pktName string) {}

func (mth *MTHSeq) PrependSize() int64 { return 0 }

func (mth *MTHSeq) leafAdd() {
	ent := MTHSeqEnt{l: 0}
	mth.hasherLeaf.Sum(ent.h[:0])
	mth.hasherLeaf.Reset()
	mth.hashes = append(mth.hashes, ent)
	if mth.events != nil {
		mth.events <- MTHEvent{
			MTHEventAppend, 0, mth.ctrs[0],
			mth.hashes[len(mth.hashes)-1].h[:],
		}
	}
	mth.ctrs[0]++
}

func (mth *MTHSeq) incr(l int64) {
	if int64(len(mth.ctrs)) <= l {
		mth.ctrs = append(mth.ctrs, 0)
	} else {
		mth.ctrs[l]++
	}
}

func (mth *MTHSeq) fold() {
	for len(mth.hashes) >= 2 {
		if mth.hashes[len(mth.hashes)-2].l != mth.hashes[len(mth.hashes)-1].l {
			break
		}
		if _, err := mth.hasherNode.Write(mth.hashes[len(mth.hashes)-2].h[:]); err != nil {
			panic(err)
		}
		if _, err := mth.hasherNode.Write(mth.hashes[len(mth.hashes)-1].h[:]); err != nil {
			panic(err)
		}
		mth.hashes = mth.hashes[:len(mth.hashes)-1]
		end := &mth.hashes[len(mth.hashes)-1]
		end.l++
		mth.incr(end.l)
		mth.hasherNode.Sum(end.h[:0])
		mth.hasherNode.Reset()
		if mth.events != nil {
			mth.events <- MTHEvent{MTHEventFold, end.l, mth.ctrs[end.l], end.h[:]}
		}
	}
}

func (mth *MTHSeq) Write(data []byte) (int, error) {
	if mth.finished {
		return 0, errors.New("already Sum()ed")
	}
	n, err := mth.buf.Write(data)
	if err != nil {
		return n, err
	}
	for mth.buf.Len() >= MTHBlockSize {
		if _, err = mth.hasherLeaf.Write(mth.buf.Next(MTHBlockSize)); err != nil {
			return n, err
		}
		mth.leafAdd()
		mth.fold()
	}
	return n, err
}

func (mth *MTHSeq) Sum(b []byte) []byte {
	if mth.finished {
		return append(b, mth.hashes[0].h[:]...)
	}
	if mth.buf.Len() > 0 {
		if _, err := mth.hasherLeaf.Write(mth.buf.Next(MTHBlockSize)); err != nil {
			panic(err)
		}
		mth.leafAdd()
		mth.fold()
	}
	switch mth.ctrs[0] {
	case 0:
		if _, err := mth.hasherLeaf.Write(nil); err != nil {
			panic(err)
		}
		mth.leafAdd()
		fallthrough
	case 1:
		mth.hashes = append(mth.hashes, mth.hashes[0])
		mth.ctrs[0]++
		if mth.events != nil {
			mth.events <- MTHEvent{
				MTHEventAppend, 0, mth.ctrs[0],
				mth.hashes[len(mth.hashes)-1].h[:],
			}
		}
		mth.fold()
	}
	for len(mth.hashes) >= 2 {
		l := mth.hashes[len(mth.hashes)-2].l
		mth.incr(l)
		mth.hashes[len(mth.hashes)-1].l = l
		if mth.events != nil {
			mth.events <- MTHEvent{
				MTHEventAppend, l, mth.ctrs[l],
				mth.hashes[len(mth.hashes)-1].h[:],
			}
		}
		mth.fold()
	}
	mth.finished = true
	if mth.events != nil {
		close(mth.events)
	}
	return append(b, mth.hashes[0].h[:]...)
}

func MTHNew(size, offset int64) MTH {
	if offset == 0 {
		return MTHSeqNew()
	}
	return MTHFatNew(size, offset)
}
