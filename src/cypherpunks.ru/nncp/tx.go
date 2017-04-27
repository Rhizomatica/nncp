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
	"bufio"
	"bytes"
	"compress/zlib"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/davecgh/go-xdr/xdr2"
	"golang.org/x/crypto/blake2b"
)

func (ctx *Ctx) Tx(node *Node, pkt *Pkt, nice uint8, size, minSize int64, src io.Reader) (*Node, error) {
	tmp, err := ctx.NewTmpFileWHash()
	if err != nil {
		return nil, err
	}
	hops := make([]*Node, 0, 1+len(node.Via))
	hops = append(hops, node)
	lastNode := node
	for i := len(node.Via); i > 0; i-- {
		lastNode = ctx.Neigh[*node.Via[i-1]]
		hops = append(hops, lastNode)
	}
	padSize := minSize - size - int64(len(hops))*(PktOverhead+PktEncOverhead)
	if padSize < 0 {
		padSize = 0
	}
	errs := make(chan error)
	curSize := size
	pipeR, pipeW := io.Pipe()
	go func(size int64, src io.Reader, dst io.WriteCloser) {
		ctx.LogD("tx", SDS{
			"node": hops[0].Id,
			"nice": strconv.Itoa(int(nice)),
			"size": strconv.FormatInt(size, 10),
		}, "wrote")
		errs <- PktEncWrite(ctx.Self, hops[0], pkt, nice, size, padSize, src, dst)
		dst.Close()
	}(curSize, src, pipeW)
	curSize += padSize

	var pipeRPrev io.Reader
	for i := 1; i < len(hops); i++ {
		pktTrans := Pkt{
			Magic:   MagicNNCPPv1,
			Type:    PktTypeTrns,
			PathLen: blake2b.Size256,
			Path:    new([MaxPathSize]byte),
		}
		copy(pktTrans.Path[:], hops[i-1].Id[:])
		curSize += PktOverhead + PktEncOverhead
		pipeRPrev = pipeR
		pipeR, pipeW = io.Pipe()
		go func(node *Node, pkt *Pkt, size int64, src io.Reader, dst io.WriteCloser) {
			ctx.LogD("tx", SDS{
				"node": node.Id,
				"nice": strconv.Itoa(int(nice)),
				"size": strconv.FormatInt(size, 10),
			}, "trns wrote")
			errs <- PktEncWrite(ctx.Self, node, pkt, nice, size, 0, src, dst)
			dst.Close()
		}(hops[i], &pktTrans, curSize, pipeRPrev, pipeW)
	}
	go func() {
		_, err := io.Copy(tmp.W, pipeR)
		errs <- err
	}()
	for i := 0; i <= len(hops); i++ {
		err = <-errs
		if err != nil {
			tmp.Fd.Close()
			return nil, err
		}
	}
	nodePath := filepath.Join(ctx.Spool, lastNode.Id.String())
	err = tmp.Commit(filepath.Join(nodePath, string(TTx)))
	os.Symlink(nodePath, filepath.Join(ctx.Spool, lastNode.Name))
	return lastNode, err
}

func (ctx *Ctx) TxFile(node *Node, nice uint8, srcPath, dstPath string, minSize int64) error {
	if dstPath == "" {
		dstPath = filepath.Base(srcPath)
	}
	dstPath = filepath.Clean(dstPath)
	if filepath.IsAbs(dstPath) {
		return errors.New("Relative destination path required")
	}
	pkt, err := NewPkt(PktTypeFile, dstPath)
	if err != nil {
		return err
	}
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()
	srcStat, err := src.Stat()
	if err != nil {
		return err
	}
	_, err = ctx.Tx(node, pkt, nice, srcStat.Size(), minSize, bufio.NewReader(src))
	if err == nil {
		ctx.LogI("tx", SDS{
			"type": "file",
			"node": node.Id,
			"nice": strconv.Itoa(int(nice)),
			"src":  srcPath,
			"dst":  dstPath,
			"size": strconv.FormatInt(srcStat.Size(), 10),
		}, "sent")
	} else {
		ctx.LogE("tx", SDS{
			"type": "file",
			"node": node.Id,
			"nice": strconv.Itoa(int(nice)),
			"src":  srcPath,
			"dst":  dstPath,
			"size": strconv.FormatInt(srcStat.Size(), 10),
			"err":  err,
		}, "sent")
	}
	return err
}

func (ctx *Ctx) TxFileChunked(node *Node, nice uint8, srcPath, dstPath string, minSize int64, chunkSize int64) error {
	if dstPath == "" {
		dstPath = filepath.Base(srcPath)
	}
	dstPath = filepath.Clean(dstPath)
	if filepath.IsAbs(dstPath) {
		return errors.New("Relative destination path required")
	}
	src, err := os.Open(srcPath)
	if err != nil {
		return err
	}
	defer src.Close()
	srcStat, err := src.Stat()
	if err != nil {
		return err
	}
	srcReader := bufio.NewReader(src)
	fileSize := srcStat.Size()
	leftSize := fileSize
	metaPkt := ChunkedMeta{
		Magic:     MagicNNCPMv1,
		FileSize:  uint64(fileSize),
		ChunkSize: uint64(chunkSize),
		Checksums: make([][32]byte, 0, (fileSize/chunkSize)+1),
	}
	for i := int64(0); i < (fileSize/chunkSize)+1; i++ {
		hsh := new([32]byte)
		metaPkt.Checksums = append(metaPkt.Checksums, *hsh)
	}
	var sizeToSend int64
	var hsh hash.Hash
	var pkt *Pkt
	var chunkNum int
	var path string
	for {
		if leftSize <= chunkSize {
			sizeToSend = leftSize
		} else {
			sizeToSend = chunkSize
		}
		path = dstPath + ChunkedSuffixPart + strconv.Itoa(chunkNum)
		pkt, err = NewPkt(PktTypeFile, path)
		if err != nil {
			return err
		}
		hsh, err = blake2b.New256(nil)
		if err != nil {
			return err
		}
		_, err = ctx.Tx(
			node,
			pkt,
			nice,
			sizeToSend,
			minSize,
			io.TeeReader(srcReader, hsh),
		)
		if err == nil {
			ctx.LogD("tx", SDS{
				"type": "file",
				"node": node.Id,
				"nice": strconv.Itoa(int(nice)),
				"src":  srcPath,
				"dst":  path,
				"size": strconv.FormatInt(sizeToSend, 10),
			}, "sent")
		} else {
			ctx.LogE("tx", SDS{
				"type": "file",
				"node": node.Id,
				"nice": strconv.Itoa(int(nice)),
				"src":  srcPath,
				"dst":  path,
				"size": strconv.FormatInt(sizeToSend, 10),
				"err":  err,
			}, "sent")
			return err
		}
		hsh.Sum(metaPkt.Checksums[chunkNum][:0])
		leftSize -= sizeToSend
		chunkNum++
		if leftSize == 0 {
			break
		}
	}
	var metaBuf bytes.Buffer
	_, err = xdr.Marshal(&metaBuf, metaPkt)
	if err != nil {
		return err
	}
	path = dstPath + ChunkedSuffixMeta
	pkt, err = NewPkt(PktTypeFile, path)
	if err != nil {
		return err
	}
	metaPktSize := int64(metaBuf.Len())
	_, err = ctx.Tx(node, pkt, nice, metaPktSize, minSize, &metaBuf)
	if err == nil {
		ctx.LogD("tx", SDS{
			"type": "file",
			"node": node.Id,
			"nice": strconv.Itoa(int(nice)),
			"src":  srcPath,
			"dst":  path,
			"size": strconv.FormatInt(metaPktSize, 10),
		}, "sent")
		ctx.LogI("tx", SDS{
			"type": "file",
			"node": node.Id,
			"nice": strconv.Itoa(int(nice)),
			"src":  srcPath,
			"dst":  dstPath,
			"size": strconv.FormatInt(fileSize, 10),
		}, "sent")
	} else {
		ctx.LogE("tx", SDS{
			"type": "file",
			"node": node.Id,
			"nice": strconv.Itoa(int(nice)),
			"src":  srcPath,
			"dst":  path,
			"size": strconv.FormatInt(metaPktSize, 10),
			"err":  err,
		}, "sent")
	}
	return err
}

func (ctx *Ctx) TxFreq(node *Node, nice uint8, srcPath, dstPath string, minSize int64) error {
	dstPath = filepath.Clean(dstPath)
	if filepath.IsAbs(dstPath) {
		return errors.New("Relative destination path required")
	}
	srcPath = filepath.Clean(srcPath)
	if filepath.IsAbs(srcPath) {
		return errors.New("Relative source path required")
	}
	pkt, err := NewPkt(PktTypeFreq, srcPath)
	if err != nil {
		return err
	}
	src := strings.NewReader(dstPath)
	size := int64(src.Len())
	_, err = ctx.Tx(node, pkt, nice, size, minSize, src)
	if err == nil {
		ctx.LogI("tx", SDS{
			"type": "freq",
			"node": node.Id,
			"nice": strconv.Itoa(int(nice)),
			"src":  srcPath,
			"dst":  dstPath,
		}, "sent")
	} else {
		ctx.LogE("tx", SDS{
			"type": "freq",
			"node": node.Id,
			"nice": strconv.Itoa(int(nice)),
			"src":  srcPath,
			"dst":  dstPath,
			"err":  err,
		}, "sent")
	}
	return err
}

func (ctx *Ctx) TxMail(node *Node, nice uint8, recipient string, body []byte, minSize int64) error {
	pkt, err := NewPkt(PktTypeMail, recipient)
	if err != nil {
		return err
	}
	var compressed bytes.Buffer
	compressor, err := zlib.NewWriterLevel(&compressed, zlib.BestCompression)
	if err != nil {
		return err
	}
	if _, err = io.Copy(compressor, bytes.NewReader(body)); err != nil {
		return err
	}
	compressor.Close()
	size := int64(compressed.Len())
	_, err = ctx.Tx(node, pkt, nice, size, minSize, &compressed)
	if err == nil {
		ctx.LogI("tx", SDS{
			"type": "mail",
			"node": node.Id,
			"nice": strconv.Itoa(int(nice)),
			"dst":  recipient,
			"size": strconv.FormatInt(size, 10),
		}, "sent")
	} else {
		ctx.LogE("tx", SDS{
			"type": "mail",
			"node": node.Id,
			"nice": strconv.Itoa(int(nice)),
			"dst":  recipient,
			"size": strconv.FormatInt(size, 10),
			"err":  err,
		}, "sent")
	}
	return err
}

func (ctx *Ctx) TxTrns(node *Node, nice uint8, size int64, src io.Reader) error {
	ctx.LogD("tx", SDS{
		"type": "trns",
		"node": node.Id,
		"nice": strconv.Itoa(int(nice)),
		"size": strconv.FormatInt(size, 10),
	}, "taken")
	tmp, err := ctx.NewTmpFileWHash()
	if err != nil {
		return err
	}
	if _, err = io.Copy(tmp.W, src); err != nil {
		return err
	}
	nodePath := filepath.Join(ctx.Spool, node.Id.String())
	err = tmp.Commit(filepath.Join(nodePath, string(TTx)))
	if err == nil {
		ctx.LogI("tx", SDS{
			"type": "trns",
			"node": node.Id,
			"nice": strconv.Itoa(int(nice)),
			"size": strconv.FormatInt(size, 10),
		}, "sent")
	} else {
		ctx.LogI("tx", SDS{
			"type": "trns",
			"node": node.Id,
			"nice": strconv.Itoa(int(nice)),
			"size": strconv.FormatInt(size, 10),
			"err":  err,
		}, "sent")
	}
	os.Symlink(nodePath, filepath.Join(ctx.Spool, node.Name))
	return err
}
