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
	"io"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/blake2b"
)

func (ctx *Ctx) Tx(node *Node, pkt *Pkt, nice uint8, size int64, src io.Reader) (*Node, error) {
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
	errs := make(chan error)
	curSize := size
	pipeR, pipeW := io.Pipe()
	go func(size int64, src io.Reader, dst io.WriteCloser) {
		ctx.LogD("tx", SDS{
			"node": hops[0].Id,
			"nice": strconv.Itoa(int(nice)),
			"size": strconv.FormatInt(size, 10),
		}, "wrote")
		errs <- PktEncWrite(ctx.Self, hops[0], pkt, nice, size, src, dst)
		dst.Close()
	}(curSize, src, pipeW)

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
			errs <- PktEncWrite(ctx.Self, node, pkt, nice, size, src, dst)
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

func (ctx *Ctx) TxFile(node *Node, nice uint8, srcPath, dstPath string) error {
	dstPath = path.Clean(dstPath)
	if path.IsAbs(dstPath) {
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
	_, err = ctx.Tx(node, pkt, nice, srcStat.Size(), bufio.NewReader(src))
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

func (ctx *Ctx) TxFreq(node *Node, nice uint8, srcPath, dstPath string) error {
	dstPath = path.Clean(dstPath)
	if path.IsAbs(dstPath) {
		return errors.New("Relative destination path required")
	}
	srcPath = path.Clean(srcPath)
	if path.IsAbs(srcPath) {
		return errors.New("Relative source path required")
	}
	pkt, err := NewPkt(PktTypeFreq, srcPath)
	if err != nil {
		return err
	}
	src := strings.NewReader(dstPath)
	size := int64(src.Len())
	_, err = ctx.Tx(node, pkt, nice, size, src)
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

func (ctx *Ctx) TxMail(node *Node, nice uint8, recipient string, body []byte) error {
	pkt, err := NewPkt(PktTypeMail, recipient)
	if err != nil {
		return err
	}
	var compressed bytes.Buffer
	compressor := zlib.NewWriter(&compressed)
	if _, err = io.Copy(compressor, bytes.NewReader(body)); err != nil {
		return err
	}
	compressor.Close()
	size := int64(compressed.Len())
	_, err = ctx.Tx(node, pkt, nice, size, &compressed)
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
