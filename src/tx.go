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
	"archive/tar"
	"bufio"
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	xdr "github.com/davecgh/go-xdr/xdr2"
	"github.com/dustin/go-humanize"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/chacha20poly1305"
)

const (
	MaxFileSize = 1 << 62

	TarBlockSize = 512
	TarExt       = ".tar"
)

func (ctx *Ctx) Tx(
	node *Node,
	pkt *Pkt,
	nice uint8,
	size, minSize int64,
	src io.Reader,
	pktName string,
) (*Node, error) {
	hops := make([]*Node, 0, 1+len(node.Via))
	hops = append(hops, node)
	lastNode := node
	for i := len(node.Via); i > 0; i-- {
		lastNode = ctx.Neigh[*node.Via[i-1]]
		hops = append(hops, lastNode)
	}
	expectedSize := size
	for i := 0; i < len(hops); i++ {
		expectedSize = PktEncOverhead +
			PktSizeOverhead +
			sizeWithTags(PktOverhead+expectedSize)
	}
	padSize := minSize - expectedSize
	if padSize < 0 {
		padSize = 0
	}
	if !ctx.IsEnoughSpace(size + padSize) {
		return nil, errors.New("is not enough space")
	}
	tmp, err := ctx.NewTmpFileWHash()
	if err != nil {
		return nil, err
	}

	errs := make(chan error)
	pktEncRaws := make(chan []byte)
	curSize := size
	pipeR, pipeW := io.Pipe()
	go func(size int64, src io.Reader, dst io.WriteCloser) {
		ctx.LogD("tx", LEs{
			{"Node", hops[0].Id},
			{"Nice", int(nice)},
			{"Size", size},
		}, func(les LEs) string {
			return fmt.Sprintf(
				"Tx packet to %s (%s) nice: %s",
				ctx.NodeName(hops[0].Id),
				humanize.IBytes(uint64(size)),
				NicenessFmt(nice),
			)
		})
		pktEncRaw, err := PktEncWrite(
			ctx.Self, hops[0], pkt, nice, size, padSize, src, dst,
		)
		pktEncRaws <- pktEncRaw
		errs <- err
		dst.Close() // #nosec G104
	}(curSize, src, pipeW)
	curSize = PktEncOverhead +
		PktSizeOverhead +
		sizeWithTags(PktOverhead+curSize) +
		padSize

	var pipeRPrev io.Reader
	for i := 1; i < len(hops); i++ {
		pktTrns, err := NewPkt(PktTypeTrns, 0, hops[i-1].Id[:])
		if err != nil {
			panic(err)
		}
		pipeRPrev = pipeR
		pipeR, pipeW = io.Pipe()
		go func(node *Node, pkt *Pkt, size int64, src io.Reader, dst io.WriteCloser) {
			ctx.LogD("tx", LEs{
				{"Node", node.Id},
				{"Nice", int(nice)},
				{"Size", size},
			}, func(les LEs) string {
				return fmt.Sprintf(
					"Tx trns packet to %s (%s) nice: %s",
					ctx.NodeName(node.Id),
					humanize.IBytes(uint64(size)),
					NicenessFmt(nice),
				)
			})
			pktEncRaw, err := PktEncWrite(ctx.Self, node, pkt, nice, size, 0, src, dst)
			pktEncRaws <- pktEncRaw
			errs <- err
			dst.Close() // #nosec G104
		}(hops[i], pktTrns, curSize, pipeRPrev, pipeW)
		curSize = PktEncOverhead + PktSizeOverhead + sizeWithTags(PktOverhead+curSize)
	}
	go func() {
		_, err := CopyProgressed(
			tmp.W, pipeR, "Tx",
			LEs{{"Pkt", pktName}, {"FullSize", curSize}},
			ctx.ShowPrgrs,
		)
		errs <- err
	}()
	var pktEncRaw []byte
	for i := 0; i < len(hops); i++ {
		pktEncRaw = <-pktEncRaws
	}
	for i := 0; i <= len(hops); i++ {
		err = <-errs
		if err != nil {
			tmp.Fd.Close() // #nosec G104
			return nil, err
		}
	}
	nodePath := filepath.Join(ctx.Spool, lastNode.Id.String())
	err = tmp.Commit(filepath.Join(nodePath, string(TTx)))
	os.Symlink(nodePath, filepath.Join(ctx.Spool, lastNode.Name)) // #nosec G104
	if err != nil {
		return lastNode, err
	}
	if ctx.HdrUsage {
		ctx.HdrWrite(pktEncRaw, filepath.Join(nodePath, string(TTx), tmp.Checksum()))
	}
	return lastNode, err
}

type DummyCloser struct{}

func (dc DummyCloser) Close() error { return nil }

func throughTmpFile(r io.Reader) (
	reader io.Reader,
	closer io.Closer,
	fileSize int64,
	rerr error,
) {
	src, err := ioutil.TempFile("", "nncp-file")
	if err != nil {
		rerr = err
		return
	}
	os.Remove(src.Name()) // #nosec G104
	tmpW := bufio.NewWriter(src)
	tmpKey := make([]byte, chacha20poly1305.KeySize)
	if _, rerr = rand.Read(tmpKey[:]); rerr != nil {
		return
	}
	aead, err := chacha20poly1305.New(tmpKey)
	if err != nil {
		rerr = err
		return
	}
	nonce := make([]byte, aead.NonceSize())
	written, err := aeadProcess(aead, nonce, nil, true, r, tmpW)
	if err != nil {
		rerr = err
		return
	}
	fileSize = int64(written)
	if err = tmpW.Flush(); err != nil {
		rerr = err
		return
	}
	if _, err = src.Seek(0, io.SeekStart); err != nil {
		rerr = err
		return
	}
	r, w := io.Pipe()
	go func() {
		if _, err := aeadProcess(aead, nonce, nil, false, bufio.NewReader(src), w); err != nil {
			w.CloseWithError(err) // #nosec G104
		}
	}()
	reader = r
	closer = src
	return
}

func prepareTxFile(srcPath string) (
	reader io.Reader,
	closer io.Closer,
	fileSize int64,
	archived bool,
	rerr error,
) {
	if srcPath == "-" {
		reader, closer, fileSize, rerr = throughTmpFile(bufio.NewReader(os.Stdin))
		return
	}

	srcStat, err := os.Stat(srcPath)
	if err != nil {
		rerr = err
		return
	}
	mode := srcStat.Mode()

	if mode.IsRegular() {
		// It is regular file, just send it
		src, err := os.Open(srcPath)
		if err != nil {
			rerr = err
			return
		}
		fileSize = srcStat.Size()
		reader = bufio.NewReader(src)
		closer = src
		return
	}

	if !mode.IsDir() {
		rerr = errors.New("unsupported file type")
		return
	}

	// It is directory, create PAX archive with its contents
	archived = true
	basePath := filepath.Base(srcPath)
	rootPath, err := filepath.Abs(srcPath)
	if err != nil {
		rerr = err
		return
	}
	type einfo struct {
		path    string
		modTime time.Time
		size    int64
	}
	dirs := make([]einfo, 0, 1<<10)
	files := make([]einfo, 0, 1<<10)
	rerr = filepath.Walk(rootPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// directory header, PAX record header+contents
			fileSize += TarBlockSize + 2*TarBlockSize
			dirs = append(dirs, einfo{path: path, modTime: info.ModTime()})
		} else {
			// file header, PAX record header+contents, file content
			fileSize += TarBlockSize + 2*TarBlockSize + info.Size()
			if n := info.Size() % TarBlockSize; n != 0 {
				fileSize += TarBlockSize - n // padding
			}
			files = append(files, einfo{
				path:    path,
				modTime: info.ModTime(),
				size:    info.Size(),
			})
		}
		return nil
	})
	if rerr != nil {
		return
	}

	r, w := io.Pipe()
	reader = r
	closer = DummyCloser{}
	fileSize += 2 * TarBlockSize // termination block

	go func() error {
		tarWr := tar.NewWriter(w)
		hdr := tar.Header{
			Typeflag: tar.TypeDir,
			Mode:     0777,
			PAXRecords: map[string]string{
				"comment": "Autogenerated by " + VersionGet(),
			},
			Format: tar.FormatPAX,
		}
		for _, e := range dirs {
			hdr.Name = basePath + e.path[len(rootPath):]
			hdr.ModTime = e.modTime
			if err = tarWr.WriteHeader(&hdr); err != nil {
				return w.CloseWithError(err)
			}
		}
		hdr.Typeflag = tar.TypeReg
		hdr.Mode = 0666
		for _, e := range files {
			hdr.Name = basePath + e.path[len(rootPath):]
			hdr.ModTime = e.modTime
			hdr.Size = e.size
			if err = tarWr.WriteHeader(&hdr); err != nil {
				return w.CloseWithError(err)
			}
			fd, err := os.Open(e.path)
			if err != nil {
				fd.Close() // #nosec G104
				return w.CloseWithError(err)
			}
			if _, err = io.Copy(tarWr, bufio.NewReader(fd)); err != nil {
				fd.Close() // #nosec G104
				return w.CloseWithError(err)
			}
			fd.Close() // #nosec G104
		}
		if err = tarWr.Close(); err != nil {
			return w.CloseWithError(err)
		}
		return w.Close()
	}()
	return
}

func (ctx *Ctx) TxFile(
	node *Node,
	nice uint8,
	srcPath, dstPath string,
	chunkSize int64,
	minSize, maxSize int64,
) error {
	dstPathSpecified := false
	if dstPath == "" {
		if srcPath == "-" {
			return errors.New("Must provide destination filename")
		}
		dstPath = filepath.Base(srcPath)
	} else {
		dstPathSpecified = true
	}
	dstPath = filepath.Clean(dstPath)
	if filepath.IsAbs(dstPath) {
		return errors.New("Relative destination path required")
	}
	reader, closer, fileSize, archived, err := prepareTxFile(srcPath)
	if closer != nil {
		defer closer.Close()
	}
	if err != nil {
		return err
	}
	if fileSize > maxSize {
		return errors.New("Too big than allowed")
	}
	if archived && !dstPathSpecified {
		dstPath += TarExt
	}

	if fileSize <= chunkSize {
		pkt, err := NewPkt(PktTypeFile, nice, []byte(dstPath))
		if err != nil {
			return err
		}
		_, err = ctx.Tx(node, pkt, nice, fileSize, minSize, reader, dstPath)
		les := LEs{
			{"Type", "file"},
			{"Node", node.Id},
			{"Nice", int(nice)},
			{"Src", srcPath},
			{"Dst", dstPath},
			{"Size", fileSize},
		}
		logMsg := func(les LEs) string {
			return fmt.Sprintf(
				"File %s (%s) sent to %s:%s",
				srcPath,
				humanize.IBytes(uint64(fileSize)),
				ctx.NodeName(node.Id),
				dstPath,
			)
		}
		if err == nil {
			ctx.LogI("tx", les, logMsg)
		} else {
			ctx.LogE("tx", les, err, logMsg)
		}
		return err
	}

	leftSize := fileSize
	metaPkt := ChunkedMeta{
		Magic:     MagicNNCPMv2.B,
		FileSize:  uint64(fileSize),
		ChunkSize: uint64(chunkSize),
		Checksums: make([][MTHSize]byte, 0, (fileSize/chunkSize)+1),
	}
	for i := int64(0); i < (fileSize/chunkSize)+1; i++ {
		hsh := new([MTHSize]byte)
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
		pkt, err = NewPkt(PktTypeFile, nice, []byte(path))
		if err != nil {
			return err
		}
		hsh = MTHNew(0, 0)
		_, err = ctx.Tx(
			node,
			pkt,
			nice,
			sizeToSend,
			minSize,
			io.TeeReader(reader, hsh),
			path,
		)
		les := LEs{
			{"Type", "file"},
			{"Node", node.Id},
			{"Nice", int(nice)},
			{"Src", srcPath},
			{"Dst", path},
			{"Size", sizeToSend},
		}
		logMsg := func(les LEs) string {
			return fmt.Sprintf(
				"File %s (%s) sent to %s:%s",
				srcPath,
				humanize.IBytes(uint64(sizeToSend)),
				ctx.NodeName(node.Id),
				path,
			)
		}
		if err == nil {
			ctx.LogI("tx", les, logMsg)
		} else {
			ctx.LogE("tx", les, err, logMsg)
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
	pkt, err = NewPkt(PktTypeFile, nice, []byte(path))
	if err != nil {
		return err
	}
	metaPktSize := int64(metaBuf.Len())
	_, err = ctx.Tx(node, pkt, nice, metaPktSize, minSize, &metaBuf, path)
	les := LEs{
		{"Type", "file"},
		{"Node", node.Id},
		{"Nice", int(nice)},
		{"Src", srcPath},
		{"Dst", path},
		{"Size", metaPktSize},
	}
	logMsg := func(les LEs) string {
		return fmt.Sprintf(
			"File %s (%s) sent to %s:%s",
			srcPath,
			humanize.IBytes(uint64(metaPktSize)),
			ctx.NodeName(node.Id),
			path,
		)
	}
	if err == nil {
		ctx.LogI("tx", les, logMsg)
	} else {
		ctx.LogE("tx", les, err, logMsg)
	}
	return err
}

func (ctx *Ctx) TxFreq(
	node *Node,
	nice, replyNice uint8,
	srcPath, dstPath string,
	minSize int64) error {
	dstPath = filepath.Clean(dstPath)
	if filepath.IsAbs(dstPath) {
		return errors.New("Relative destination path required")
	}
	srcPath = filepath.Clean(srcPath)
	if filepath.IsAbs(srcPath) {
		return errors.New("Relative source path required")
	}
	pkt, err := NewPkt(PktTypeFreq, replyNice, []byte(srcPath))
	if err != nil {
		return err
	}
	src := strings.NewReader(dstPath)
	size := int64(src.Len())
	_, err = ctx.Tx(node, pkt, nice, size, minSize, src, srcPath)
	les := LEs{
		{"Type", "freq"},
		{"Node", node.Id},
		{"Nice", int(nice)},
		{"ReplyNice", int(replyNice)},
		{"Src", srcPath},
		{"Dst", dstPath},
	}
	logMsg := func(les LEs) string {
		return fmt.Sprintf(
			"File request from %s:%s to %s sent",
			ctx.NodeName(node.Id), srcPath,
			dstPath,
		)
	}
	if err == nil {
		ctx.LogI("tx", les, logMsg)
	} else {
		ctx.LogE("tx", les, err, logMsg)
	}
	return err
}

func (ctx *Ctx) TxExec(
	node *Node,
	nice, replyNice uint8,
	handle string,
	args []string,
	in io.Reader,
	minSize int64,
	useTmp bool,
	noCompress bool,
) error {
	path := make([][]byte, 0, 1+len(args))
	path = append(path, []byte(handle))
	for _, arg := range args {
		path = append(path, []byte(arg))
	}
	pktType := PktTypeExec
	if noCompress {
		pktType = PktTypeExecFat
	}
	pkt, err := NewPkt(pktType, replyNice, bytes.Join(path, []byte{0}))
	if err != nil {
		return err
	}
	var size int64

	if !noCompress && !useTmp {
		var compressed bytes.Buffer
		compressor, err := zstd.NewWriter(
			&compressed,
			zstd.WithEncoderLevel(zstd.SpeedDefault),
		)
		if err != nil {
			return err
		}
		if _, err = io.Copy(compressor, in); err != nil {
			compressor.Close() // #nosec G104
			return err
		}
		if err = compressor.Close(); err != nil {
			return err
		}
		size = int64(compressed.Len())
		_, err = ctx.Tx(node, pkt, nice, size, minSize, &compressed, handle)
	}
	if noCompress && !useTmp {
		var data bytes.Buffer
		if _, err = io.Copy(&data, in); err != nil {
			return err
		}
		size = int64(data.Len())
		_, err = ctx.Tx(node, pkt, nice, size, minSize, &data, handle)
	}
	if !noCompress && useTmp {
		r, w := io.Pipe()
		compressor, err := zstd.NewWriter(w, zstd.WithEncoderLevel(zstd.SpeedDefault))
		if err != nil {
			return err
		}
		copyErr := make(chan error)
		go func() {
			_, err := io.Copy(compressor, in)
			if err != nil {
				compressor.Close() // #nosec G104
				copyErr <- err
			}
			err = compressor.Close()
			w.Close()
			copyErr <- err
		}()
		tmpReader, closer, fileSize, err := throughTmpFile(r)
		if closer != nil {
			defer closer.Close()
		}
		if err != nil {
			return err
		}
		err = <-copyErr
		if err != nil {
			return err
		}
		size = fileSize
		_, err = ctx.Tx(node, pkt, nice, size, minSize, tmpReader, handle)
	}
	if noCompress && useTmp {
		tmpReader, closer, fileSize, err := throughTmpFile(in)
		if closer != nil {
			defer closer.Close()
		}
		if err != nil {
			return err
		}
		size = fileSize
		_, err = ctx.Tx(node, pkt, nice, size, minSize, tmpReader, handle)
	}

	dst := strings.Join(append([]string{handle}, args...), " ")
	les := LEs{
		{"Type", "exec"},
		{"Node", node.Id},
		{"Nice", int(nice)},
		{"ReplyNice", int(replyNice)},
		{"Dst", dst},
		{"Size", size},
	}
	logMsg := func(les LEs) string {
		return fmt.Sprintf(
			"Exec sent to %s@%s (%s)",
			ctx.NodeName(node.Id), dst, humanize.IBytes(uint64(size)),
		)
	}
	if err == nil {
		ctx.LogI("tx", les, logMsg)
	} else {
		ctx.LogE("tx", les, err, logMsg)
	}
	return err
}

func (ctx *Ctx) TxTrns(node *Node, nice uint8, size int64, src io.Reader) error {
	les := LEs{
		{"Type", "trns"},
		{"Node", node.Id},
		{"Nice", int(nice)},
		{"Size", size},
	}
	logMsg := func(les LEs) string {
		return fmt.Sprintf(
			"Transitional packet to %s (%s) (nice %s)",
			ctx.NodeName(node.Id),
			humanize.IBytes(uint64(size)),
			NicenessFmt(nice),
		)
	}
	ctx.LogD("tx", les, logMsg)
	if !ctx.IsEnoughSpace(size) {
		err := errors.New("is not enough space")
		ctx.LogE("tx", les, err, logMsg)
		return err
	}
	tmp, err := ctx.NewTmpFileWHash()
	if err != nil {
		return err
	}
	if _, err = CopyProgressed(
		tmp.W, src, "Tx trns",
		LEs{{"Pkt", node.Id.String()}, {"FullSize", size}},
		ctx.ShowPrgrs,
	); err != nil {
		return err
	}
	nodePath := filepath.Join(ctx.Spool, node.Id.String())
	err = tmp.Commit(filepath.Join(nodePath, string(TTx)))
	if err == nil {
		ctx.LogI("tx", les, logMsg)
	} else {
		ctx.LogI("tx", append(les, LE{"Err", err}), logMsg)
	}
	os.Symlink(nodePath, filepath.Join(ctx.Spool, node.Name)) // #nosec G104
	return err
}
