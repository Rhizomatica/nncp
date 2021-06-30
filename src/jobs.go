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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	xdr "github.com/davecgh/go-xdr/xdr2"
	"github.com/dustin/go-humanize"
)

type TRxTx string

const (
	TRx TRxTx = "rx"
	TTx TRxTx = "tx"

	HdrSuffix = ".hdr"
)

type Job struct {
	PktEnc   *PktEnc
	Path     string
	Size     int64
	HshValue *[MTHSize]byte
}

func (ctx *Ctx) HdrRead(fd *os.File) (*PktEnc, []byte, error) {
	var pktEnc PktEnc
	_, err := xdr.Unmarshal(fd, &pktEnc)
	if err != nil {
		return nil, nil, err
	}
	var raw bytes.Buffer
	if _, err = xdr.Marshal(&raw, pktEnc); err != nil {
		panic(err)
	}
	return &pktEnc, raw.Bytes(), nil
}

func (ctx *Ctx) HdrWrite(pktEncRaw []byte, tgt string) error {
	tmpHdr, err := ctx.NewTmpFile()
	if err != nil {
		ctx.LogE("hdr-write-tmp-new", nil, err, func(les LEs) string {
			return "Header writing: new temporary file"
		})
		return err
	}
	if _, err = tmpHdr.Write(pktEncRaw); err != nil {
		ctx.LogE("hdr-write-write", nil, err, func(les LEs) string {
			return "Header writing: writing"
		})
		os.Remove(tmpHdr.Name())
		return err
	}
	if err = tmpHdr.Close(); err != nil {
		ctx.LogE("hdr-write-close", nil, err, func(les LEs) string {
			return "Header writing: closing"
		})
		os.Remove(tmpHdr.Name())
		return err
	}
	if err = os.Rename(tmpHdr.Name(), tgt+HdrSuffix); err != nil {
		ctx.LogE("hdr-write-rename", nil, err, func(les LEs) string {
			return "Header writing: renaming"
		})
		return err
	}
	return err
}

func (ctx *Ctx) jobsFind(nodeId *NodeId, xx TRxTx, nock bool) chan Job {
	rxPath := filepath.Join(ctx.Spool, nodeId.String(), string(xx))
	jobs := make(chan Job, 16)
	go func() {
		defer close(jobs)
		dir, err := os.Open(rxPath)
		if err != nil {
			return
		}
		fis, err := dir.Readdir(0)
		dir.Close() // #nosec G104
		if err != nil {
			return
		}
		for _, fi := range fis {
			name := fi.Name()
			var hshValue []byte
			if nock {
				if !strings.HasSuffix(name, NoCKSuffix) ||
					len(name) != Base32Encoded32Len+len(NoCKSuffix) {
					continue
				}
				hshValue, err = Base32Codec.DecodeString(
					strings.TrimSuffix(name, NoCKSuffix),
				)
			} else {
				if len(name) != Base32Encoded32Len {
					continue
				}
				hshValue, err = Base32Codec.DecodeString(name)
			}
			if err != nil {
				continue
			}
			pth := filepath.Join(rxPath, name)
			hdrExists := true
			var fd *os.File
			if nock {
				fd, err = os.Open(pth)
			} else {
				fd, err = os.Open(pth + HdrSuffix)
				if err != nil && os.IsNotExist(err) {
					hdrExists = false
					fd, err = os.Open(pth)
				}
			}
			if err != nil {
				continue
			}
			pktEnc, pktEncRaw, err := ctx.HdrRead(fd)
			fd.Close()
			if err != nil || pktEnc.Magic != MagicNNCPEv5.B {
				continue
			}
			ctx.LogD("job", LEs{
				{"XX", string(xx)},
				{"Node", pktEnc.Sender},
				{"Name", name},
				{"Nice", int(pktEnc.Nice)},
				{"Size", fi.Size()},
			}, func(les LEs) string {
				return fmt.Sprintf(
					"Job %s/%s/%s nice: %s size: %s",
					pktEnc.Sender, string(xx), name,
					NicenessFmt(pktEnc.Nice),
					humanize.IBytes(uint64(fi.Size())),
				)
			})
			if !hdrExists && ctx.HdrUsage {
				ctx.HdrWrite(pktEncRaw, pth)
			}
			job := Job{
				PktEnc:   pktEnc,
				Path:     pth,
				Size:     fi.Size(),
				HshValue: new([MTHSize]byte),
			}
			copy(job.HshValue[:], hshValue)
			jobs <- job
		}
	}()
	return jobs
}

func (ctx *Ctx) Jobs(nodeId *NodeId, xx TRxTx) chan Job {
	return ctx.jobsFind(nodeId, xx, false)
}

func (ctx *Ctx) JobsNoCK(nodeId *NodeId) chan Job {
	return ctx.jobsFind(nodeId, TRx, true)
}
