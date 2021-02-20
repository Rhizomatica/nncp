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
	"os"
	"path/filepath"
	"strings"

	xdr "github.com/davecgh/go-xdr/xdr2"
)

type TRxTx string

const (
	TRx TRxTx = "rx"
	TTx TRxTx = "tx"
)

type Job struct {
	PktEnc   *PktEnc
	Path     string
	Size     int64
	HshValue *[32]byte
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
			var hshValue []byte
			if nock {
				if !strings.HasSuffix(fi.Name(), NoCKSuffix) {
					continue
				}
				hshValue, err = Base32Codec.DecodeString(
					strings.TrimSuffix(fi.Name(), NoCKSuffix),
				)
			} else {
				hshValue, err = Base32Codec.DecodeString(fi.Name())
			}
			if err != nil {
				continue
			}
			pth := filepath.Join(rxPath, fi.Name())
			fd, err := os.Open(pth)
			if err != nil {
				continue
			}
			var pktEnc PktEnc
			_, err = xdr.Unmarshal(fd, &pktEnc)
			fd.Close()
			if err != nil || pktEnc.Magic != MagicNNCPEv4 {
				continue
			}
			ctx.LogD("jobs", LEs{
				{"XX", string(xx)},
				{"Node", pktEnc.Sender},
				{"Name", fi.Name()},
				{"Nice", int(pktEnc.Nice)},
				{"Size", fi.Size()},
			}, "taken")
			job := Job{
				PktEnc:   &pktEnc,
				Path:     pth,
				Size:     fi.Size(),
				HshValue: new([32]byte),
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
