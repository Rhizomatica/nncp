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
	"bufio"
	"bytes"
	"errors"
	"io"
	"log"
	"os"

	"golang.org/x/crypto/blake2b"
)

func Check(src io.Reader, checksum []byte, les LEs, showPrgrs bool) (bool, error) {
	hsh, err := blake2b.New256(nil)
	if err != nil {
		log.Fatalln(err)
	}
	if _, err = CopyProgressed(hsh, bufio.NewReader(src), "check", les, showPrgrs); err != nil {
		return false, err
	}
	return bytes.Compare(hsh.Sum(nil), checksum) == 0, nil
}

func (ctx *Ctx) checkXxIsBad(nodeId *NodeId, xx TRxTx) bool {
	isBad := false
	for job := range ctx.Jobs(nodeId, xx) {
		les := LEs{
			{"XX", string(xx)},
			{"Node", nodeId},
			{"Pkt", Base32Codec.EncodeToString(job.HshValue[:])},
			{"FullSize", job.Size},
		}
		fd, err := os.Open(job.Path)
		if err != nil {
			ctx.LogE("check", les, err, "")
			return true
		}
		gut, err := Check(fd, job.HshValue[:], les, ctx.ShowPrgrs)
		fd.Close() // #nosec G104
		if err != nil {
			ctx.LogE("check", les, err, "")
			return true
		}
		if !gut {
			isBad = true
			ctx.LogE("check", les, errors.New("bad"), "")
		}
	}
	return isBad
}

func (ctx *Ctx) Check(nodeId *NodeId) bool {
	return !(ctx.checkXxIsBad(nodeId, TRx) || ctx.checkXxIsBad(nodeId, TTx))
}
