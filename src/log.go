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
	"time"

	"go.cypherpunks.ru/recfile"
	"golang.org/x/sys/unix"
)

type LE struct {
	K string
	V interface{}
}
type LEs []LE

func (les LEs) Rec() string {
	fields := make([]recfile.Field, 0, len(les)+1)
	fields = append(fields, recfile.Field{
		Name: "When", Value: time.Now().UTC().Format(time.RFC3339Nano),
	})
	var val string
	for _, le := range les {
		switch v := le.V.(type) {
		case int, int8, uint8, int64, uint64:
			val = fmt.Sprintf("%d", v)
		case bool:
			val = fmt.Sprintf("%v", v)
		default:
			val = fmt.Sprintf("%s", v)
		}
		fields = append(fields, recfile.Field{Name: le.K, Value: val})
	}
	b := bytes.NewBuffer(make([]byte, 0, 1<<10))
	w := recfile.NewWriter(b)
	_, err := w.RecordStart()
	if err != nil {
		panic(err)
	}
	_, err = w.WriteFields(fields...)
	if err != nil {
		panic(err)
	}
	return b.String()
}

func (ctx *Ctx) Log(rec string) {
	fdLock, err := os.OpenFile(
		ctx.LogPath+".lock",
		os.O_CREATE|os.O_WRONLY,
		os.FileMode(0666),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Can not open lock for log:", err)
		return
	}
	defer fdLock.Close()
	fdLockFd := int(fdLock.Fd())
	err = unix.Flock(fdLockFd, unix.LOCK_EX)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Can not acquire lock for log:", err)
		return
	}
	defer unix.Flock(fdLockFd, unix.LOCK_UN)
	fd, err := os.OpenFile(
		ctx.LogPath,
		os.O_CREATE|os.O_WRONLY|os.O_APPEND,
		os.FileMode(0666),
	)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Can not open log:", err)
		return
	}
	fd.WriteString(rec) // #nosec G104
	fd.Close()          // #nosec G104
}

func (ctx *Ctx) LogD(who string, les LEs, msg string) {
	if !ctx.Debug {
		return
	}
	les = append(LEs{{"Debug", true}, {"Who", who}}, les...)
	if msg != "" {
		les = append(les, LE{"Msg", msg})
	}
	fmt.Fprint(os.Stderr, les.Rec())
}

func (ctx *Ctx) LogI(who string, les LEs, msg string) {
	les = append(LEs{{"Who", who}}, les...)
	if msg != "" {
		les = append(les, LE{"Msg", msg})
	}
	rec := les.Rec()
	if !ctx.Quiet {
		fmt.Fprintln(os.Stderr, ctx.HumanizeRec(rec))
	}
	ctx.Log(rec)
}

func (ctx *Ctx) LogE(who string, les LEs, err error, msg string) {
	les = append(LEs{{"Err", err.Error()}, {"Who", who}}, les...)
	if msg != "" {
		les = append(les, LE{"Msg", msg})
	}
	rec := les.Rec()
	if !ctx.Quiet {
		fmt.Fprintln(os.Stderr, ctx.HumanizeRec(rec))
	}
	ctx.Log(rec)
}
