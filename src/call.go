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
	"fmt"
	"net"
	"time"

	"github.com/dustin/go-humanize"
	"github.com/gorhill/cronexpr"
)

type Call struct {
	Cron           *cronexpr.Expression
	Nice           uint8
	Xx             TRxTx
	RxRate         int
	TxRate         int
	Addr           *string
	OnlineDeadline time.Duration
	MaxOnlineTime  time.Duration
	WhenTxExists   bool
	NoCK           bool

	AutoToss       bool
	AutoTossDoSeen bool
	AutoTossNoFile bool
	AutoTossNoFreq bool
	AutoTossNoExec bool
	AutoTossNoTrns bool
}

func (ctx *Ctx) CallNode(
	node *Node,
	addrs []string,
	nice uint8,
	xxOnly TRxTx,
	rxRate, txRate int,
	onlineDeadline, maxOnlineTime time.Duration,
	listOnly bool,
	noCK bool,
	onlyPkts map[[32]byte]bool,
) (isGood bool) {
	for _, addr := range addrs {
		les := LEs{{"Node", node.Id}, {"Addr", addr}}
		ctx.LogD("calling", les, func(les LEs) string {
			return fmt.Sprintf("Calling %s (%s)", node.Name, addr)
		})
		var conn ConnDeadlined
		var err error
		if addr[0] == '|' {
			conn, err = NewPipeConn(addr[1:])
		} else {
			conn, err = net.Dial("tcp", addr)
		}
		if err != nil {
			ctx.LogD("calling", append(les, LE{"Err", err}), func(les LEs) string {
				return fmt.Sprintf("Calling %s (%s)", node.Name, addr)
			})
			continue
		}
		ctx.LogD("call-connected", les, func(les LEs) string {
			return fmt.Sprintf("Connected %s (%s)", node.Name, addr)
		})
		state := SPState{
			Ctx:            ctx,
			Node:           node,
			Nice:           nice,
			onlineDeadline: onlineDeadline,
			maxOnlineTime:  maxOnlineTime,
			xxOnly:         xxOnly,
			rxRate:         rxRate,
			txRate:         txRate,
			listOnly:       listOnly,
			NoCK:           noCK,
			onlyPkts:       onlyPkts,
		}
		if err = state.StartI(conn); err == nil {
			ctx.LogI("call-started", les, func(les LEs) string {
				return fmt.Sprintf("Connection to %s (%s)", node.Name, addr)
			})
			state.Wait()
			ctx.LogI("call-finished", append(
				les,
				LE{"Duration", int64(state.Duration.Seconds())},
				LE{"RxBytes", state.RxBytes},
				LE{"RxSpeed", state.RxSpeed},
				LE{"TxBytes", state.TxBytes},
				LE{"TxSpeed", state.TxSpeed},
			), func(les LEs) string {
				return fmt.Sprintf(
					"Finished call with %s (%d:%d:%d): %s received (%s/sec), %s transferred (%s/sec)",
					node.Name,
					int(state.Duration.Hours()),
					int(state.Duration.Minutes()),
					int(state.Duration.Seconds()),
					humanize.IBytes(uint64(state.RxBytes)),
					humanize.IBytes(uint64(state.RxSpeed)),
					humanize.IBytes(uint64(state.TxBytes)),
					humanize.IBytes(uint64(state.TxSpeed)),
				)
			})
			isGood = true
			conn.Close() // #nosec G104
			break
		} else {
			ctx.LogE("call-started", les, err, func(les LEs) string {
				return fmt.Sprintf("Connection to %s (%s)", node.Name, addr)
			})
			conn.Close() // #nosec G104
		}
	}
	return
}
