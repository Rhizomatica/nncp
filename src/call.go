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
	"net"
	"time"

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
		ctx.LogD("call", les, "dialing")
		var conn ConnDeadlined
		var err error
		if addr[0] == '|' {
			conn, err = NewPipeConn(addr[1:])
		} else {
			conn, err = net.Dial("tcp", addr)
		}
		if err != nil {
			ctx.LogD("call", append(les, LE{"Err", err}), "dialing")
			continue
		}
		ctx.LogD("call", les, "connected")
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
			ctx.LogI("call-start", les, "connected")
			state.Wait()
			ctx.LogI("call-finish", LEs{
				{"Node", state.Node.Id},
				{"Duration", int64(state.Duration.Seconds())},
				{"RxBytes", state.RxBytes},
				{"TxBytes", state.TxBytes},
				{"RxSpeed", state.RxSpeed},
				{"TxSpeed", state.TxSpeed},
			}, "")
			isGood = true
			conn.Close() // #nosec G104
			break
		} else {
			ctx.LogE("call-start", les, err, "")
			conn.Close() // #nosec G104
		}
	}
	return
}
