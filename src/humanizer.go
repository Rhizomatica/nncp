/*
NNCP -- Node to Node copy
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
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"go.cypherpunks.ru/recfile"
)

func (ctx *Ctx) HumanizeRec(rec string) string {
	r := recfile.NewReader(strings.NewReader(rec))
	le, err := r.NextMap()
	if err != nil {
		return rec
	}
	humanized, err := ctx.Humanize(le)
	if err != nil {
		return fmt.Sprintf("Can not humanize: %s\n%s", err, rec)
	}
	return humanized
}

func (ctx *Ctx) Humanize(le map[string]string) (string, error) {
	nodeS := le["Node"]
	node, err := ctx.FindNode(nodeS)
	if err == nil {
		nodeS = node.Name
	}
	var size string
	if sizeRaw, exists := le["Size"]; exists {
		sp, err := strconv.ParseUint(sizeRaw, 10, 64)
		if err != nil {
			return "", err
		}
		size = humanize.IBytes(uint64(sp))
	}

	var msg string
	switch le["Who"] {
	case "tx":
		switch le["Type"] {
		case "file":
			msg = fmt.Sprintf(
				"File %s (%s) transfer to %s:%s: %s",
				le["Src"], size, nodeS, le["Dst"], le["Msg"],
			)
		case "freq":
			msg = fmt.Sprintf(
				"File request from %s:%s to %s: %s",
				nodeS, le["Src"], le["Dst"], le["Msg"],
			)
		case "exec":
			msg = fmt.Sprintf(
				"Exec to %s@%s (%s): %s",
				nodeS, le["Dst"], size, le["Msg"],
			)
		case "trns":
			msg = fmt.Sprintf(
				"Transitional packet to %s (%s) (nice %s): %s",
				nodeS, size, le["Nice"], le["Msg"],
			)
		default:
			return "", errors.New("unknown \"tx\" type")
		}
		if err, exists := le["Err"]; exists {
			msg += ": " + err
		}
	case "rx":
		switch le["Type"] {
		case "exec":
			msg = fmt.Sprintf("Got exec from %s to %s (%s)", nodeS, le["Dst"], size)
		case "file":
			msg = fmt.Sprintf("Got file %s (%s) from %s", le["Dst"], size, nodeS)
		case "freq":
			msg = fmt.Sprintf("Got file request %s to %s", le["Src"], nodeS)
		case "trns":
			nodeT := le["Dst"]
			node, err := ctx.FindNode(nodeT)
			if err == nil {
				nodeT = node.Name
			}
			msg = fmt.Sprintf(
				"Got transitional packet from %s to %s (%s)",
				nodeS, nodeT, size,
			)
		default:
			return "", errors.New("unknown \"rx\" type")
		}
		if err, exists := le["Err"]; exists {
			msg += ": " + err
		}
	case "check":
		msg = fmt.Sprintf("Checking: %s/%s/%s", le["Node"], le["XX"], le["Pkt"])
		if err, exists := le["Err"]; exists {
			msg += fmt.Sprintf(" %s", err)
		}
	case "nncp-xfer":
		switch le["XX"] {
		case "rx":
			msg = "Packet transfer, received from"
		case "tx":
			msg = "Packet transfer, sent to"
		default:
			return "", errors.New("unknown XX")
		}
		if nodeS != "" {
			msg += " node " + nodeS
		}
		if size != "" {
			msg += fmt.Sprintf(" (%s)", size)
		}
		if err, exists := le["Err"]; exists {
			msg += ": " + err
		} else {
			msg += " " + le["Msg"]
		}
	case "nncp-bundle":
		switch le["XX"] {
		case "rx":
			msg = "Bundle transfer, received from"
		case "tx":
			msg = "Bundle transfer, sent to"
		default:
			return "", errors.New("unknown XX")
		}
		if nodeS != "" {
			msg += " node " + nodeS
		}
		msg += " " + le["Pkt"]
		if size != "" {
			msg += fmt.Sprintf(" (%s)", size)
		}
		if err, exists := le["Err"]; exists {
			msg += ": " + err
		}
	case "nncp-rm":
		msg += "removing " + le["File"]
	case "call-start":
		msg = fmt.Sprintf("Connection to %s", nodeS)
		if err, exists := le["Err"]; exists {
			msg += ": " + err
		}
	case "call-finish":
		rx, err := strconv.ParseUint(le["RxBytes"], 10, 64)
		if err != nil {
			return "", err
		}
		rxs, err := strconv.ParseUint(le["RxSpeed"], 10, 64)
		if err != nil {
			return "", err
		}
		tx, err := strconv.ParseUint(le["TxBytes"], 10, 64)
		if err != nil {
			return "", err
		}
		txs, err := strconv.ParseUint(le["TxSpeed"], 10, 64)
		if err != nil {
			return "", err
		}
		msg = fmt.Sprintf(
			"Finished call with %s: %s received (%s/sec), %s transferred (%s/sec)",
			nodeS,
			humanize.IBytes(uint64(rx)), humanize.IBytes(uint64(rxs)),
			humanize.IBytes(uint64(tx)), humanize.IBytes(uint64(txs)),
		)
	case "sp-start":
		if nodeS == "" {
			msg += "SP"
			if peer, exists := le["Peer"]; exists {
				msg += fmt.Sprintf(": %s", peer)
			}
		} else {
			nice, err := NicenessParse(le["Nice"])
			if err != nil {
				return "", err
			}
			msg += fmt.Sprintf("SP with %s (nice %s)", nodeS, NicenessFmt(nice))
		}
		if m, exists := le["Msg"]; exists {
			msg += ": " + m
		}
		if err, exists := le["Err"]; exists {
			msg += ": " + err
		}
	case "sp-info":
		nice, err := NicenessParse(le["Nice"])
		if err != nil {
			return "", err
		}
		msg = fmt.Sprintf(
			"Packet %s (%s) (nice %s)",
			le["Pkt"], size, NicenessFmt(nice),
		)
		offsetParsed, err := strconv.ParseUint(le["Offset"], 10, 64)
		if err != nil {
			return "", err
		}
		sizeParsed, err := strconv.ParseUint(le["Size"], 10, 64)
		if err != nil {
			return "", err
		}
		msg += fmt.Sprintf(": %d%%", 100*offsetParsed/sizeParsed)
		if m, exists := le["Msg"]; exists {
			msg += ": " + m
		}
	case "sp-infos":
		switch le["XX"] {
		case "rx":
			msg = fmt.Sprintf("%s has got for us: ", nodeS)
		case "tx":
			msg = fmt.Sprintf("We have got for %s: ", nodeS)
		default:
			return "", errors.New("unknown XX")
		}
		msg += fmt.Sprintf("%s packets, %s", le["Pkts"], size)
	case "sp-process":
		msg = fmt.Sprintf("%s has %s (%s): %s", nodeS, le["Pkt"], size, le["Msg"])
	case "sp-file":
		switch le["XX"] {
		case "rx":
			msg = "Got packet "
		case "tx":
			msg = "Sent packet "
		default:
			return "", errors.New("unknown XX")
		}
		fullsize, err := strconv.ParseUint(le["FullSize"], 10, 64)
		if err != nil {
			return "", err
		}
		sizeParsed, err := strconv.ParseUint(le["Size"], 10, 64)
		if err != nil {
			return "", err
		}
		msg += fmt.Sprintf(
			"%s %d%% (%s / %s)",
			le["Pkt"],
			100*sizeParsed/fullsize,
			humanize.IBytes(uint64(sizeParsed)),
			humanize.IBytes(uint64(fullsize)),
		)
	case "sp-done":
		switch le["XX"] {
		case "rx":
			msg = fmt.Sprintf("Packet %s is retreived (%s)", le["Pkt"], size)
		case "tx":
			msg = fmt.Sprintf("Packet %s is sent", le["Pkt"])
		default:
			return "", errors.New("unknown XX")
		}
	case "nncp-reass":
		chunkNum, exists := le["Chunk"]
		if exists {
			msg = fmt.Sprintf(
				"Reassembling chunked file \"%s\" (chunk %s): %s",
				le["Path"], chunkNum, le["Msg"],
			)
		} else {
			msg = fmt.Sprintf(
				"Reassembling chunked file \"%s\": %s",
				le["Path"], le["Msg"],
			)
		}
		if err, exists := le["Err"]; exists {
			msg += ": " + err
		}
	case "lockdir":
		msg = fmt.Sprintf("Acquire lock for %s: %s", le["Path"], le["Err"])
	default:
		return "", errors.New("unknown Who")
	}
	when, err := time.Parse(time.RFC3339Nano, le["When"])
	if err != nil {
		return "", err
	}
	var level string
	if _, isErr := le["Err"]; isErr {
		level = "ERROR "
	}
	return fmt.Sprintf("%s %s%s", when.Format(time.RFC3339), level, msg), nil
}
