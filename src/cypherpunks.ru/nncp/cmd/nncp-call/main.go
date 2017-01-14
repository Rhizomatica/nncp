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

// Call NNCP TCP daemon
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"

	"cypherpunks.ru/nncp"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintln(os.Stderr, "nncp-call -- call TCP daemon\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options] NODE[:ADDR] [FORCEADDR]\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "Options:")
	flag.PrintDefaults()
}

func main() {
	var (
		cfgPath  = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		niceRaw  = flag.Int("nice", 255, "Minimal required niceness")
		rxOnly   = flag.Bool("rx", false, "Only receive packets")
		txOnly   = flag.Bool("tx", false, "Only transfer packets")
		quiet    = flag.Bool("quiet", false, "Print only errors")
		debug    = flag.Bool("debug", false, "Print debug messages")
		version  = flag.Bool("version", false, "Print version information")
		warranty = flag.Bool("warranty", false, "Print warranty information")
	)
	flag.Usage = usage
	flag.Parse()
	if *warranty {
		fmt.Println(nncp.Warranty)
		return
	}
	if *version {
		fmt.Println(nncp.VersionGet())
		return
	}
	if flag.NArg() < 1 {
		usage()
		os.Exit(1)
	}
	if *niceRaw < 1 || *niceRaw > 255 {
		log.Fatalln("-nice must be between 1 and 255")
	}
	nice := uint8(*niceRaw)
	if *rxOnly && *txOnly {
		log.Fatalln("-rx and -tx can not be set simultaneously")
	}

	cfgRaw, err := ioutil.ReadFile(nncp.CfgPathFromEnv(cfgPath))
	if err != nil {
		log.Fatalln("Can not read config:", err)
	}
	ctx, err := nncp.CfgParse(cfgRaw)
	if err != nil {
		log.Fatalln("Can not parse config:", err)
	}
	ctx.Quiet = *quiet
	ctx.Debug = *debug

	splitted := strings.SplitN(flag.Arg(0), ":", 2)
	node, err := ctx.FindNode(splitted[0])
	if err != nil {
		log.Fatalln("Invalid NODE specified:", err)
	}
	if node.NoisePub == nil {
		log.Fatalln("Node does not have online communication capability")
	}

	var xxOnly nncp.TRxTx
	if *rxOnly {
		xxOnly = nncp.TRx
	} else if *txOnly {
		xxOnly = nncp.TTx
	}

	var addrs []string
	if flag.NArg() == 2 {
		addrs = append(addrs, flag.Arg(1))
	} else if len(splitted) == 2 {
		addr, known := ctx.Neigh[*node.Id].Addrs[splitted[1]]
		if !known {
			log.Fatalln("Unknown ADDR specified")
		}
		addrs = append(addrs, addr)
	} else {
		for _, addr := range ctx.Neigh[*node.Id].Addrs {
			addrs = append(addrs, addr)
		}
	}

	isGood := false
	for _, addr := range addrs {
		ctx.LogD("call", nncp.SDS{"addr": addr}, "dialing")
		conn, err := net.Dial("tcp", addr)
		if err != nil {
			log.Println("Can not connect:", err)
			continue
		}
		ctx.LogD("call", nncp.SDS{"addr": addr}, "connected")
		state, err := ctx.StartI(conn, node.Id, nice, &xxOnly)
		if err == nil {
			ctx.LogI("call-start", nncp.SDS{"node": state.NodeId}, "connected")
			state.Wait()
			ctx.LogI("call-finish", nncp.SDS{
				"node":     state.NodeId,
				"duration": strconv.FormatInt(int64(state.Duration.Seconds()), 10),
				"rxbytes":  strconv.FormatInt(state.RxBytes, 10),
				"txbytes":  strconv.FormatInt(state.TxBytes, 10),
				"rxspeed":  strconv.FormatInt(state.RxSpeed, 10),
				"txspeed":  strconv.FormatInt(state.TxSpeed, 10),
			}, "")
			isGood = true
			conn.Close()
			break
		} else {
			ctx.LogE("call-start", nncp.SDS{"node": state.NodeId, "err": err}, "")
			conn.Close()
		}
	}
	if !isGood {
		os.Exit(1)
	}
}
