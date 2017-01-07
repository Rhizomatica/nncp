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

// Show queued NNCP Rx/Tx stats
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"cypherpunks.ru/nncp"
	"github.com/dustin/go-humanize"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintln(os.Stderr, "nncp-stat -- show queued Rx/Tx stats\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\nOptions:", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	var (
		cfgPath  = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		nodeRaw  = flag.String("node", "", "Process only that node")
		debug    = flag.Bool("debug", false, "Enable debugging information")
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

	cfgRaw, err := ioutil.ReadFile(*cfgPath)
	if err != nil {
		log.Fatalln("Can not read config:", err)
	}
	ctx, err := nncp.CfgParse(cfgRaw)
	if err != nil {
		log.Fatalln("Can not parse config:", err)
	}
	ctx.Debug = *debug

	var nodeOnly *nncp.Node
	if *nodeRaw != "" {
		nodeOnly, err = ctx.FindNode(*nodeRaw)
		if err != nil {
			log.Fatalln("Invalid -node specified:", err)
		}
	}

	for nodeId, node := range ctx.Neigh {
		if nodeOnly != nil && nodeId != *nodeOnly.Id {
			continue
		}
		rxNums := make(map[uint8]int)
		rxBytes := make(map[uint8]int64)
		for job := range ctx.Jobs(&nodeId, nncp.TRx) {
			job.Fd.Close()
			rxNums[job.PktEnc.Nice] = rxNums[job.PktEnc.Nice] + 1
			rxBytes[job.PktEnc.Nice] = rxBytes[job.PktEnc.Nice] + job.Size
		}
		txNums := make(map[uint8]int)
		txBytes := make(map[uint8]int64)
		for job := range ctx.Jobs(&nodeId, nncp.TTx) {
			job.Fd.Close()
			txNums[job.PktEnc.Nice] = txNums[job.PktEnc.Nice] + 1
			txBytes[job.PktEnc.Nice] = txBytes[job.PktEnc.Nice] + job.Size
		}
		fmt.Println(node.Name)
		for nice := 0; nice < 256; nice++ {
			rxNum, rxExists := rxNums[uint8(nice)]
			txNum, txExists := txNums[uint8(nice)]
			if !(rxExists || txExists) {
				continue
			}
			fmt.Printf(
				"\tnice:% 3d | Rx: % 10s, % 3d pkts | Tx: % 10s, % 3d pkts\n",
				nice,
				humanize.IBytes(uint64(rxBytes[uint8(nice)])),
				rxNum,
				humanize.IBytes(uint64(txBytes[uint8(nice)])),
				txNum,
			)
		}
	}
}
