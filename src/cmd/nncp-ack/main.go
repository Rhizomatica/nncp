/*
NNCP -- Node to Node copy, utilities for store-and-forward data exchange
Copyright (C) 2016-2022 Sergey Matveev <stargrave@stargrave.org>

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

// Send packet receipt acknowledgement via NNCP.
package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"go.cypherpunks.ru/nncp/v8"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-ack -- send packet receipt acknowledgement\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options] -all\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Usage: %s           -node NODE[,...]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Usage: %s           -node NODE -pkt PKT\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "Options:")
	flag.PrintDefaults()
}

func main() {
	var (
		cfgPath     = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		niceRaw     = flag.String("nice", nncp.NicenessFmt(nncp.DefaultNiceFreq), "Outbound packet niceness")
		minSizeRaw  = flag.Uint64("minsize", 0, "Minimal required resulting packet size, in KiB")
		viaOverride = flag.String("via", "", "Override Via path to destination node (ignored with -all)")
		spoolPath   = flag.String("spool", "", "Override path to spool")
		logPath     = flag.String("log", "", "Override path to logfile")
		doAll       = flag.Bool("all", false, "ACK all rx packet for all nodes")
		nodesRaw    = flag.String("node", "", "ACK rx packets for that node")
		pktRaw      = flag.String("pkt", "", "ACK only that packet")
		quiet       = flag.Bool("quiet", false, "Print only errors")
		showPrgrs   = flag.Bool("progress", false, "Force progress showing")
		omitPrgrs   = flag.Bool("noprogress", false, "Omit progress showing")
		debug       = flag.Bool("debug", false, "Print debug messages")
		version     = flag.Bool("version", false, "Print version information")
		warranty    = flag.Bool("warranty", false, "Print warranty information")
	)
	log.SetFlags(log.Lshortfile)
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
	nice, err := nncp.NicenessParse(*niceRaw)
	if err != nil {
		log.Fatalln(err)
	}

	ctx, err := nncp.CtxFromCmdline(
		*cfgPath,
		*spoolPath,
		*logPath,
		*quiet,
		*showPrgrs,
		*omitPrgrs,
		*debug,
	)
	if err != nil {
		log.Fatalln("Error during initialization:", err)
	}
	if ctx.Self == nil {
		log.Fatalln("Config lacks private keys")
	}

	ctx.Umask()
	minSize := int64(*minSizeRaw) * 1024

	var nodes []*nncp.Node
	if *nodesRaw != "" {
		for _, nodeRaw := range strings.Split(*nodesRaw, ",") {
			node, err := ctx.FindNode(nodeRaw)
			if err != nil {
				log.Fatalln("Invalid -node specified:", err)
			}
			nodes = append(nodes, node)
		}
	}
	if *doAll {
		if len(nodes) != 0 {
			usage()
			os.Exit(1)
		}
		for _, node := range ctx.Neigh {
			nodes = append(nodes, node)
		}
	} else if len(nodes) == 0 {
		usage()
		os.Exit(1)
	}

	if *pktRaw != "" {
		if len(nodes) != 1 {
			usage()
			os.Exit(1)
		}
		nncp.ViaOverride(*viaOverride, ctx, nodes[0])
		if err = ctx.TxACK(nodes[0], nice, *pktRaw, minSize); err != nil {
			log.Fatalln(err)
		}
		return
	}

	for _, node := range nodes {
		for job := range ctx.Jobs(node.Id, nncp.TRx) {
			pktName := filepath.Base(job.Path)
			if err = ctx.TxACK(node, nice, pktName, minSize); err != nil {
				log.Fatalln(err)
			}
		}
	}
}
