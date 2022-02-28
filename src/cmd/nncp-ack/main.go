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

	"go.cypherpunks.ru/nncp/v8"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-ack -- send packet receipt acknowledgement\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options] NODE [PKT|rx]\nOptions:\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	var (
		cfgPath     = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		niceRaw     = flag.String("nice", nncp.NicenessFmt(nncp.DefaultNiceFreq), "Outbound packet niceness")
		minSizeRaw  = flag.Uint64("minsize", 0, "Minimal required resulting packet size, in KiB")
		viaOverride = flag.String("via", "", "Override Via path to destination node")
		spoolPath   = flag.String("spool", "", "Override path to spool")
		logPath     = flag.String("log", "", "Override path to logfile")
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
	if flag.NArg() != 2 {
		usage()
		os.Exit(1)
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

	node, err := ctx.FindNode(flag.Arg(0))
	if err != nil {
		log.Fatalln("Invalid NODE specified:", err)
	}

	nncp.ViaOverride(*viaOverride, ctx, node)
	ctx.Umask()
	minSize := int64(*minSizeRaw) * 1024

	if flag.Arg(1) == string(nncp.TRx) {
		for job := range ctx.Jobs(node.Id, nncp.TRx) {
			pktName := filepath.Base(job.Path)
			if err = ctx.TxACK(node, nice, pktName, minSize); err != nil {
				log.Fatalln(err)
			}
		}
	} else {
		if err = ctx.TxACK(node, nice, flag.Arg(1), minSize); err != nil {
			log.Fatalln(err)
		}
	}
}
