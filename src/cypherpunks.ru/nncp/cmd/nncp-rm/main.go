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

// Remove packet from the queue
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"

	"cypherpunks.ru/nncp"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintln(os.Stderr, "nncp-rm -- remove packet\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options] NODE PKT\nOptions:\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	var (
		cfgPath  = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
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
	if flag.NArg() != 2 {
		usage()
		os.Exit(1)
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

	node, err := ctx.FindNode(flag.Arg(0))
	if err != nil {
		log.Fatalln("Invalid NODE specified:", err)
	}

	pktName := flag.Arg(1)
	remove := func(xx nncp.TRxTx) bool {
		for job := range ctx.Jobs(node.Id, xx) {
			job.Fd.Close()
			if filepath.Base(job.Fd.Name()) == pktName {
				if err = os.Remove(job.Fd.Name()); err != nil {
					log.Fatalln("Can not remove packet:", err)
				}
				return true
			}
		}
		return false
	}

	if !(remove(nncp.TRx) || remove(nncp.TTx)) {
		log.Fatalln("Have not found specified packet")
	}
}
