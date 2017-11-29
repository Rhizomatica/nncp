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
	"log"
	"os"
	"path/filepath"
	"strings"

	"cypherpunks.ru/nncp"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintln(os.Stderr, "nncp-rm -- remove packet\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options] -tmp\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "       %s [options] -lock\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "       %s [options] -node NODE [-rx] [-tx] [-part] [-seen]\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "       %s [options] -node NODE -pkt PKT\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "Options:")
	flag.PrintDefaults()
}

func main() {
	var (
		cfgPath   = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		doTmp     = flag.Bool("tmp", false, "Remove all temporary files")
		doLock    = flag.Bool("lock", false, "Remove all lock files")
		nodeRaw   = flag.String("node", "", "Node to remove files in")
		doRx      = flag.Bool("rx", false, "Process received packets")
		doTx      = flag.Bool("tx", false, "Process transfered packets")
		doPart    = flag.Bool("part", false, "Remove only .part files")
		doSeen    = flag.Bool("seen", false, "Remove only .seen files")
		pktRaw    = flag.String("pkt", "", "Packet to remove")
		spoolPath = flag.String("spool", "", "Override path to spool")
		quiet     = flag.Bool("quiet", false, "Print only errors")
		debug     = flag.Bool("debug", false, "Print debug messages")
		version   = flag.Bool("version", false, "Print version information")
		warranty  = flag.Bool("warranty", false, "Print warranty information")
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

	ctx, err := nncp.CtxFromCmdline(*cfgPath, *spoolPath, "", *quiet, *debug)
	if err != nil {
		log.Fatalln("Error during initialization:", err)
	}

	if *doTmp {
		err = filepath.Walk(filepath.Join(ctx.Spool, "tmp"), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			return os.Remove(info.Name())
		})
		if err != nil {
			log.Fatalln("Error during walking:", err)
		}
		return
	}
	if *doLock {
		err = filepath.Walk(ctx.Spool, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if strings.HasSuffix(info.Name(), ".lock") {
				return os.Remove(info.Name())
			}
			return nil
		})
		if err != nil {
			log.Fatalln("Error during walking:", err)
		}
		return
	}
	if *nodeRaw == "" {
		usage()
		os.Exit(1)
	}
	node, err := ctx.FindNode(*nodeRaw)
	if err != nil {
		log.Fatalln("Invalid -node specified:", err)
	}
	remove := func(xx nncp.TRxTx) error {
		return filepath.Walk(filepath.Join(ctx.Spool, node.Id.String(), string(xx)), func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if *doSeen && strings.HasSuffix(info.Name(), nncp.SeenSuffix) {
				return os.Remove(info.Name())
			}
			if *doPart && strings.HasSuffix(info.Name(), nncp.PartSuffix) {
				return os.Remove(info.Name())
			}
			if *pktRaw == "" || filepath.Base(info.Name()) == *pktRaw {
				return os.Remove(info.Name())
			}
			return nil
		})
	}
	if *pktRaw != "" || *doRx {
		if err = remove(nncp.TRx); err != nil {
			log.Fatalln("Can not remove:", err)
		}
	}
	if *pktRaw != "" || *doTx {
		if err = remove(nncp.TTx); err != nil {
			log.Fatalln("Can not remove:", err)
		}
	}
}
