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

// Calculate MTH hash of the file
package main

import (
	"bufio"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"sync"

	"go.cypherpunks.ru/nncp/v7"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-hash -- calculate MTH hash of the file\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [-file ...] [-seek X] [-debug] [-progress] [options]\nOptions:\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	var (
		fn        = flag.String("file", "", "Read the file instead of stdin")
		seek      = flag.Uint64("seek", 0, "Seek the file, hash, rewind, hash remaining")
		showPrgrs = flag.Bool("progress", false, "Progress showing")
		debug     = flag.Bool("debug", false, "Print MTH steps calculations")
		version   = flag.Bool("version", false, "Print version information")
		warranty  = flag.Bool("warranty", false, "Print warranty information")
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

	fd := os.Stdin
	var err error
	var size int64
	if *fn == "" {
		*showPrgrs = false
	} else {
		fd, err = os.Open(*fn)
		if err != nil {
			log.Fatalln(err)
		}
		fi, err := fd.Stat()
		if err != nil {
			log.Fatalln(err)
		}
		size = fi.Size()
	}
	mth := nncp.MTHNew(size, int64(*seek))
	var debugger sync.WaitGroup
	if *debug {
		fmt.Println("Leaf BLAKE3 key:", hex.EncodeToString(nncp.MTHLeafKey[:]))
		fmt.Println("Node BLAKE3 key:", hex.EncodeToString(nncp.MTHNodeKey[:]))
		mth.Events = make(chan nncp.MTHEvent)
		debugger.Add(1)
		go func() {
			for e := range mth.Events {
				var t string
				switch e.Type {
				case nncp.MTHEventAppend:
					t = "Add"
				case nncp.MTHEventPrepend:
					t = "Pre"
				case nncp.MTHEventFold:
					t = "Fold"
				}
				fmt.Printf(
					"%s\t%03d\t%06d\t%s\n",
					t, e.Level, e.Ctr, hex.EncodeToString(e.Hsh),
				)
			}
			debugger.Done()
		}()
	}
	if *seek != 0 {
		if *fn == "" {
			log.Fatalln("-file is required with -seek")
		}
		if _, err = fd.Seek(int64(*seek), io.SeekStart); err != nil {
			log.Fatalln(err)
		}
	}
	if _, err = nncp.CopyProgressed(
		mth, bufio.NewReaderSize(fd, nncp.MTHBlockSize),
		"hash", nncp.LEs{{K: "Pkt", V: *fn}, {K: "FullSize", V: size - int64(*seek)}},
		*showPrgrs,
	); err != nil {
		log.Fatalln(err)
	}
	if *seek != 0 {
		if _, err = fd.Seek(0, io.SeekStart); err != nil {
			log.Fatalln(err)
		}
		if *showPrgrs {
			mth.PktName = *fn
		}
		if _, err = mth.PrependFrom(bufio.NewReaderSize(fd, nncp.MTHBlockSize)); err != nil {
			log.Fatalln(err)
		}
	}
	sum := mth.Sum(nil)
	debugger.Wait()
	fmt.Println(hex.EncodeToString(sum))
}
