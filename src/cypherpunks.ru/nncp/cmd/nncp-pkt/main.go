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

// Parse raw NNCP packet
package main

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"

	"cypherpunks.ru/nncp"
	"github.com/davecgh/go-xdr/xdr2"
	"golang.org/x/crypto/blake2b"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintln(os.Stderr, "nncp-pkt -- parse raw packet\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\nOptions:\n", os.Args[0])
	flag.PrintDefaults()
	fmt.Fprintln(os.Stderr, "Packet is read from stdin.")
}

func main() {
	var (
		dump       = flag.Bool("dump", false, "Write decrypted/parsed payload to stdout")
		decompress = flag.Bool("decompress", false, "Try to zlib decompress dumped data")
		cfgPath    = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		version    = flag.Bool("version", false, "Print version information")
		warranty   = flag.Bool("warranty", false, "Print warranty information")
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

	var err error
	beginning := make([]byte, nncp.PktOverhead-8-2*blake2b.Size256)
	if _, err = io.ReadFull(os.Stdin, beginning); err != nil {
		log.Fatalln("Not enough data to read")
	}
	var pkt nncp.Pkt
	_, err = xdr.Unmarshal(bytes.NewReader(beginning), &pkt)
	if err == nil && pkt.Magic == nncp.MagicNNCPPv1 {
		if *dump {
			bufW := bufio.NewWriter(os.Stdout)
			var r io.Reader
			r = bufio.NewReader(os.Stdin)
			if *decompress {
				decompressor, err := zlib.NewReader(r)
				if err != nil {
					log.Fatalln(err)
				}
				r = decompressor
			}
			if _, err = io.Copy(bufW, r); err != nil {
				log.Fatalln(err)
			}
			if err = bufW.Flush(); err != nil {
				log.Fatalln(err)
			}
			return
		}
		payloadType := "unknown"
		switch pkt.Type {
		case nncp.PktTypeFile:
			payloadType = "file"
		case nncp.PktTypeFreq:
			payloadType = "file request"
		case nncp.PktTypeMail:
			payloadType = "mail"
		case nncp.PktTypeTrns:
			payloadType = "transitional"
		}
		var path string
		switch pkt.Type {
		case nncp.PktTypeTrns:
			path = nncp.ToBase32(pkt.Path[:pkt.PathLen])
		default:
			path = string(pkt.Path[:pkt.PathLen])
		}
		fmt.Printf("Packet type: plain\nPayload type: %s\nPath: %s\n", payloadType, path)
		return
	}
	var pktEnc nncp.PktEnc
	_, err = xdr.Unmarshal(bytes.NewReader(beginning), &pktEnc)
	if err == nil && pktEnc.Magic == nncp.MagicNNCPEv1 {
		if *dump {
			cfgRaw, err := ioutil.ReadFile(nncp.CfgPathFromEnv(cfgPath))
			if err != nil {
				log.Fatalln("Can not read config:", err)
			}
			ctx, err := nncp.CfgParse(cfgRaw)
			if err != nil {
				log.Fatalln("Can not parse config:", err)
			}
			bufW := bufio.NewWriter(os.Stdout)
			if _, _, err = nncp.PktEncRead(
				ctx.Self,
				ctx.Neigh,
				io.MultiReader(
					bytes.NewReader(beginning),
					bufio.NewReader(os.Stdin),
				),
				bufW,
			); err != nil {
				log.Fatalln(err)
			}
			if err = bufW.Flush(); err != nil {
				log.Fatalln(err)
			}
			return
		}
		fmt.Printf(
			"Packet type: encrypted\nNiceness: %d\nSender: %s\n",
			pktEnc.Nice, pktEnc.Sender,
		)
		return
	}
	log.Fatalln("Unable to determine packet type")
}
