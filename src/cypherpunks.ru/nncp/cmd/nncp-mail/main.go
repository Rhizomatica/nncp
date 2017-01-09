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

// Send email via NNCP
package main

import (
	"bufio"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"strings"

	"cypherpunks.ru/nncp"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintln(os.Stderr, "nncp-mail -- send email\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options] NODE USER ...\nOptions:\n", os.Args[0])
	flag.PrintDefaults()
	fmt.Fprintln(os.Stderr, "Email body is read from stdin.")
}

func main() {
	var (
		cfgPath  = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		niceRaw  = flag.Int("nice", nncp.DefaultNiceMail, "Outbound packet niceness")
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
	if flag.NArg() < 2 {
		usage()
		os.Exit(1)
	}
	if *niceRaw < 1 || *niceRaw > 255 {
		log.Fatalln("-nice must be between 1 and 255")
	}
	nice := uint8(*niceRaw)

	cfgRaw, err := ioutil.ReadFile(*cfgPath)
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

	body, err := ioutil.ReadAll(bufio.NewReader(os.Stdin))
	if err != nil {
		log.Fatalln("Can not read mail body from stdin:", err)
	}

	if err = ctx.TxMail(node, nice, strings.Join(flag.Args()[1:], " "), body); err != nil {
		log.Fatalln(err)
	}
}
