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

// Generate new NNCP node keys
package main

import (
	"flag"
	"fmt"
	"os"

	"cypherpunks.ru/nncp"
	"gopkg.in/yaml.v2"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintln(os.Stderr, "nncp-newnode -- generate new node keys\nOptions:")
	flag.PrintDefaults()
}

func main() {
	var (
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
	nodeOur, err := nncp.NewNodeGenerate()
	if err != nil {
		panic(err)
	}
	incoming := "/path/to/upload/dir, omit it to forbid uploading"
	freq := "/path/to/freq/able/dir, omit to forbid freqing"
	cfg := nncp.CfgYAML{
		Self: nncp.NodeOurYAML{
			Id:       nodeOur.Id.String(),
			ExchPub:  nncp.ToBase32(nodeOur.ExchPub[:]),
			ExchPrv:  nncp.ToBase32(nodeOur.ExchPrv[:]),
			SignPub:  nncp.ToBase32(nodeOur.SignPub[:]),
			SignPrv:  nncp.ToBase32(nodeOur.SignPrv[:]),
			NoisePub: nncp.ToBase32(nodeOur.NoisePub[:]),
			NoisePrv: nncp.ToBase32(nodeOur.NoisePrv[:]),
		},
		Neigh: map[string]nncp.NodeYAML{
			"self": nncp.NodeYAML{
				Id:       nodeOur.Id.String(),
				ExchPub:  nncp.ToBase32(nodeOur.ExchPub[:]),
				SignPub:  nncp.ToBase32(nodeOur.SignPub[:]),
				NoisePub: nncp.ToBase32(nodeOur.NoisePub[:]),
				Sendmail: []string{nncp.DefaultSendmailPath},
				Incoming: &incoming,
				Freq:     &freq,
				Addrs:    map[string]string{"main": "localhost:5400"},
			},
		},
		Spool: "/path/to/spool",
		Log:   "/path/to/log.file",
		Notify: &nncp.NotifyYAML{
			File: &nncp.FromToYAML{
				From: "nncp@localhost",
				To:   "root@localhost, delete section to disable notifies",
			},
			Freq: &nncp.FromToYAML{
				From: "nncp@localhost",
				To:   "root@localhost, delete section to disable notifies",
			},
		},
	}
	raw, err := yaml.Marshal(&cfg)
	if err != nil {
		panic(err)
	}
	fmt.Print(string(raw))
}
