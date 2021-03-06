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

// Croned NNCP TCP daemon caller.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"go.cypherpunks.ru/nncp/v6"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-caller -- croned NNCP TCP daemon caller\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options] [NODE ...]\n", os.Args[0])
	fmt.Fprintln(os.Stderr, "Options:")
	flag.PrintDefaults()
}

func main() {
	var (
		cfgPath   = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		spoolPath = flag.String("spool", "", "Override path to spool")
		logPath   = flag.String("log", "", "Override path to logfile")
		quiet     = flag.Bool("quiet", false, "Print only errors")
		showPrgrs = flag.Bool("progress", false, "Force progress showing")
		omitPrgrs = flag.Bool("noprogress", false, "Omit progress showing")
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

	var nodes []*nncp.Node
	if flag.NArg() > 0 {
		for _, nodeId := range flag.Args() {
			node, err := ctx.FindNode(nodeId)
			if err != nil {
				log.Fatalln("Invalid NODE specified:", err)
			}
			if len(node.Calls) == 0 {
				ctx.LogD(
					"caller-no-calls",
					nncp.LEs{{K: "Node", V: node.Id}},
					func(les nncp.LEs) string {
						return fmt.Sprintf("%s node has no calls, skipping", node.Name)
					},
				)
				continue
			}
			nodes = append(nodes, node)
		}
	} else {
		for _, node := range ctx.Neigh {
			if len(node.Calls) == 0 {
				ctx.LogD(
					"caller-no-calls",
					nncp.LEs{{K: "Node", V: node.Id}},
					func(les nncp.LEs) string {
						return fmt.Sprintf("%s node has no calls, skipping", node.Name)
					},
				)
				continue
			}
			nodes = append(nodes, node)
		}
	}

	var wg sync.WaitGroup
	for _, node := range nodes {
		for i, call := range node.Calls {
			wg.Add(1)
			go func(node *nncp.Node, i int, call *nncp.Call) {
				defer wg.Done()
				var addrs []string
				if call.Addr == nil {
					for _, addr := range node.Addrs {
						addrs = append(addrs, addr)
					}
				} else {
					addrs = append(addrs, *call.Addr)
				}
				les := nncp.LEs{{K: "Node", V: node.Id}, {K: "CallIndex", V: i}}
				logMsg := func(les nncp.LEs) string {
					return fmt.Sprintf("%s node, call %d", node.Name, i)
				}
				for {
					n := time.Now()
					t := call.Cron.Next(n)
					ctx.LogD("caller-time", les, func(les nncp.LEs) string {
						return logMsg(les) + ": " + t.String()
					})
					if t.IsZero() {
						ctx.LogE("caller", les, errors.New("got zero time"), logMsg)
						return
					}
					time.Sleep(t.Sub(n))
					node.Lock()
					if node.Busy {
						node.Unlock()
						ctx.LogD("caller-busy", les, func(les nncp.LEs) string {
							return logMsg(les) + ": busy"
						})
						continue
					} else {
						node.Busy = true
						node.Unlock()

						if call.WhenTxExists && call.Xx != "TRx" {
							ctx.LogD("caller", les, func(les nncp.LEs) string {
								return logMsg(les) + ": checking tx existence"
							})
							txExists := false
							for job := range ctx.Jobs(node.Id, nncp.TTx) {
								if job.PktEnc.Nice > call.Nice {
									continue
								}
								txExists = true
							}
							if !txExists {
								ctx.LogD("caller-no-tx", les, func(les nncp.LEs) string {
									return logMsg(les) + ": no tx"
								})
								node.Lock()
								node.Busy = false
								node.Unlock()
								continue
							}
						}

						var autoTossFinish chan struct{}
						var autoTossBadCode chan bool
						if call.AutoToss {
							autoTossFinish, autoTossBadCode = ctx.AutoToss(
								node.Id,
								call.Nice,
								call.AutoTossDoSeen,
								call.AutoTossNoFile,
								call.AutoTossNoFreq,
								call.AutoTossNoExec,
								call.AutoTossNoTrns,
							)
						}

						ctx.CallNode(
							node,
							addrs,
							call.Nice,
							call.Xx,
							call.RxRate,
							call.TxRate,
							call.OnlineDeadline,
							call.MaxOnlineTime,
							false,
							call.NoCK,
							nil,
						)

						if call.AutoToss {
							close(autoTossFinish)
							<-autoTossBadCode
						}

						node.Lock()
						node.Busy = false
						node.Unlock()
					}
				}
			}(node, i, call)
		}
	}
	wg.Wait()
}
