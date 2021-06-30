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

// NNCP TCP daemon.
package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/dustin/go-humanize"
	"go.cypherpunks.ru/nncp/v7"
	"golang.org/x/net/netutil"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-daemon -- TCP daemon\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options]\nOptions:\n", os.Args[0])
	flag.PrintDefaults()
}

type InetdConn struct {
	r *os.File
	w *os.File
}

func (c InetdConn) Read(p []byte) (n int, err error) {
	return c.r.Read(p)
}

func (c InetdConn) Write(p []byte) (n int, err error) {
	return c.w.Write(p)
}

func (c InetdConn) SetReadDeadline(t time.Time) error {
	return c.r.SetReadDeadline(t)
}

func (c InetdConn) SetWriteDeadline(t time.Time) error {
	return c.w.SetWriteDeadline(t)
}

func (c InetdConn) Close() error {
	if err := c.r.Close(); err != nil {
		c.w.Close() // #nosec G104
		return err
	}
	return c.w.Close()
}

func performSP(
	ctx *nncp.Ctx,
	conn nncp.ConnDeadlined,
	addr string,
	nice uint8,
	noCK bool,
	nodeIdC chan *nncp.NodeId,
) {
	state := nncp.SPState{
		Ctx:  ctx,
		Nice: nice,
		NoCK: noCK,
	}
	if err := state.StartR(conn); err == nil {
		ctx.LogI(
			"call-started",
			nncp.LEs{{K: "Node", V: state.Node.Id}},
			func(les nncp.LEs) string {
				return fmt.Sprintf("Connection with %s (%s)", state.Node.Name, addr)
			},
		)
		nodeIdC <- state.Node.Id
		state.Wait()
		ctx.LogI("call-finished", nncp.LEs{
			{K: "Node", V: state.Node.Id},
			{K: "Duration", V: int64(state.Duration.Seconds())},
			{K: "RxBytes", V: state.RxBytes},
			{K: "TxBytes", V: state.TxBytes},
			{K: "RxSpeed", V: state.RxSpeed},
			{K: "TxSpeed", V: state.TxSpeed},
		}, func(les nncp.LEs) string {
			return fmt.Sprintf(
				"Finished call with %s (%d:%d:%d): %s received (%s/sec), %s transferred (%s/sec)",
				state.Node.Name,
				int(state.Duration.Hours()),
				int(state.Duration.Minutes()),
				int(state.Duration.Seconds()/60),
				humanize.IBytes(uint64(state.RxBytes)),
				humanize.IBytes(uint64(state.RxSpeed)),
				humanize.IBytes(uint64(state.TxBytes)),
				humanize.IBytes(uint64(state.TxSpeed)),
			)
		})
	} else {
		var nodeId string
		var nodeName string
		if state.Node == nil {
			nodeId = "unknown"
			nodeName = "unknown"
			nodeIdC <- nil
		} else {
			nodeId = state.Node.Id.String()
			nodeName = state.Node.Name
			nodeIdC <- state.Node.Id
		}
		ctx.LogI(
			"call-started",
			nncp.LEs{{K: "Node", V: nodeId}},
			func(les nncp.LEs) string { return "Connected to " + nodeName },
		)
	}
	close(nodeIdC)
}

func main() {
	var (
		cfgPath   = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		niceRaw   = flag.String("nice", nncp.NicenessFmt(255), "Minimal required niceness")
		bind      = flag.String("bind", "[::]:5400", "Address to bind to")
		inetd     = flag.Bool("inetd", false, "Is it started as inetd service")
		maxConn   = flag.Int("maxconn", 128, "Maximal number of simultaneous connections")
		noCK      = flag.Bool("nock", false, "Do no checksum checking")
		mcdOnce   = flag.Bool("mcd-once", false, "Send MCDs once and quit")
		spoolPath = flag.String("spool", "", "Override path to spool")
		logPath   = flag.String("log", "", "Override path to logfile")
		quiet     = flag.Bool("quiet", false, "Print only errors")
		showPrgrs = flag.Bool("progress", false, "Force progress showing")
		omitPrgrs = flag.Bool("noprogress", false, "Omit progress showing")
		debug     = flag.Bool("debug", false, "Print debug messages")
		version   = flag.Bool("version", false, "Print version information")
		warranty  = flag.Bool("warranty", false, "Print warranty information")

		autoToss       = flag.Bool("autotoss", false, "Toss after call is finished")
		autoTossDoSeen = flag.Bool("autotoss-seen", false, "Create .seen files during tossing")
		autoTossNoFile = flag.Bool("autotoss-nofile", false, "Do not process \"file\" packets during tossing")
		autoTossNoFreq = flag.Bool("autotoss-nofreq", false, "Do not process \"freq\" packets during tossing")
		autoTossNoExec = flag.Bool("autotoss-noexec", false, "Do not process \"exec\" packets during tossing")
		autoTossNoTrns = flag.Bool("autotoss-notrns", false, "Do not process \"trns\" packets during tossing")
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

	if *inetd {
		os.Stderr.Close() // #nosec G104
		conn := &InetdConn{os.Stdin, os.Stdout}
		nodeIdC := make(chan *nncp.NodeId)
		go performSP(ctx, conn, "PIPE", nice, *noCK, nodeIdC)
		nodeId := <-nodeIdC
		var autoTossFinish chan struct{}
		var autoTossBadCode chan bool
		if *autoToss && nodeId != nil {
			autoTossFinish, autoTossBadCode = ctx.AutoToss(
				nodeId,
				nice,
				*autoTossDoSeen,
				*autoTossNoFile,
				*autoTossNoFreq,
				*autoTossNoExec,
				*autoTossNoTrns,
			)
		}
		<-nodeIdC // call completion
		if *autoToss {
			close(autoTossFinish)
			<-autoTossBadCode
		}
		conn.Close() // #nosec G104
		return
	}

	cols := strings.Split(*bind, ":")
	port, err := strconv.Atoi(cols[len(cols)-1])
	if err != nil {
		log.Fatalln("Can not parse port:", err)
	}

	if *mcdOnce {
		for ifiName := range ctx.MCDTxIfis {
			if err = ctx.MCDTx(ifiName, port, 0); err != nil {
				log.Fatalln("Can not do MCD transmission:", err)
			}
		}
		return
	}

	ln, err := net.Listen("tcp", *bind)
	if err != nil {
		log.Fatalln("Can not listen:", err)
	}

	for ifiName, secs := range ctx.MCDTxIfis {
		if err = ctx.MCDTx(ifiName, port, time.Duration(secs)*time.Second); err != nil {
			log.Fatalln("Can not run MCD transmission:", err)
		}
	}

	ln = netutil.LimitListener(ln, *maxConn)
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatalln("Can not accept connection:", err)
		}
		ctx.LogD(
			"daemon-accepted",
			nncp.LEs{{K: "Addr", V: conn.RemoteAddr()}},
			func(les nncp.LEs) string {
				return "Accepted connection with " + conn.RemoteAddr().String()
			},
		)
		go func(conn net.Conn) {
			nodeIdC := make(chan *nncp.NodeId)
			go performSP(ctx, conn, conn.RemoteAddr().String(), nice, *noCK, nodeIdC)
			nodeId := <-nodeIdC
			var autoTossFinish chan struct{}
			var autoTossBadCode chan bool
			if *autoToss && nodeId != nil {
				autoTossFinish, autoTossBadCode = ctx.AutoToss(
					nodeId,
					nice,
					*autoTossDoSeen,
					*autoTossNoFile,
					*autoTossNoFreq,
					*autoTossNoExec,
					*autoTossNoTrns,
				)
			}
			<-nodeIdC // call completion
			if *autoToss {
				close(autoTossFinish)
				<-autoTossBadCode
			}
			conn.Close() // #nosec G104
		}(conn)
	}
}
