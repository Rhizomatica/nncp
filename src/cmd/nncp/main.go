package main

import (
	"flag"
	"fmt"
	"os"
	"path"

	"go.cypherpunks.su/nncp/v8"
)

const (
	CmdNameACK      = "nncp-ack"
	CmdNameBundle   = "nncp-bundle"
	CmdNameCall     = "nncp-call"
	CmdNameCaller   = "nncp-caller"
	CmdNameCfgDir   = "nncp-cfgdir"
	CmdNameCfgEnc   = "nncp-cfgenc"
	CmdNameCfgMin   = "nncp-cfgmin"
	CmdNameCfgNew   = "nncp-cfgnew"
	CmdNameCheck    = "nncp-check"
	CmdNameCronExpr = "nncp-cronexpr"
	CmdNameDaemon   = "nncp-daemon"
	CmdNameExec     = "nncp-exec"
	CmdNameFile     = "nncp-file"
	CmdNameFreq     = "nncp-freq"
	CmdNameHash     = "nncp-hash"
	CmdNameLog      = "nncp-log"
	CmdNameMain     = "nncp-main"
	CmdNamePkt      = "nncp-pkt"
	CmdNameReass    = "nncp-reass"
	CmdNameRm       = "nncp-rm"
	CmdNameStat     = "nncp-stat"
	CmdNameToss     = "nncp-toss"
	CmdNameTrns     = "nncp-trns"
	CmdNameXfer     = "nncp-xfer"
)

func main() {
	cmdName := path.Base(os.Args[0])
	switch cmdName {
	case CmdNameACK:
		mainACK()
	case CmdNameBundle:
		mainBundle()
	case CmdNameCall:
		mainCall()
	case CmdNameCaller:
		mainCaller()
	case CmdNameCfgDir:
		mainCfgDir()
	case CmdNameCfgEnc:
		mainCfgEnc()
	case CmdNameCfgMin:
		mainCfgMin()
	case CmdNameCfgNew:
		mainCfgNew()
	case CmdNameCheck:
		mainCheck()
	case CmdNameCronExpr:
		mainCronExpr()
	case CmdNameDaemon:
		mainDaemon()
	case CmdNameExec:
		mainExec()
	case CmdNameFile:
		mainFile()
	case CmdNameFreq:
		mainFreq()
	case CmdNameHash:
		mainHash()
	case CmdNameLog:
		mainLog()
	case CmdNamePkt:
		mainPkt()
	case CmdNameReass:
		mainReass()
	case CmdNameRm:
		mainRm()
	case CmdNameStat:
		mainStat()
	case CmdNameToss:
		mainToss()
	case CmdNameTrns:
		mainTrns()
	case CmdNameXfer:
		mainXfer()
	default:
		version := flag.Bool("version", false, "Print version information")
		warranty := flag.Bool("warranty", false, "Print warranty information")
		flag.Parse()
		if *warranty {
			fmt.Println(nncp.Warranty)
			return
		}
		if *version {
			fmt.Println(nncp.VersionGet())
			return
		}
	}
}
