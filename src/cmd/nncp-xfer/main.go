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

// Exchange NNCP inbound and outbounds packets with external directory.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	xdr "github.com/davecgh/go-xdr/xdr2"
	"go.cypherpunks.ru/nncp/v5"
)

func usage() {
	fmt.Fprintf(os.Stderr, nncp.UsageHeader())
	fmt.Fprintf(os.Stderr, "nncp-xfer -- copy inbound and outbounds packets\n\n")
	fmt.Fprintf(os.Stderr, "Usage: %s [options] DIR\nOptions:\n", os.Args[0])
	flag.PrintDefaults()
}

func main() {
	var (
		cfgPath   = flag.String("cfg", nncp.DefaultCfgPath, "Path to configuration file")
		nodeRaw   = flag.String("node", "", "Process only that node")
		niceRaw   = flag.String("nice", nncp.NicenessFmt(255), "Minimal required niceness")
		rxOnly    = flag.Bool("rx", false, "Only receive packets")
		txOnly    = flag.Bool("tx", false, "Only transfer packets")
		mkdir     = flag.Bool("mkdir", false, "Create necessary outbound directories")
		keep      = flag.Bool("keep", false, "Do not delete transferred packets")
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
	if flag.NArg() != 1 {
		usage()
		os.Exit(1)
	}
	nice, err := nncp.NicenessParse(*niceRaw)
	if err != nil {
		log.Fatalln(err)
	}
	if *rxOnly && *txOnly {
		log.Fatalln("-rx and -tx can not be set simultaneously")
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

	var nodeOnly *nncp.Node
	if *nodeRaw != "" {
		nodeOnly, err = ctx.FindNode(*nodeRaw)
		if err != nil {
			log.Fatalln("Invalid -node specified:", err)
		}
	}

	ctx.Umask()
	selfPath := filepath.Join(flag.Arg(0), ctx.SelfId.String())
	isBad := false
	var dir *os.File
	var fis []os.FileInfo
	var les nncp.LEs
	if *txOnly {
		goto Tx
	}
	les = nncp.LEs{
		{K: "XX", V: string(nncp.TRx)},
		{K: "Dir", V: selfPath},
	}
	ctx.LogD("nncp-xfer", les, "self")
	if _, err = os.Stat(selfPath); err != nil {
		if os.IsNotExist(err) {
			ctx.LogD("nncp-xfer", les, "no dir")
			goto Tx
		}
		ctx.LogE("nncp-xfer", les, err, "stat")
		isBad = true
		goto Tx
	}
	dir, err = os.Open(selfPath)
	if err != nil {
		ctx.LogE("nncp-xfer", les, err, "open")
		isBad = true
		goto Tx
	}
	fis, err = dir.Readdir(0)
	dir.Close() // #nosec G104
	if err != nil {
		ctx.LogE("nncp-xfer", les, err, "read")
		isBad = true
		goto Tx
	}
	for _, fi := range fis {
		if !fi.IsDir() {
			continue
		}
		nodeId, err := nncp.NodeIdFromString(fi.Name())
		les := append(les, nncp.LE{K: "Node", V: fi.Name()})
		if err != nil {
			ctx.LogD("nncp-xfer", les, "is not NodeId")
			continue
		}
		if nodeOnly != nil && *nodeId != *nodeOnly.Id {
			ctx.LogD("nncp-xfer", les, "skip")
			continue
		}
		if _, known := ctx.Neigh[*nodeId]; !known {
			ctx.LogD("nncp-xfer", les, "unknown")
			continue
		}
		dir, err = os.Open(filepath.Join(selfPath, fi.Name()))
		if err != nil {
			ctx.LogE("nncp-xfer", les, err, "open")
			isBad = true
			continue
		}
		fisInt, err := dir.Readdir(0)
		dir.Close() // #nosec G104
		if err != nil {
			ctx.LogE("nncp-xfer", les, err, "read")
			isBad = true
			continue
		}
		for _, fiInt := range fisInt {
			if !fi.IsDir() {
				continue
			}
			// Check that it is valid Base32 encoding
			if _, err = nncp.NodeIdFromString(fiInt.Name()); err != nil {
				continue
			}
			filename := filepath.Join(dir.Name(), fiInt.Name())
			les := append(les, nncp.LE{K: "File", V: filename})
			fd, err := os.Open(filename)
			if err != nil {
				ctx.LogE("nncp-xfer", les, err, "open")
				isBad = true
				continue
			}
			var pktEnc nncp.PktEnc
			_, err = xdr.Unmarshal(fd, &pktEnc)
			if err != nil || pktEnc.Magic != nncp.MagicNNCPEv4 {
				ctx.LogD("nncp-xfer", les, "is not a packet")
				fd.Close() // #nosec G104
				continue
			}
			if pktEnc.Nice > nice {
				ctx.LogD("nncp-xfer", les, "too nice")
				fd.Close() // #nosec G104
				continue
			}
			les = append(les, nncp.LE{K: "Size", V: fiInt.Size()})
			if !ctx.IsEnoughSpace(fiInt.Size()) {
				ctx.LogE("nncp-xfer", les, errors.New("is not enough space"), "")
				fd.Close() // #nosec G104
				continue
			}
			if _, err = fd.Seek(0, 0); err != nil {
				log.Fatalln(err)
			}
			tmp, err := ctx.NewTmpFileWHash()
			if err != nil {
				log.Fatalln(err)
			}
			r, w := io.Pipe()
			go func() {
				_, err := io.CopyN(w, bufio.NewReader(fd), fiInt.Size())
				if err == nil {
					err = w.Close()
				}
				if err != nil {
					ctx.LogE("nncp-xfer", les, err, "copy")
					w.CloseWithError(err) // #nosec G104
				}
			}()
			if _, err = nncp.CopyProgressed(
				tmp.W, r, "Rx",
				append(les, nncp.LEs{
					{K: "Pkt", V: filename},
					{K: "FullSize", V: fiInt.Size()},
				}...),
				ctx.ShowPrgrs,
			); err != nil {
				ctx.LogE("nncp-xfer", les, err, "copy")
				isBad = true
			}
			fd.Close() // #nosec G104
			if isBad {
				tmp.Cancel()
				continue
			}
			if err = tmp.Commit(filepath.Join(
				ctx.Spool,
				nodeId.String(),
				string(nncp.TRx),
			)); err != nil {
				log.Fatalln(err)
			}
			ctx.LogI("nncp-xfer", les, "")
			if !*keep {
				if err = os.Remove(filename); err != nil {
					ctx.LogE("nncp-xfer", les, err, "remove")
					isBad = true
				}
			}
		}
	}

Tx:
	if *rxOnly {
		if isBad {
			os.Exit(1)
		}
		return
	}
	for nodeId := range ctx.Neigh {
		les := nncp.LEs{
			{K: "XX", V: string(nncp.TTx)},
			{K: "Node", V: nodeId},
		}
		if nodeOnly != nil && nodeId != *nodeOnly.Id {
			ctx.LogD("nncp-xfer", les, "skip")
			continue
		}
		dirLock, err := ctx.LockDir(&nodeId, string(nncp.TTx))
		if err != nil {
			continue
		}
		nodePath := filepath.Join(flag.Arg(0), nodeId.String())
		les = append(les, nncp.LE{K: "Dir", V: nodePath})
		_, err = os.Stat(nodePath)
		if err != nil {
			if os.IsNotExist(err) {
				ctx.LogD("nncp-xfer", les, "does not exist")
				if !*mkdir {
					ctx.UnlockDir(dirLock)
					continue
				}
				if err = os.Mkdir(nodePath, os.FileMode(0777)); err != nil {
					ctx.UnlockDir(dirLock)
					ctx.LogE("nncp-xfer", les, err, "mkdir")
					isBad = true
					continue
				}
			} else {
				ctx.UnlockDir(dirLock)
				ctx.LogE("nncp-xfer", les, err, "stat")
				isBad = true
				continue
			}
		}
		dstPath := filepath.Join(nodePath, ctx.SelfId.String())
		les[len(les)-1].V = dstPath
		_, err = os.Stat(dstPath)
		if err != nil {
			if os.IsNotExist(err) {
				if err = os.Mkdir(dstPath, os.FileMode(0777)); err != nil {
					ctx.UnlockDir(dirLock)
					ctx.LogE("nncp-xfer", les, err, "mkdir")
					isBad = true
					continue
				}
			} else {
				ctx.UnlockDir(dirLock)
				ctx.LogE("nncp-xfer", les, err, "stat")
				isBad = true
				continue
			}
		}
		les = les[:len(les)-1]
		for job := range ctx.Jobs(&nodeId, nncp.TTx) {
			pktName := filepath.Base(job.Fd.Name())
			les := append(les, nncp.LE{K: "Pkt", V: pktName})
			if job.PktEnc.Nice > nice {
				ctx.LogD("nncp-xfer", les, "too nice")
				job.Fd.Close() // #nosec G104
				continue
			}
			if _, err = os.Stat(filepath.Join(dstPath, pktName)); err == nil || !os.IsNotExist(err) {
				ctx.LogD("nncp-xfer", les, "already exists")
				job.Fd.Close() // #nosec G104
				continue
			}
			if _, err = os.Stat(filepath.Join(dstPath, pktName+nncp.SeenSuffix)); err == nil || !os.IsNotExist(err) {
				ctx.LogD("nncp-xfer", les, "already exists")
				job.Fd.Close() // #nosec G104
				continue
			}
			tmp, err := nncp.TempFile(dstPath, "xfer")
			if err != nil {
				ctx.LogE("nncp-xfer", les, err, "mktemp")
				job.Fd.Close() // #nosec G104
				isBad = true
				break
			}
			les = append(les, nncp.LE{K: "Tmp", V: tmp.Name()})
			ctx.LogD("nncp-xfer", les, "created")
			bufW := bufio.NewWriter(tmp)
			copied, err := nncp.CopyProgressed(
				bufW, bufio.NewReader(job.Fd), "Tx",
				append(les, nncp.LE{K: "FullSize", V: job.Size}),
				ctx.ShowPrgrs,
			)
			job.Fd.Close() // #nosec G104
			if err != nil {
				ctx.LogE("nncp-xfer", les, err, "copy")
				tmp.Close() // #nosec G104
				isBad = true
				continue
			}
			if err = bufW.Flush(); err != nil {
				tmp.Close() // #nosec G104
				ctx.LogE("nncp-xfer", les, err, "flush")
				isBad = true
				continue
			}
			if err = tmp.Sync(); err != nil {
				tmp.Close() // #nosec G104
				ctx.LogE("nncp-xfer", les, err, "sync")
				isBad = true
				continue
			}
			if err = tmp.Close(); err != nil {
				ctx.LogE("nncp-xfer", les, err, "sync")
			}
			if err = os.Rename(tmp.Name(), filepath.Join(dstPath, pktName)); err != nil {
				ctx.LogE("nncp-xfer", les, err, "rename")
				isBad = true
				continue
			}
			if err = nncp.DirSync(dstPath); err != nil {
				ctx.LogE("nncp-xfer", les, err, "sync")
				isBad = true
				continue
			}
			os.Remove(filepath.Join(dstPath, pktName+".part")) // #nosec G104
			les = les[:len(les)-1]
			ctx.LogI("nncp-xfer", append(les, nncp.LE{K: "Size", V: copied}), "")
			if !*keep {
				if err = os.Remove(job.Fd.Name()); err != nil {
					ctx.LogE("nncp-xfer", les, err, "remove")
					isBad = true
				}
			}
		}
		ctx.UnlockDir(dirLock)
	}
	if isBad {
		os.Exit(1)
	}
}
