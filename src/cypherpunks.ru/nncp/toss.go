/*
NNCP -- Node to Node copy, utilities for store-and-forward data exchange
Copyright (C) 2016-2018 Sergey Matveev <stargrave@stargrave.org>

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

package nncp

import (
	"bufio"
	"compress/zlib"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"mime"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/davecgh/go-xdr/xdr2"
	"github.com/dustin/go-humanize"
	"golang.org/x/crypto/blake2b"
)

const (
	SeenSuffix = ".seen"
)

func newNotification(fromTo *FromToYAML, subject string) io.Reader {
	return strings.NewReader(fmt.Sprintf(
		"From: %s\nTo: %s\nSubject: %s\n",
		fromTo.From,
		fromTo.To,
		mime.BEncoding.Encode("UTF-8", subject),
	))
}

func (ctx *Ctx) Toss(nodeId *NodeId, nice uint8, dryRun, doSeen bool) bool {
	isBad := false
	for job := range ctx.Jobs(nodeId, TRx) {
		pktName := filepath.Base(job.Fd.Name())
		sds := SDS{"node": job.PktEnc.Sender, "pkt": pktName}
		if job.PktEnc.Nice > nice {
			ctx.LogD("rx", SdsAdd(sds, SDS{
				"nice": strconv.Itoa(int(job.PktEnc.Nice)),
			}), "too nice")
			continue
		}
		pipeR, pipeW := io.Pipe()
		errs := make(chan error, 1)
		go func(job Job) {
			pipeWB := bufio.NewWriter(pipeW)
			_, _, err := PktEncRead(
				ctx.Self,
				ctx.Neigh,
				bufio.NewReader(job.Fd),
				pipeWB,
			)
			errs <- err
			pipeWB.Flush()
			pipeW.Close()
			job.Fd.Close()
			if err != nil {
				ctx.LogE("rx", SdsAdd(sds, SDS{"err": err}), "decryption")
			}
		}(job)
		var pkt Pkt
		var err error
		var pktSize int64
		if _, err = xdr.Unmarshal(pipeR, &pkt); err != nil {
			ctx.LogE("rx", SdsAdd(sds, SDS{"err": err}), "unmarshal")
			isBad = true
			goto Closing
		}
		pktSize = job.Size - PktEncOverhead - PktOverhead
		sds["size"] = strconv.FormatInt(pktSize, 10)
		ctx.LogD("rx", sds, "taken")
		switch pkt.Type {
		case PktTypeMail:
			recipients := string(pkt.Path[:int(pkt.PathLen)])
			sds := SdsAdd(sds, SDS{
				"type": "mail",
				"dst":  recipients,
			})
			decompressor, err := zlib.NewReader(pipeR)
			if err != nil {
				log.Fatalln(err)
			}
			sender := ctx.Neigh[*job.PktEnc.Sender]
			sendmail := sender.Sendmail
			if len(sendmail) == 0 {
				ctx.LogE("rx", SdsAdd(sds, SDS{"err": "No sendmail configured"}), "")
				isBad = true
				goto Closing
			}
			if !dryRun {
				cmd := exec.Command(
					sendmail[0],
					append(
						sendmail[1:len(sendmail)],
						strings.Split(recipients, " ")...,
					)...,
				)
				cmd.Env = append(cmd.Env, "NNCP_SENDER="+sender.Id.String())
				cmd.Stdin = decompressor
				if err = cmd.Run(); err != nil {
					ctx.LogE("rx", SdsAdd(sds, SDS{"err": err}), "sendmail")
					isBad = true
					goto Closing
				}
			}
			ctx.LogI("rx", sds, "")
			if !dryRun {
				if doSeen {
					if fd, err := os.Create(job.Fd.Name() + SeenSuffix); err == nil {
						fd.Close()
					}
				}
				if err = os.Remove(job.Fd.Name()); err != nil {
					ctx.LogE("rx", SdsAdd(sds, SDS{"err": err}), "remove")
					isBad = true
				}
			}
		case PktTypeFile:
			dst := string(pkt.Path[:int(pkt.PathLen)])
			sds := SdsAdd(sds, SDS{"type": "file", "dst": dst})
			if filepath.IsAbs(dst) {
				ctx.LogE("rx", sds, "non-relative destination path")
				isBad = true
				goto Closing
			}
			incoming := ctx.Neigh[*job.PktEnc.Sender].Incoming
			if incoming == nil {
				ctx.LogE("rx", sds, "incoming is not allowed")
				isBad = true
				goto Closing
			}
			dir := filepath.Join(*incoming, path.Dir(dst))
			if err = os.MkdirAll(dir, os.FileMode(0700)); err != nil {
				ctx.LogE("rx", SdsAdd(sds, SDS{"err": err}), "mkdir")
				isBad = true
				goto Closing
			}
			if !dryRun {
				tmp, err := ioutil.TempFile(dir, "nncp-file")
				sds["tmp"] = tmp.Name()
				ctx.LogD("rx", sds, "created")
				if err != nil {
					ctx.LogE("rx", SdsAdd(sds, SDS{"err": err}), "mktemp")
					isBad = true
					goto Closing
				}
				bufW := bufio.NewWriter(tmp)
				if _, err = io.Copy(bufW, pipeR); err != nil {
					ctx.LogE("rx", SdsAdd(sds, SDS{"err": err}), "copy")
					isBad = true
					goto Closing
				}
				bufW.Flush()
				tmp.Sync()
				tmp.Close()
				dstPathOrig := filepath.Join(*incoming, dst)
				dstPath := dstPathOrig
				dstPathCtr := 0
				for {
					if _, err = os.Stat(dstPath); err != nil {
						if os.IsNotExist(err) {
							break
						}
						ctx.LogE("rx", SdsAdd(sds, SDS{"err": err}), "stat")
						isBad = true
						goto Closing
					}
					dstPath = dstPathOrig + strconv.Itoa(dstPathCtr)
					dstPathCtr++
				}
				if err = os.Rename(tmp.Name(), dstPath); err != nil {
					ctx.LogE("rx", SdsAdd(sds, SDS{"err": err}), "rename")
					isBad = true
				}
				delete(sds, "tmp")
			}
			ctx.LogI("rx", sds, "")
			if !dryRun {
				if doSeen {
					if fd, err := os.Create(job.Fd.Name() + SeenSuffix); err == nil {
						fd.Close()
					}
				}
				if err = os.Remove(job.Fd.Name()); err != nil {
					ctx.LogE("rx", SdsAdd(sds, SDS{"err": err}), "remove")
					isBad = true
				}
				sendmail := ctx.Neigh[*ctx.SelfId].Sendmail
				if ctx.NotifyFile != nil {
					cmd := exec.Command(
						sendmail[0],
						append(sendmail[1:len(sendmail)], ctx.NotifyFile.To)...,
					)
					cmd.Stdin = newNotification(ctx.NotifyFile, fmt.Sprintf(
						"File from %s: %s (%s)",
						ctx.Neigh[*job.PktEnc.Sender].Name,
						dst,
						humanize.IBytes(uint64(pktSize)),
					))
					cmd.Run()
				}
			}
		case PktTypeFreq:
			src := string(pkt.Path[:int(pkt.PathLen)])
			if filepath.IsAbs(src) {
				ctx.LogE("rx", sds, "non-relative source path")
				isBad = true
				goto Closing
			}
			sds := SdsAdd(sds, SDS{"type": "freq", "src": src})
			dstRaw, err := ioutil.ReadAll(pipeR)
			if err != nil {
				ctx.LogE("rx", SdsAdd(sds, SDS{"err": err}), "read")
				isBad = true
				goto Closing
			}
			dst := string(dstRaw)
			sds["dst"] = dst
			sender := ctx.Neigh[*job.PktEnc.Sender]
			freq := sender.Freq
			if freq == nil {
				ctx.LogE("rx", sds, "freqing is not allowed")
				isBad = true
				goto Closing
			}
			if !dryRun {
				if sender.FreqChunked == 0 {
					err = ctx.TxFile(
						sender,
						job.PktEnc.Nice,
						filepath.Join(*freq, src),
						dst,
						sender.FreqMinSize,
					)
				} else {
					err = ctx.TxFileChunked(
						sender,
						job.PktEnc.Nice,
						filepath.Join(*freq, src),
						dst,
						sender.FreqMinSize,
						sender.FreqChunked,
					)
				}
				if err != nil {
					ctx.LogE("rx", SdsAdd(sds, SDS{"err": err}), "tx file")
					isBad = true
					goto Closing
				}
			}
			ctx.LogI("rx", sds, "")
			if !dryRun {
				if doSeen {
					if fd, err := os.Create(job.Fd.Name() + SeenSuffix); err == nil {
						fd.Close()
					}
				}
				if err = os.Remove(job.Fd.Name()); err != nil {
					ctx.LogE("rx", SdsAdd(sds, SDS{"err": err}), "remove")
					isBad = true
				}
				if ctx.NotifyFreq != nil {
					sendmail := ctx.Neigh[*ctx.SelfId].Sendmail
					cmd := exec.Command(
						sendmail[0],
						append(sendmail[1:len(sendmail)], ctx.NotifyFreq.To)...,
					)
					cmd.Stdin = newNotification(ctx.NotifyFreq, fmt.Sprintf(
						"Freq from %s: %s",
						ctx.Neigh[*job.PktEnc.Sender].Name,
						src,
					))
					cmd.Run()
				}
			}
		case PktTypeTrns:
			dst := new([blake2b.Size256]byte)
			copy(dst[:], pkt.Path[:int(pkt.PathLen)])
			nodeId := NodeId(*dst)
			node, known := ctx.Neigh[nodeId]
			sds := SdsAdd(sds, SDS{"type": "trns", "dst": nodeId})
			if !known {
				ctx.LogE("rx", sds, "unknown node")
				isBad = true
				goto Closing
			}
			ctx.LogD("rx", sds, "taken")
			if !dryRun {
				if err = ctx.TxTrns(node, job.PktEnc.Nice, pktSize, pipeR); err != nil {
					ctx.LogE("rx", SdsAdd(sds, SDS{"err": err}), "tx trns")
					isBad = true
					goto Closing
				}
			}
			ctx.LogI("rx", sds, "")
			if !dryRun {
				if doSeen {
					if fd, err := os.Create(job.Fd.Name() + SeenSuffix); err == nil {
						fd.Close()
					}
				}
				if err = os.Remove(job.Fd.Name()); err != nil {
					ctx.LogE("rx", SdsAdd(sds, SDS{"err": err}), "remove")
					isBad = true
				}
			}
		default:
			ctx.LogE("rx", sds, "unknown type")
			isBad = true
		}
	Closing:
		pipeR.Close()
	}
	return isBad
}
