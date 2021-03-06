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

package nncp

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"errors"
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
	"time"

	xdr "github.com/davecgh/go-xdr/xdr2"
	"github.com/dustin/go-humanize"
	"github.com/klauspost/compress/zstd"
	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/poly1305"
)

const (
	SeenSuffix = ".seen"
)

func newNotification(fromTo *FromToJSON, subject string, body []byte) io.Reader {
	lines := []string{
		"From: " + fromTo.From,
		"To: " + fromTo.To,
		"Subject: " + mime.BEncoding.Encode("UTF-8", subject),
	}
	if len(body) > 0 {
		lines = append(
			lines,
			"MIME-Version: 1.0",
			"Content-Type: text/plain; charset=utf-8",
			"Content-Transfer-Encoding: base64",
			"",
			base64.StdEncoding.EncodeToString(body),
		)
	}
	return strings.NewReader(strings.Join(lines, "\n"))
}

func (ctx *Ctx) Toss(
	nodeId *NodeId,
	nice uint8,
	dryRun, doSeen, noFile, noFreq, noExec, noTrns bool,
) bool {
	dirLock, err := ctx.LockDir(nodeId, "toss")
	if err != nil {
		return false
	}
	defer ctx.UnlockDir(dirLock)
	isBad := false
	sendmail := ctx.Neigh[*ctx.SelfId].Exec["sendmail"]
	decompressor, err := zstd.NewReader(nil)
	if err != nil {
		panic(err)
	}
	defer decompressor.Close()
	for job := range ctx.Jobs(nodeId, TRx) {
		pktName := filepath.Base(job.Path)
		les := LEs{
			{"Node", job.PktEnc.Sender},
			{"Pkt", pktName},
			{"Nice", int(job.PktEnc.Nice)},
		}
		if job.PktEnc.Nice > nice {
			ctx.LogD("rx-too-nice", les, func(les LEs) string {
				return fmt.Sprintf(
					"Tossing %s/%s: too nice: %s",
					ctx.NodeName(job.PktEnc.Sender), pktName,
					NicenessFmt(job.PktEnc.Nice),
				)
			})
			continue
		}
		fd, err := os.Open(job.Path)
		if err != nil {
			ctx.LogE("rx-open", les, err, func(les LEs) string {
				return fmt.Sprintf(
					"Tossing %s/%s: opening %s",
					ctx.NodeName(job.PktEnc.Sender), pktName, job.Path,
				)
			})
			isBad = true
			continue
		}

		pipeR, pipeW := io.Pipe()
		go func(job Job) error {
			pipeWB := bufio.NewWriter(pipeW)
			_, _, err := PktEncRead(ctx.Self, ctx.Neigh, bufio.NewReader(fd), pipeWB)
			fd.Close() // #nosec G104
			if err != nil {
				return pipeW.CloseWithError(err)
			}
			if err = pipeWB.Flush(); err != nil {
				return pipeW.CloseWithError(err)
			}
			return pipeW.Close()
		}(job)
		var pkt Pkt
		var pktSize int64
		var pktSizeBlocks int64
		if _, err = xdr.Unmarshal(pipeR, &pkt); err != nil {
			ctx.LogE("rx-unmarshal", les, err, func(les LEs) string {
				return fmt.Sprintf(
					"Tossing %s/%s: unmarshal",
					ctx.NodeName(job.PktEnc.Sender), pktName,
				)
			})
			isBad = true
			goto Closing
		}
		pktSize = job.Size - PktEncOverhead - PktOverhead - PktSizeOverhead
		pktSizeBlocks = pktSize / (EncBlkSize + poly1305.TagSize)
		if pktSize%(EncBlkSize+poly1305.TagSize) != 0 {
			pktSize -= poly1305.TagSize
		}
		pktSize -= pktSizeBlocks * poly1305.TagSize
		les = append(les, LE{"Size", pktSize})
		ctx.LogD("rx", les, func(les LEs) string {
			return fmt.Sprintf(
				"Tossing %s/%s (%s)",
				ctx.NodeName(job.PktEnc.Sender), pktName,
				humanize.IBytes(uint64(pktSize)),
			)
		})

		switch pkt.Type {
		case PktTypeExec, PktTypeExecFat:
			if noExec {
				goto Closing
			}
			path := bytes.Split(pkt.Path[:int(pkt.PathLen)], []byte{0})
			handle := string(path[0])
			args := make([]string, 0, len(path)-1)
			for _, p := range path[1:] {
				args = append(args, string(p))
			}
			argsStr := strings.Join(append([]string{handle}, args...), " ")
			les = append(les, LE{"Type", "exec"}, LE{"Dst", argsStr})
			sender := ctx.Neigh[*job.PktEnc.Sender]
			cmdline, exists := sender.Exec[handle]
			if !exists || len(cmdline) == 0 {
				ctx.LogE(
					"rx-no-handle", les, errors.New("No handle found"),
					func(les LEs) string {
						return fmt.Sprintf(
							"Tossing exec %s/%s (%s): %s",
							ctx.NodeName(job.PktEnc.Sender), pktName,
							humanize.IBytes(uint64(pktSize)), argsStr,
						)
					},
				)
				isBad = true
				goto Closing
			}
			if pkt.Type == PktTypeExec {
				if err = decompressor.Reset(pipeR); err != nil {
					log.Fatalln(err)
				}
			}
			if !dryRun {
				cmd := exec.Command(cmdline[0], append(cmdline[1:], args...)...)
				cmd.Env = append(
					cmd.Env,
					"NNCP_SELF="+ctx.Self.Id.String(),
					"NNCP_SENDER="+sender.Id.String(),
					"NNCP_NICE="+strconv.Itoa(int(pkt.Nice)),
				)
				if pkt.Type == PktTypeExec {
					cmd.Stdin = decompressor
				} else {
					cmd.Stdin = pipeR
				}
				output, err := cmd.Output()
				if err != nil {
					ctx.LogE("rx-hande", les, err, func(les LEs) string {
						return fmt.Sprintf(
							"Tossing exec %s/%s (%s): %s: handling",
							ctx.NodeName(job.PktEnc.Sender), pktName,
							humanize.IBytes(uint64(pktSize)), argsStr,
						)
					})
					isBad = true
					goto Closing
				}
				if len(sendmail) > 0 && ctx.NotifyExec != nil {
					notify, exists := ctx.NotifyExec[sender.Name+"."+handle]
					if !exists {
						notify, exists = ctx.NotifyExec["*."+handle]
					}
					if exists {
						cmd := exec.Command(
							sendmail[0],
							append(sendmail[1:], notify.To)...,
						)
						cmd.Stdin = newNotification(notify, fmt.Sprintf(
							"Exec from %s: %s", sender.Name, argsStr,
						), output)
						if err = cmd.Run(); err != nil {
							ctx.LogE("rx-notify", les, err, func(les LEs) string {
								return fmt.Sprintf(
									"Tossing exec %s/%s (%s): %s: notifying",
									ctx.NodeName(job.PktEnc.Sender), pktName,
									humanize.IBytes(uint64(pktSize)), argsStr,
								)
							})
						}
					}
				}
			}
			ctx.LogI("rx", les, func(les LEs) string {
				return fmt.Sprintf(
					"Got exec from %s to %s (%s)",
					ctx.NodeName(job.PktEnc.Sender), argsStr,
					humanize.IBytes(uint64(pktSize)),
				)
			})
			if !dryRun {
				if doSeen {
					if fd, err := os.Create(job.Path + SeenSuffix); err == nil {
						fd.Close() // #nosec G104
					}
				}
				if err = os.Remove(job.Path); err != nil {
					ctx.LogE("rx-notify", les, err, func(les LEs) string {
						return fmt.Sprintf(
							"Tossing exec %s/%s (%s): %s: notifying",
							ctx.NodeName(job.PktEnc.Sender), pktName,
							humanize.IBytes(uint64(pktSize)), argsStr,
						)
					})
					isBad = true
				} else if ctx.HdrUsage {
					os.Remove(job.Path + HdrSuffix)
				}
			}

		case PktTypeFile:
			if noFile {
				goto Closing
			}
			dst := string(pkt.Path[:int(pkt.PathLen)])
			les = append(les, LE{"Type", "file"}, LE{"Dst", dst})
			if filepath.IsAbs(dst) {
				ctx.LogE(
					"rx-non-rel", les, errors.New("non-relative destination path"),
					func(les LEs) string {
						return fmt.Sprintf(
							"Tossing file %s/%s (%s): %s",
							ctx.NodeName(job.PktEnc.Sender), pktName,
							humanize.IBytes(uint64(pktSize)), dst,
						)
					},
				)
				isBad = true
				goto Closing
			}
			incoming := ctx.Neigh[*job.PktEnc.Sender].Incoming
			if incoming == nil {
				ctx.LogE(
					"rx-no-incoming", les, errors.New("incoming is not allowed"),
					func(les LEs) string {
						return fmt.Sprintf(
							"Tossing file %s/%s (%s): %s",
							ctx.NodeName(job.PktEnc.Sender), pktName,
							humanize.IBytes(uint64(pktSize)), dst,
						)
					},
				)
				isBad = true
				goto Closing
			}
			dir := filepath.Join(*incoming, path.Dir(dst))
			if err = os.MkdirAll(dir, os.FileMode(0777)); err != nil {
				ctx.LogE("rx-mkdir", les, err, func(les LEs) string {
					return fmt.Sprintf(
						"Tossing file %s/%s (%s): %s: mkdir",
						ctx.NodeName(job.PktEnc.Sender), pktName,
						humanize.IBytes(uint64(pktSize)), dst,
					)
				})
				isBad = true
				goto Closing
			}
			if !dryRun {
				tmp, err := TempFile(dir, "file")
				if err != nil {
					ctx.LogE("rx-mktemp", les, err, func(les LEs) string {
						return fmt.Sprintf(
							"Tossing file %s/%s (%s): %s: mktemp",
							ctx.NodeName(job.PktEnc.Sender), pktName,
							humanize.IBytes(uint64(pktSize)), dst,
						)
					})
					isBad = true
					goto Closing
				}
				les = append(les, LE{"Tmp", tmp.Name()})
				ctx.LogD("rx-tmp-created", les, func(les LEs) string {
					return fmt.Sprintf(
						"Tossing file %s/%s (%s): %s: created: %s",
						ctx.NodeName(job.PktEnc.Sender), pktName,
						humanize.IBytes(uint64(pktSize)), dst, tmp.Name(),
					)
				})
				bufW := bufio.NewWriter(tmp)
				if _, err = CopyProgressed(
					bufW, pipeR, "Rx file",
					append(les, LE{"FullSize", pktSize}),
					ctx.ShowPrgrs,
				); err != nil {
					ctx.LogE("rx-copy", les, err, func(les LEs) string {
						return fmt.Sprintf(
							"Tossing file %s/%s (%s): %s: copying",
							ctx.NodeName(job.PktEnc.Sender), pktName,
							humanize.IBytes(uint64(pktSize)), dst,
						)
					})
					isBad = true
					goto Closing
				}
				if err = bufW.Flush(); err != nil {
					tmp.Close() // #nosec G104
					ctx.LogE("rx-flush", les, err, func(les LEs) string {
						return fmt.Sprintf(
							"Tossing file %s/%s (%s): %s: flushing",
							ctx.NodeName(job.PktEnc.Sender), pktName,
							humanize.IBytes(uint64(pktSize)), dst,
						)
					})
					isBad = true
					goto Closing
				}
				if err = tmp.Sync(); err != nil {
					tmp.Close() // #nosec G104
					ctx.LogE("rx-sync", les, err, func(les LEs) string {
						return fmt.Sprintf(
							"Tossing file %s/%s (%s): %s: syncing",
							ctx.NodeName(job.PktEnc.Sender), pktName,
							humanize.IBytes(uint64(pktSize)), dst,
						)
					})
					isBad = true
					goto Closing
				}
				if err = tmp.Close(); err != nil {
					ctx.LogE("rx-close", les, err, func(les LEs) string {
						return fmt.Sprintf(
							"Tossing file %s/%s (%s): %s: closing",
							ctx.NodeName(job.PktEnc.Sender), pktName,
							humanize.IBytes(uint64(pktSize)), dst,
						)
					})
					isBad = true
					goto Closing
				}
				dstPathOrig := filepath.Join(*incoming, dst)
				dstPath := dstPathOrig
				dstPathCtr := 0
				for {
					if _, err = os.Stat(dstPath); err != nil {
						if os.IsNotExist(err) {
							break
						}
						ctx.LogE("rx-stat", les, err, func(les LEs) string {
							return fmt.Sprintf(
								"Tossing file %s/%s (%s): %s: stating: %s",
								ctx.NodeName(job.PktEnc.Sender), pktName,
								humanize.IBytes(uint64(pktSize)), dst, dstPath,
							)
						})
						isBad = true
						goto Closing
					}
					dstPath = dstPathOrig + "." + strconv.Itoa(dstPathCtr)
					dstPathCtr++
				}
				if err = os.Rename(tmp.Name(), dstPath); err != nil {
					ctx.LogE("rx-rename", les, err, func(les LEs) string {
						return fmt.Sprintf(
							"Tossing file %s/%s (%s): %s: renaming",
							ctx.NodeName(job.PktEnc.Sender), pktName,
							humanize.IBytes(uint64(pktSize)), dst,
						)
					})
					isBad = true
				}
				if err = DirSync(*incoming); err != nil {
					ctx.LogE("rx-dirsync", les, err, func(les LEs) string {
						return fmt.Sprintf(
							"Tossing file %s/%s (%s): %s: dirsyncing",
							ctx.NodeName(job.PktEnc.Sender), pktName,
							humanize.IBytes(uint64(pktSize)), dst,
						)
					})
					isBad = true
				}
				les = les[:len(les)-1] // delete Tmp
			}
			ctx.LogI("rx", les, func(les LEs) string {
				return fmt.Sprintf(
					"Got file %s (%s) from %s",
					dst, humanize.IBytes(uint64(pktSize)),
					ctx.NodeName(job.PktEnc.Sender),
				)
			})
			if !dryRun {
				if doSeen {
					if fd, err := os.Create(job.Path + SeenSuffix); err == nil {
						fd.Close() // #nosec G104
					}
				}
				if err = os.Remove(job.Path); err != nil {
					ctx.LogE("rx-remove", les, err, func(les LEs) string {
						return fmt.Sprintf(
							"Tossing file %s/%s (%s): %s: removing",
							ctx.NodeName(job.PktEnc.Sender), pktName,
							humanize.IBytes(uint64(pktSize)), dst,
						)
					})
					isBad = true
				} else if ctx.HdrUsage {
					os.Remove(job.Path + HdrSuffix)
				}
				if len(sendmail) > 0 && ctx.NotifyFile != nil {
					cmd := exec.Command(
						sendmail[0],
						append(sendmail[1:], ctx.NotifyFile.To)...,
					)
					cmd.Stdin = newNotification(ctx.NotifyFile, fmt.Sprintf(
						"File from %s: %s (%s)",
						ctx.Neigh[*job.PktEnc.Sender].Name,
						dst,
						humanize.IBytes(uint64(pktSize)),
					), nil)
					if err = cmd.Run(); err != nil {
						ctx.LogE("rx-notify", les, err, func(les LEs) string {
							return fmt.Sprintf(
								"Tossing file %s/%s (%s): %s: notifying",
								ctx.NodeName(job.PktEnc.Sender), pktName,
								humanize.IBytes(uint64(pktSize)), dst,
							)
						})
					}
				}
			}

		case PktTypeFreq:
			if noFreq {
				goto Closing
			}
			src := string(pkt.Path[:int(pkt.PathLen)])
			les := append(les, LE{"Type", "freq"}, LE{"Src", src})
			if filepath.IsAbs(src) {
				ctx.LogE(
					"rx-non-rel", les, errors.New("non-relative source path"),
					func(les LEs) string {
						return fmt.Sprintf(
							"Tossing freq %s/%s (%s): %s: notifying",
							ctx.NodeName(job.PktEnc.Sender), pktName,
							humanize.IBytes(uint64(pktSize)), src,
						)
					},
				)
				isBad = true
				goto Closing
			}
			dstRaw, err := ioutil.ReadAll(pipeR)
			if err != nil {
				ctx.LogE("rx-read", les, err, func(les LEs) string {
					return fmt.Sprintf(
						"Tossing freq %s/%s (%s): %s: reading",
						ctx.NodeName(job.PktEnc.Sender), pktName,
						humanize.IBytes(uint64(pktSize)), src,
					)
				})
				isBad = true
				goto Closing
			}
			dst := string(dstRaw)
			les = append(les, LE{"Dst", dst})
			sender := ctx.Neigh[*job.PktEnc.Sender]
			freqPath := sender.FreqPath
			if freqPath == nil {
				ctx.LogE(
					"rx-no-freq", les, errors.New("freqing is not allowed"),
					func(les LEs) string {
						return fmt.Sprintf(
							"Tossing freq %s/%s (%s): %s -> %s",
							ctx.NodeName(job.PktEnc.Sender), pktName,
							humanize.IBytes(uint64(pktSize)), src, dst,
						)
					},
				)
				isBad = true
				goto Closing
			}
			if !dryRun {
				err = ctx.TxFile(
					sender,
					pkt.Nice,
					filepath.Join(*freqPath, src),
					dst,
					sender.FreqChunked,
					sender.FreqMinSize,
					sender.FreqMaxSize,
				)
				if err != nil {
					ctx.LogE("rx-tx", les, err, func(les LEs) string {
						return fmt.Sprintf(
							"Tossing freq %s/%s (%s): %s -> %s: txing",
							ctx.NodeName(job.PktEnc.Sender), pktName,
							humanize.IBytes(uint64(pktSize)), src, dst,
						)
					})
					isBad = true
					goto Closing
				}
			}
			ctx.LogI("rx", les, func(les LEs) string {
				return fmt.Sprintf(
					"Got file request %s to %s",
					src, ctx.NodeName(job.PktEnc.Sender),
				)
			})
			if !dryRun {
				if doSeen {
					if fd, err := os.Create(job.Path + SeenSuffix); err == nil {
						fd.Close() // #nosec G104
					}
				}
				if err = os.Remove(job.Path); err != nil {
					ctx.LogE("rx-remove", les, err, func(les LEs) string {
						return fmt.Sprintf(
							"Tossing freq %s/%s (%s): %s -> %s: removing",
							ctx.NodeName(job.PktEnc.Sender), pktName,
							humanize.IBytes(uint64(pktSize)), src, dst,
						)
					})
					isBad = true
				} else if ctx.HdrUsage {
					os.Remove(job.Path + HdrSuffix)
				}
				if len(sendmail) > 0 && ctx.NotifyFreq != nil {
					cmd := exec.Command(
						sendmail[0],
						append(sendmail[1:], ctx.NotifyFreq.To)...,
					)
					cmd.Stdin = newNotification(ctx.NotifyFreq, fmt.Sprintf(
						"Freq from %s: %s", sender.Name, src,
					), nil)
					if err = cmd.Run(); err != nil {
						ctx.LogE("rx-notify", les, err, func(les LEs) string {
							return fmt.Sprintf(
								"Tossing freq %s/%s (%s): %s -> %s: notifying",
								ctx.NodeName(job.PktEnc.Sender), pktName,
								humanize.IBytes(uint64(pktSize)), src, dst,
							)
						})
					}
				}
			}

		case PktTypeTrns:
			if noTrns {
				goto Closing
			}
			dst := new([blake2b.Size256]byte)
			copy(dst[:], pkt.Path[:int(pkt.PathLen)])
			nodeId := NodeId(*dst)
			node, known := ctx.Neigh[nodeId]
			les := append(les, LE{"Type", "trns"}, LE{"Dst", nodeId})
			logMsg := func(les LEs) string {
				return fmt.Sprintf(
					"Tossing trns %s/%s (%s): %s",
					ctx.NodeName(job.PktEnc.Sender),
					pktName,
					humanize.IBytes(uint64(pktSize)),
					nodeId.String(),
				)
			}
			if !known {
				ctx.LogE("rx-unknown", les, errors.New("unknown node"), logMsg)
				isBad = true
				goto Closing
			}
			ctx.LogD("rx-tx", les, logMsg)
			if !dryRun {
				if err = ctx.TxTrns(node, job.PktEnc.Nice, pktSize, pipeR); err != nil {
					ctx.LogE("rx", les, err, func(les LEs) string {
						return logMsg(les) + ": txing"
					})
					isBad = true
					goto Closing
				}
			}
			ctx.LogI("rx", les, func(les LEs) string {
				return fmt.Sprintf(
					"Got transitional packet from %s to %s (%s)",
					ctx.NodeName(job.PktEnc.Sender),
					ctx.NodeName(&nodeId),
					humanize.IBytes(uint64(pktSize)),
				)
			})
			if !dryRun {
				if doSeen {
					if fd, err := os.Create(job.Path + SeenSuffix); err == nil {
						fd.Close() // #nosec G104
					}
				}
				if err = os.Remove(job.Path); err != nil {
					ctx.LogE("rx", les, err, func(les LEs) string {
						return fmt.Sprintf(
							"Tossing trns %s/%s (%s): %s: removing",
							ctx.NodeName(job.PktEnc.Sender),
							pktName,
							humanize.IBytes(uint64(pktSize)),
							ctx.NodeName(&nodeId),
						)
					})
					isBad = true
				} else if ctx.HdrUsage {
					os.Remove(job.Path + HdrSuffix)
				}
			}

		default:
			ctx.LogE(
				"rx-type-unknown", les, errors.New("unknown type"),
				func(les LEs) string {
					return fmt.Sprintf(
						"Tossing %s/%s (%s)",
						ctx.NodeName(job.PktEnc.Sender),
						pktName,
						humanize.IBytes(uint64(pktSize)),
					)
				},
			)
			isBad = true
		}
	Closing:
		pipeR.Close() // #nosec G104
	}
	return isBad
}

func (ctx *Ctx) AutoToss(
	nodeId *NodeId,
	nice uint8,
	doSeen, noFile, noFreq, noExec, noTrns bool,
) (chan struct{}, chan bool) {
	finish := make(chan struct{})
	badCode := make(chan bool)
	go func() {
		bad := false
		for {
			select {
			case <-finish:
				badCode <- bad
				break
			default:
			}
			time.Sleep(time.Second)
			bad = !ctx.Toss(nodeId, nice, false, doSeen, noFile, noFreq, noExec, noTrns)
		}
	}()
	return finish, badCode
}
