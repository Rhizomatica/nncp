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

package nncp

import (
	"bytes"
	"crypto/subtle"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/davecgh/go-xdr/xdr2"
	"github.com/flynn/noise"
)

const (
	MaxSPSize        = 2<<15 - 256
	PartSuffix       = ".part"
	DeadlineDuration = 10
)

var (
	MagicNNCPLv1 [8]byte = [8]byte{'N', 'N', 'C', 'P', 'L', 1, 0, 0}

	SPHeadOverhead    int
	SPInfoOverhead    int
	SPFreqOverhead    int
	SPFileOverhead    int
	SPHaltMarshalized []byte

	NoiseCipherSuite noise.CipherSuite = noise.NewCipherSuite(
		noise.DH25519,
		noise.CipherChaChaPoly,
		noise.HashBLAKE2b,
	)
)

type SPType uint8

const (
	SPTypeInfo SPType = iota
	SPTypeFreq SPType = iota
	SPTypeFile SPType = iota
	SPTypeDone SPType = iota
	SPTypeHalt SPType = iota
)

type SPHead struct {
	Type SPType
}

type SPInfo struct {
	Nice uint8
	Size uint64
	Hash *[32]byte
}

type SPFreq struct {
	Hash   *[32]byte
	Offset uint64
}

type SPFile struct {
	Hash    *[32]byte
	Offset  uint64
	Payload []byte
}

type SPDone struct {
	Hash *[32]byte
}

type SPRaw struct {
	Magic   [8]byte
	Payload []byte
}

func init() {
	var buf bytes.Buffer
	spHead := SPHead{Type: SPTypeHalt}
	if _, err := xdr.Marshal(&buf, spHead); err != nil {
		panic(err)
	}
	copy(SPHaltMarshalized, buf.Bytes())
	SPHeadOverhead = buf.Len()
	buf.Reset()

	spInfo := SPInfo{Nice: 123, Size: 123, Hash: new([32]byte)}
	if _, err := xdr.Marshal(&buf, spInfo); err != nil {
		panic(err)
	}
	SPInfoOverhead = buf.Len()
	buf.Reset()

	spFreq := SPFreq{Hash: new([32]byte), Offset: 123}
	if _, err := xdr.Marshal(&buf, spFreq); err != nil {
		panic(err)
	}
	SPFreqOverhead = buf.Len()
	buf.Reset()

	spFile := SPFile{Hash: new([32]byte), Offset: 123}
	if _, err := xdr.Marshal(&buf, spFile); err != nil {
		panic(err)
	}
	SPFileOverhead = buf.Len()
}

func MarshalSP(typ SPType, sp interface{}) []byte {
	var buf bytes.Buffer
	var err error
	if _, err = xdr.Marshal(&buf, SPHead{typ}); err != nil {
		panic(err)
	}
	if _, err = xdr.Marshal(&buf, sp); err != nil {
		panic(err)
	}
	return buf.Bytes()
}

func payloadsSplit(payloads [][]byte) [][]byte {
	var outbounds [][]byte
	outbound := make([]byte, 0, MaxSPSize)
	for i, payload := range payloads {
		outbound = append(outbound, payload...)
		if i+1 < len(payloads) && len(outbound)+len(payloads[i+1]) > MaxSPSize {
			outbounds = append(outbounds, outbound)
			outbound = make([]byte, 0, MaxSPSize)
		}
	}
	if len(outbound) > 0 {
		outbounds = append(outbounds, outbound)
	}
	return outbounds
}

type SPState struct {
	ctx        *Ctx
	NodeId     *NodeId
	nice       uint8
	hs         *noise.HandshakeState
	csOur      *noise.CipherState
	csTheir    *noise.CipherState
	payloads   chan []byte
	infosTheir map[[32]byte]*SPInfo
	queueTheir []*SPFreq
	wg         sync.WaitGroup
	RxBytes    int64
	RxLastSeen time.Time
	TxBytes    int64
	TxLastSeen time.Time
	started    time.Time
	Duration   time.Duration
	RxSpeed    int64
	TxSpeed    int64
	rxLock     *os.File
	txLock     *os.File
	xxOnly     *TRxTx
	sync.RWMutex
}

func (state *SPState) isDead() bool {
	now := time.Now()
	return now.Sub(state.RxLastSeen).Seconds() >= DeadlineDuration && now.Sub(state.TxLastSeen).Seconds() >= DeadlineDuration
}

func (state *SPState) dirUnlock() {
	state.ctx.UnlockDir(state.rxLock)
	state.ctx.UnlockDir(state.txLock)
}

func (state *SPState) WriteSP(dst io.Writer, payload []byte) error {
	n, err := xdr.Marshal(dst, SPRaw{Magic: MagicNNCPLv1, Payload: payload})
	if err == nil {
		state.TxLastSeen = time.Now()
		state.TxBytes += int64(n)
	}
	return err
}

func (state *SPState) ReadSP(src io.Reader) ([]byte, error) {
	var sp SPRaw
	n, err := xdr.Unmarshal(src, &sp)
	if err != nil {
		return nil, err
	}
	state.RxLastSeen = time.Now()
	state.RxBytes += int64(n)
	if sp.Magic != MagicNNCPLv1 {
		return nil, BadMagic
	}
	return sp.Payload, nil
}

func (ctx *Ctx) infosOur(nodeId *NodeId, nice uint8) [][]byte {
	var infos []*SPInfo
	var totalSize int64
	for job := range ctx.Jobs(nodeId, TTx) {
		job.Fd.Close()
		if job.PktEnc.Nice > nice {
			continue
		}
		totalSize += job.Size
		infos = append(infos, &SPInfo{
			Nice: job.PktEnc.Nice,
			Size: uint64(job.Size),
			Hash: job.HshValue,
		})
	}
	sort.Sort(ByNice(infos))
	var payloads [][]byte
	for _, info := range infos {
		payloads = append(payloads, MarshalSP(SPTypeInfo, info))
		ctx.LogD("sp-info-our", SDS{
			"node": nodeId,
			"name": ToBase32(info.Hash[:]),
			"size": strconv.FormatInt(int64(info.Size), 10),
		}, "")
	}
	ctx.LogI("sp-infos", SDS{
		"xx":   string(TTx),
		"node": nodeId,
		"pkts": strconv.Itoa(len(payloads)),
		"size": strconv.FormatInt(totalSize, 10),
	}, "")
	return payloadsSplit(payloads)
}

func (ctx *Ctx) StartI(conn net.Conn, nodeId *NodeId, nice uint8, xxOnly *TRxTx) (*SPState, error) {
	err := ctx.ensureRxDir(nodeId)
	if err != nil {
		return nil, err
	}
	var rxLock *os.File
	if xxOnly != nil && *xxOnly == TRx {
		rxLock, err = ctx.LockDir(nodeId, TRx)
		if err != nil {
			return nil, err
		}
	}
	var txLock *os.File
	if xxOnly != nil && *xxOnly == TTx {
		txLock, err = ctx.LockDir(nodeId, TTx)
		if err != nil {
			return nil, err
		}
	}
	started := time.Now()
	conf := noise.Config{
		CipherSuite: NoiseCipherSuite,
		Pattern:     noise.HandshakeIK,
		Initiator:   true,
		StaticKeypair: noise.DHKey{
			Private: ctx.Self.NoisePrv[:],
			Public:  ctx.Self.NoisePub[:],
		},
		PeerStatic: ctx.Neigh[*nodeId].NoisePub[:],
	}
	state := SPState{
		ctx:        ctx,
		hs:         noise.NewHandshakeState(conf),
		NodeId:     nodeId,
		nice:       nice,
		payloads:   make(chan []byte),
		infosTheir: make(map[[32]byte]*SPInfo),
		started:    started,
		rxLock:     rxLock,
		txLock:     txLock,
		xxOnly:     xxOnly,
	}

	var infosPayloads [][]byte
	if xxOnly == nil || *xxOnly != TTx {
		infosPayloads = ctx.infosOur(nodeId, nice)
	}
	var firstPayload []byte
	if len(infosPayloads) > 0 {
		firstPayload = infosPayloads[0]
	}
	// Pad first payload, to hide actual existing files
	for i := 0; i < (MaxSPSize-len(firstPayload))/SPHeadOverhead; i++ {
		firstPayload = append(firstPayload, SPHaltMarshalized...)
	}

	var buf []byte
	var payload []byte
	buf, _, _ = state.hs.WriteMessage(nil, firstPayload)
	sds := SDS{"node": nodeId, "nice": strconv.Itoa(int(nice))}
	ctx.LogD("sp-start", sds, "sending first message")
	conn.SetWriteDeadline(time.Now().Add(DeadlineDuration * time.Second))
	if err = state.WriteSP(conn, buf); err != nil {
		ctx.LogE("sp-start", SdsAdd(sds, SDS{"err": err}), "")
		state.dirUnlock()
		return nil, err
	}
	ctx.LogD("sp-start", sds, "waiting for first message")
	conn.SetReadDeadline(time.Now().Add(DeadlineDuration * time.Second))
	if buf, err = state.ReadSP(conn); err != nil {
		ctx.LogE("sp-start", SdsAdd(sds, SDS{"err": err}), "")
		state.dirUnlock()
		return nil, err
	}
	payload, state.csOur, state.csTheir, err = state.hs.ReadMessage(nil, buf)
	if err != nil {
		ctx.LogE("sp-start", SdsAdd(sds, SDS{"err": err}), "")
		state.dirUnlock()
		return nil, err
	}
	ctx.LogD("sp-start", sds, "starting workers")
	err = state.StartWorkers(conn, infosPayloads, payload)
	if err != nil {
		ctx.LogE("sp-start", SdsAdd(sds, SDS{"err": err}), "")
		state.dirUnlock()
		return nil, err
	}
	return &state, err
}

func (ctx *Ctx) StartR(conn net.Conn, nice uint8, xxOnly *TRxTx) (*SPState, error) {
	started := time.Now()
	conf := noise.Config{
		CipherSuite: NoiseCipherSuite,
		Pattern:     noise.HandshakeIK,
		Initiator:   false,
		StaticKeypair: noise.DHKey{
			Private: ctx.Self.NoisePrv[:],
			Public:  ctx.Self.NoisePub[:],
		},
	}
	state := SPState{
		ctx:        ctx,
		hs:         noise.NewHandshakeState(conf),
		nice:       nice,
		payloads:   make(chan []byte),
		infosTheir: make(map[[32]byte]*SPInfo),
		started:    started,
		xxOnly:     xxOnly,
	}
	var buf []byte
	var payload []byte
	var err error
	ctx.LogD(
		"sp-start",
		SDS{"nice": strconv.Itoa(int(nice))},
		"waiting for first message",
	)
	conn.SetReadDeadline(time.Now().Add(DeadlineDuration * time.Second))
	if buf, err = state.ReadSP(conn); err != nil {
		ctx.LogE("sp-start", SDS{"err": err}, "")
		return nil, err
	}
	if payload, _, _, err = state.hs.ReadMessage(nil, buf); err != nil {
		ctx.LogE("sp-start", SDS{"err": err}, "")
		return nil, err
	}

	var nodeId *NodeId
	for _, node := range ctx.Neigh {
		if subtle.ConstantTimeCompare(state.hs.PeerStatic(), node.NoisePub[:]) == 1 {
			nodeId = node.Id
			break
		}
	}
	if nodeId == nil {
		peerId := ToBase32(state.hs.PeerStatic())
		ctx.LogE("sp-start", SDS{"peer": peerId}, "unknown")
		return nil, errors.New("Unknown peer: " + peerId)
	}
	state.NodeId = nodeId
	sds := SDS{"node": nodeId, "nice": strconv.Itoa(int(nice))}

	if ctx.ensureRxDir(nodeId); err != nil {
		return nil, err
	}
	var rxLock *os.File
	if xxOnly != nil && *xxOnly == TRx {
		rxLock, err = ctx.LockDir(nodeId, TRx)
		if err != nil {
			return nil, err
		}
	}
	state.rxLock = rxLock
	var txLock *os.File
	if xxOnly != nil && *xxOnly == TTx {
		txLock, err = ctx.LockDir(nodeId, TTx)
		if err != nil {
			return nil, err
		}
	}
	state.txLock = txLock

	var infosPayloads [][]byte
	if xxOnly == nil || *xxOnly != TTx {
		infosPayloads = ctx.infosOur(nodeId, nice)
	}
	var firstPayload []byte
	if len(infosPayloads) > 0 {
		firstPayload = infosPayloads[0]
	}
	// Pad first payload, to hide actual existing files
	for i := 0; i < (MaxSPSize-len(firstPayload))/SPHeadOverhead; i++ {
		firstPayload = append(firstPayload, SPHaltMarshalized...)
	}

	ctx.LogD("sp-start", sds, "sending first message")
	buf, state.csTheir, state.csOur = state.hs.WriteMessage(nil, firstPayload)
	conn.SetWriteDeadline(time.Now().Add(DeadlineDuration * time.Second))
	if err = state.WriteSP(conn, buf); err != nil {
		ctx.LogE("sp-start", SdsAdd(sds, SDS{"err": err}), "")
		state.dirUnlock()
		return nil, err
	}
	ctx.LogD("sp-start", sds, "starting workers")
	err = state.StartWorkers(conn, infosPayloads, payload)
	if err != nil {
		state.dirUnlock()
		return nil, err
	}
	return &state, err
}

func (state *SPState) StartWorkers(conn net.Conn, infosPayloads [][]byte, payload []byte) error {
	sds := SDS{"node": state.NodeId, "nice": strconv.Itoa(int(state.nice))}
	if len(infosPayloads) > 1 {
		go func() {
			for _, payload := range infosPayloads[1:] {
				state.ctx.LogD(
					"sp-work",
					SdsAdd(sds, SDS{"size": strconv.Itoa(len(payload))}),
					"queuing remaining payload",
				)
				state.payloads <- payload
			}
		}()
	}
	state.ctx.LogD(
		"sp-work",
		SdsAdd(sds, SDS{"size": strconv.Itoa(len(payload))}),
		"processing first payload",
	)
	replies, err := state.ProcessSP(payload)
	if err != nil {
		state.ctx.LogE("sp-work", SdsAdd(sds, SDS{"err": err}), "")
		return err
	}
	go func() {
		for _, reply := range replies {
			state.ctx.LogD(
				"sp-work",
				SdsAdd(sds, SDS{"size": strconv.Itoa(len(reply))}),
				"queuing reply",
			)
			state.payloads <- reply
		}
	}()
	state.wg.Add(1)
	go func() {
		defer state.wg.Done()
		for {
			if state.isDead() {
				return
			}
			var payload []byte
			select {
			case payload = <-state.payloads:
				state.ctx.LogD(
					"sp-xmit",
					SdsAdd(sds, SDS{"size": strconv.Itoa(len(payload))}),
					"got payload",
				)
			default:
			}
			if payload == nil {
				state.RLock()
				if len(state.queueTheir) == 0 {
					state.ctx.LogD("sp-xmit", sds, "file queue is empty")
					state.RUnlock()
					time.Sleep(100 * time.Millisecond)
					continue
				}
				freq := state.queueTheir[0]
				state.RUnlock()
				sdsp := SdsAdd(sds, SDS{
					"xx":   string(TTx),
					"hash": ToBase32(freq.Hash[:]),
					"size": strconv.FormatInt(int64(freq.Offset), 10),
				})
				state.ctx.LogD("sp-file", sdsp, "queueing")
				fd, err := os.Open(filepath.Join(
					state.ctx.Spool,
					state.NodeId.String(),
					string(TTx),
					ToBase32(freq.Hash[:]),
				))
				if err != nil {
					state.ctx.LogE("sp-file", SdsAdd(sdsp, SDS{"err": err}), "")
					break
				}
				fi, err := fd.Stat()
				if err != nil {
					state.ctx.LogE("sp-file", SdsAdd(sdsp, SDS{"err": err}), "")
					break
				}
				fullSize := uint64(fi.Size())
				var buf []byte
				if freq.Offset < fullSize {
					state.ctx.LogD("sp-file", sdsp, "seeking")
					if _, err = fd.Seek(int64(freq.Offset), 0); err != nil {
						state.ctx.LogE("sp-file", SdsAdd(sdsp, SDS{"err": err}), "")
						break
					}
					buf = make([]byte, MaxSPSize-SPHeadOverhead-SPFileOverhead)
					n, err := fd.Read(buf)
					if err != nil {
						state.ctx.LogE("sp-file", SdsAdd(sdsp, SDS{"err": err}), "")
						break
					}
					buf = buf[:n]
					state.ctx.LogD(
						"sp-file",
						SdsAdd(sdsp, SDS{"size": strconv.Itoa(n)}),
						"read",
					)
				}
				fd.Close()
				payload = MarshalSP(SPTypeFile, SPFile{
					Hash:    freq.Hash,
					Offset:  freq.Offset,
					Payload: buf,
				})
				ourSize := freq.Offset + uint64(len(buf))
				sdsp["size"] = strconv.FormatInt(int64(ourSize), 10)
				sdsp["fullsize"] = strconv.FormatInt(int64(fullSize), 10)
				state.ctx.LogP("sp-file", sdsp, "")
				state.Lock()
				if len(state.queueTheir) > 0 && *state.queueTheir[0].Hash == *freq.Hash {
					if ourSize == fullSize {
						state.ctx.LogD("sp-file", sdsp, "finished")
						if len(state.queueTheir) > 1 {
							state.queueTheir = state.queueTheir[1:]
						} else {
							state.queueTheir = state.queueTheir[:0]
						}
					} else {
						state.queueTheir[0].Offset += uint64(len(buf))
					}
				} else {
					state.ctx.LogD("sp-file", sdsp, "queue disappeared")
				}
				state.Unlock()
			}
			state.ctx.LogD(
				"sp-xmit",
				SdsAdd(sds, SDS{"size": strconv.Itoa(len(payload))}),
				"sending",
			)
			conn.SetWriteDeadline(time.Now().Add(DeadlineDuration * time.Second))
			if err := state.WriteSP(conn, state.csOur.Encrypt(nil, nil, payload)); err != nil {
				state.ctx.LogE("sp-xmit", SdsAdd(sds, SDS{"err": err}), "")
				break
			}
		}
	}()
	state.wg.Add(1)
	go func() {
		defer state.wg.Done()
		for {
			if state.isDead() {
				return
			}
			state.ctx.LogD("sp-recv", sds, "waiting for payload")
			conn.SetReadDeadline(time.Now().Add(DeadlineDuration * time.Second))
			payload, err := state.ReadSP(conn)
			if err != nil {
				unmarshalErr := err.(*xdr.UnmarshalError)
				netErr, ok := unmarshalErr.Err.(net.Error)
				if (ok && netErr.Timeout()) || unmarshalErr.ErrorCode == xdr.ErrIO {
					continue
				} else {
					state.ctx.LogE("sp-recv", SdsAdd(sds, SDS{"err": err}), "")
					break
				}
			}
			state.ctx.LogD(
				"sp-recv",
				SdsAdd(sds, SDS{"size": strconv.Itoa(len(payload))}),
				"got payload",
			)
			payload, err = state.csTheir.Decrypt(nil, nil, payload)
			if err != nil {
				state.ctx.LogE("sp-recv", SdsAdd(sds, SDS{"err": err}), "")
				break
			}
			state.ctx.LogD(
				"sp-recv",
				SdsAdd(sds, SDS{"size": strconv.Itoa(len(payload))}),
				"processing",
			)
			replies, err := state.ProcessSP(payload)
			if err != nil {
				state.ctx.LogE("sp-recv", SdsAdd(sds, SDS{"err": err}), "")
				break
			}
			go func() {
				for _, reply := range replies {
					state.ctx.LogD(
						"sp-recv",
						SdsAdd(sds, SDS{"size": strconv.Itoa(len(reply))}),
						"queuing reply",
					)
					state.payloads <- reply
				}
			}()
		}
	}()
	return nil
}

func (state *SPState) Wait() {
	state.wg.Wait()
	state.dirUnlock()
	state.Duration = time.Now().Sub(state.started)
	state.RxSpeed = state.RxBytes
	state.TxSpeed = state.TxBytes
	rxDuration := int64(state.RxLastSeen.Sub(state.started).Seconds())
	txDuration := int64(state.TxLastSeen.Sub(state.started).Seconds())
	if rxDuration > 0 {
		state.RxSpeed = state.RxBytes / rxDuration
	}
	if txDuration > 0 {
		state.TxSpeed = state.TxBytes / txDuration
	}
}

func (state *SPState) ProcessSP(payload []byte) ([][]byte, error) {
	sds := SDS{"node": state.NodeId, "nice": strconv.Itoa(int(state.nice))}
	r := bytes.NewReader(payload)
	var err error
	var replies [][]byte
	var infosGot bool
	for r.Len() > 0 {
		state.ctx.LogD("sp-process", sds, "unmarshaling header")
		var head SPHead
		if _, err = xdr.Unmarshal(r, &head); err != nil {
			state.ctx.LogE("sp-process", SdsAdd(sds, SDS{"err": err}), "")
			return nil, err
		}
		switch head.Type {
		case SPTypeInfo:
			infosGot = true
			sdsp := SdsAdd(sds, SDS{"type": "info"})
			state.ctx.LogD("sp-process", sdsp, "unmarshaling packet")
			var info SPInfo
			if _, err = xdr.Unmarshal(r, &info); err != nil {
				state.ctx.LogE("sp-process", SdsAdd(sdsp, SDS{"err": err}), "")
				return nil, err
			}
			sdsp = SdsAdd(sds, SDS{
				"hash": ToBase32(info.Hash[:]),
				"size": strconv.FormatInt(int64(info.Size), 10),
			})
			if info.Nice > state.nice {
				state.ctx.LogD("sp-process", sdsp, "too nice")
				continue
			}
			state.ctx.LogD("sp-process", sdsp, "received")
			if state.xxOnly != nil && *state.xxOnly == TTx {
				continue
			}
			state.Lock()
			state.infosTheir[*info.Hash] = &info
			state.Unlock()
			state.ctx.LogD("sp-process", sdsp, "stating part")
			if _, err = os.Stat(filepath.Join(
				state.ctx.Spool,
				state.NodeId.String(),
				string(TRx),
				ToBase32(info.Hash[:]),
			)); err == nil {
				state.ctx.LogD("sp-process", sdsp, "already done")
				replies = append(replies, MarshalSP(SPTypeDone, SPDone{info.Hash}))
				continue
			}
			fi, err := os.Stat(filepath.Join(
				state.ctx.Spool,
				state.NodeId.String(),
				string(TRx),
				ToBase32(info.Hash[:])+PartSuffix,
			))
			var offset int64
			if err == nil {
				offset = fi.Size()
				state.ctx.LogD(
					"sp-process",
					SdsAdd(sdsp, SDS{"offset": strconv.FormatInt(offset, 10)}),
					"part exists",
				)
			}
			replies = append(replies, MarshalSP(
				SPTypeFreq,
				SPFreq{info.Hash, uint64(offset)},
			))
		case SPTypeFile:
			state.ctx.LogD(
				"sp-process",
				SdsAdd(sds, SDS{"type": "file"}),
				"unmarshaling packet",
			)
			var file SPFile
			if _, err = xdr.Unmarshal(r, &file); err != nil {
				state.ctx.LogE("sp-process", SdsAdd(sds, SDS{
					"err":  err,
					"type": "file",
				}), "")
				return nil, err
			}
			sdsp := SdsAdd(sds, SDS{
				"xx":   string(TRx),
				"hash": ToBase32(file.Hash[:]),
				"size": strconv.Itoa(len(file.Payload)),
			})
			filePath := filepath.Join(
				state.ctx.Spool,
				state.NodeId.String(),
				string(TRx),
				ToBase32(file.Hash[:]),
			)
			state.ctx.LogD("sp-file", sdsp, "opening part")
			fd, err := os.OpenFile(
				filePath+PartSuffix,
				os.O_RDWR|os.O_CREATE,
				os.FileMode(0600),
			)
			if err != nil {
				state.ctx.LogE("sp-file", SdsAdd(sdsp, SDS{"err": err}), "")
				return nil, err
			}
			state.ctx.LogD(
				"sp-file",
				SdsAdd(sdsp, SDS{"offset": strconv.FormatInt(int64(file.Offset), 10)}),
				"seeking",
			)
			if _, err = fd.Seek(int64(file.Offset), 0); err != nil {
				state.ctx.LogE("sp-file", SdsAdd(sdsp, SDS{"err": err}), "")
				fd.Close()
				return nil, err
			}
			state.ctx.LogD("sp-file", sdsp, "writing")
			_, err = fd.Write(file.Payload)
			if err != nil {
				state.ctx.LogE("sp-file", SdsAdd(sdsp, SDS{"err": err}), "")
				fd.Close()
				return nil, err
			}
			ourSize := uint64(file.Offset) + uint64(len(file.Payload))
			sdsp["fullsize"] = strconv.FormatInt(int64(state.infosTheir[*file.Hash].Size), 10)
			sdsp["size"] = strconv.FormatInt(int64(ourSize), 10)
			state.ctx.LogP("sp-file", sdsp, "")
			if state.infosTheir[*file.Hash].Size != ourSize {
				fd.Close()
				continue
			}
			go func() {
				if err := fd.Sync(); err != nil {
					state.ctx.LogE("sp-file", SdsAdd(sdsp, SDS{"err": err}), "sync")
					fd.Close()
					return
				}
				state.wg.Add(1)
				defer state.wg.Done()
				fd.Seek(0, 0)
				state.ctx.LogD("sp-file", sdsp, "checking")
				gut, err := Check(fd, file.Hash[:])
				fd.Close()
				if err != nil || !gut {
					state.ctx.LogE("sp-file", sdsp, "checksum mismatch")
					return
				}
				state.ctx.LogI("sp-done", SdsAdd(sdsp, SDS{"xx": string(TRx)}), "")
				os.Rename(filePath+PartSuffix, filePath)
				state.payloads <- MarshalSP(SPTypeDone, SPDone{file.Hash})
			}()
		case SPTypeDone:
			state.ctx.LogD(
				"sp-process",
				SdsAdd(sds, SDS{"type": "done"}),
				"unmarshaling packet",
			)
			var done SPDone
			if _, err = xdr.Unmarshal(r, &done); err != nil {
				state.ctx.LogE("sp-process", SdsAdd(sds, SDS{
					"type": "done",
					"err":  err,
				}), "")
				return nil, err
			}
			sdsp := SdsAdd(sds, SDS{"hash": ToBase32(done.Hash[:])})
			state.ctx.LogD("sp-done", sdsp, "removing")
			err := os.Remove(filepath.Join(
				state.ctx.Spool,
				state.NodeId.String(),
				string(TTx),
				ToBase32(done.Hash[:]),
			))
			if err == nil {
				state.ctx.LogI("sp-done", SdsAdd(sdsp, SDS{"xx": string(TTx)}), "")
			} else {
				state.ctx.LogE("sp-done", SdsAdd(sdsp, SDS{"xx": string(TTx)}), "")
			}
		case SPTypeFreq:
			sdsp := SdsAdd(sds, SDS{"type": "freq"})
			state.ctx.LogD("sp-process", sdsp, "unmarshaling packet")
			var freq SPFreq
			if _, err = xdr.Unmarshal(r, &freq); err != nil {
				state.ctx.LogE("sp-process", SdsAdd(sdsp, SDS{"err": err}), "")
				return nil, err
			}
			state.ctx.LogD("sp-process", SdsAdd(sdsp, SDS{
				"hash":   ToBase32(freq.Hash[:]),
				"offset": strconv.FormatInt(int64(freq.Offset), 10),
			}), "queueing")
			state.Lock()
			state.queueTheir = append(state.queueTheir, &freq)
			state.Unlock()
		case SPTypeHalt:
			sdsp := SdsAdd(sds, SDS{"type": "halt"})
			state.ctx.LogD("sp-process", sdsp, "")
			state.Lock()
			state.queueTheir = nil
			state.Unlock()
		default:
			state.ctx.LogE(
				"sp-process",
				SdsAdd(sds, SDS{"type": head.Type}),
				"unknown",
			)
			return nil, BadPktType
		}
	}
	if infosGot {
		var pkts int
		var size uint64
		for _, info := range state.infosTheir {
			pkts++
			size += info.Size
		}
		state.ctx.LogI("sp-infos", SDS{
			"xx":   string(TRx),
			"node": state.NodeId,
			"pkts": strconv.Itoa(pkts),
			"size": strconv.FormatInt(int64(size), 10),
		}, "")
	}
	return payloadsSplit(replies), nil
}