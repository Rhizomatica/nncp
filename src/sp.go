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
	"bytes"
	"crypto/subtle"
	"errors"
	"hash"
	"io"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	xdr "github.com/davecgh/go-xdr/xdr2"
	"github.com/flynn/noise"
	"golang.org/x/crypto/blake2b"
)

const (
	MaxSPSize      = 1<<16 - 256
	PartSuffix     = ".part"
	SPHeadOverhead = 4
)

var (
	MagicNNCPLv1 [8]byte = [8]byte{'N', 'N', 'C', 'P', 'S', 0, 0, 1}

	SPInfoOverhead    int
	SPFreqOverhead    int
	SPFileOverhead    int
	SPHaltMarshalized []byte
	SPPingMarshalized []byte

	NoiseCipherSuite noise.CipherSuite = noise.NewCipherSuite(
		noise.DH25519,
		noise.CipherChaChaPoly,
		noise.HashBLAKE2b,
	)

	DefaultDeadline = 10 * time.Second
	PingTimeout     = time.Minute
)

type FdAndFullSize struct {
	fd       *os.File
	fullSize int64
}

type HasherAndOffset struct {
	h      hash.Hash
	offset uint64
}

type SPType uint8

const (
	SPTypeInfo SPType = iota
	SPTypeFreq SPType = iota
	SPTypeFile SPType = iota
	SPTypeDone SPType = iota
	SPTypeHalt SPType = iota
	SPTypePing SPType = iota
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

type FreqWithNice struct {
	freq *SPFreq
	nice uint8
}

type ConnDeadlined interface {
	io.ReadWriteCloser
	SetReadDeadline(t time.Time) error
	SetWriteDeadline(t time.Time) error
}

func init() {
	var buf bytes.Buffer
	spHead := SPHead{Type: SPTypeHalt}
	if _, err := xdr.Marshal(&buf, spHead); err != nil {
		panic(err)
	}
	SPHaltMarshalized = make([]byte, SPHeadOverhead)
	copy(SPHaltMarshalized, buf.Bytes())
	buf.Reset()

	spHead = SPHead{Type: SPTypePing}
	if _, err := xdr.Marshal(&buf, spHead); err != nil {
		panic(err)
	}
	SPPingMarshalized = make([]byte, SPHeadOverhead)
	copy(SPPingMarshalized, buf.Bytes())
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
	if _, err := xdr.Marshal(&buf, SPHead{typ}); err != nil {
		panic(err)
	}
	if _, err := xdr.Marshal(&buf, sp); err != nil {
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
	Ctx            *Ctx
	Node           *Node
	Nice           uint8
	NoCK           bool
	onlineDeadline time.Duration
	maxOnlineTime  time.Duration
	hs             *noise.HandshakeState
	csOur          *noise.CipherState
	csTheir        *noise.CipherState
	payloads       chan []byte
	pings          chan struct{}
	infosTheir     map[[32]byte]*SPInfo
	infosOurSeen   map[[32]byte]uint8
	queueTheir     []*FreqWithNice
	wg             sync.WaitGroup
	RxBytes        int64
	RxLastSeen     time.Time
	RxLastNonPing  time.Time
	TxBytes        int64
	TxLastSeen     time.Time
	TxLastNonPing  time.Time
	started        time.Time
	mustFinishAt   time.Time
	Duration       time.Duration
	RxSpeed        int64
	TxSpeed        int64
	rxLock         *os.File
	txLock         *os.File
	xxOnly         TRxTx
	rxRate         int
	txRate         int
	isDead         chan struct{}
	listOnly       bool
	onlyPkts       map[[32]byte]bool
	writeSPBuf     bytes.Buffer
	fds            map[string]FdAndFullSize
	fileHashers    map[string]*HasherAndOffset
	checkerJobs    chan *[32]byte
	sync.RWMutex
}

func (state *SPState) SetDead() {
	state.Lock()
	defer state.Unlock()
	select {
	case <-state.isDead:
		// Already closed channel, dead
		return
	default:
	}
	close(state.isDead)
	go func() {
		for range state.payloads {
		}
	}()
	go func() {
		for range state.pings {
		}
	}()
	go func() {
		for _, s := range state.fds {
			s.fd.Close()
		}
	}()
	if !state.NoCK {
		close(state.checkerJobs)
	}
}

func (state *SPState) NotAlive() bool {
	select {
	case <-state.isDead:
		return true
	default:
	}
	return false
}

func (state *SPState) dirUnlock() {
	state.Ctx.UnlockDir(state.rxLock)
	state.Ctx.UnlockDir(state.txLock)
}

func (state *SPState) SPChecker() {
	for hshValue := range state.checkerJobs {
		les := LEs{
			{"XX", string(TRx)},
			{"Node", state.Node.Id},
			{"Pkt", Base32Codec.EncodeToString(hshValue[:])},
		}
		state.Ctx.LogD("sp-file", les, "checking")
		size, err := state.Ctx.CheckNoCK(state.Node.Id, hshValue)
		les = append(les, LE{"Size", size})
		if err != nil {
			state.Ctx.LogE("sp-file", les, err, "")
			continue
		}
		state.Ctx.LogI("sp-done", les, "")
		state.wg.Add(1)
		go func(hsh *[32]byte) {
			if !state.NotAlive() {
				state.payloads <- MarshalSP(SPTypeDone, SPDone{hsh})
			}
			state.wg.Done()
		}(hshValue)
	}
}

func (state *SPState) WriteSP(dst io.Writer, payload []byte, ping bool) error {
	state.writeSPBuf.Reset()
	n, err := xdr.Marshal(&state.writeSPBuf, SPRaw{
		Magic:   MagicNNCPLv1,
		Payload: payload,
	})
	if err != nil {
		return err
	}
	if n, err = dst.Write(state.writeSPBuf.Bytes()); err == nil {
		state.TxLastSeen = time.Now()
		state.TxBytes += int64(n)
		if !ping {
			state.TxLastNonPing = state.TxLastSeen
		}
	}
	return err
}

func (state *SPState) ReadSP(src io.Reader) ([]byte, error) {
	var sp SPRaw
	n, err := xdr.UnmarshalLimited(src, &sp, 1<<17)
	if err != nil {
		ue := err.(*xdr.UnmarshalError)
		if ue.Err == io.EOF {
			return nil, ue.Err
		}
		return nil, err
	}
	state.RxLastSeen = time.Now()
	state.RxBytes += int64(n)
	if sp.Magic != MagicNNCPLv1 {
		return nil, BadMagic
	}
	return sp.Payload, nil
}

func (ctx *Ctx) infosOur(nodeId *NodeId, nice uint8, seen *map[[32]byte]uint8) [][]byte {
	var infos []*SPInfo
	var totalSize int64
	for job := range ctx.Jobs(nodeId, TTx) {
		if job.PktEnc.Nice > nice {
			continue
		}
		if _, known := (*seen)[*job.HshValue]; known {
			continue
		}
		totalSize += job.Size
		infos = append(infos, &SPInfo{
			Nice: job.PktEnc.Nice,
			Size: uint64(job.Size),
			Hash: job.HshValue,
		})
		(*seen)[*job.HshValue] = job.PktEnc.Nice
	}
	sort.Sort(ByNice(infos))
	var payloads [][]byte
	for _, info := range infos {
		payloads = append(payloads, MarshalSP(SPTypeInfo, info))
		ctx.LogD("sp-info-our", LEs{
			{"Node", nodeId},
			{"Name", Base32Codec.EncodeToString(info.Hash[:])},
			{"Size", info.Size},
		}, "")
	}
	if totalSize > 0 {
		ctx.LogI("sp-infos", LEs{
			{"XX", string(TTx)},
			{"Node", nodeId},
			{"Pkts", len(payloads)},
			{"Size", totalSize},
		}, "")
	}
	return payloadsSplit(payloads)
}

func (state *SPState) StartI(conn ConnDeadlined) error {
	nodeId := state.Node.Id
	err := state.Ctx.ensureRxDir(nodeId)
	if err != nil {
		return err
	}
	var rxLock *os.File
	if !state.listOnly && (state.xxOnly == "" || state.xxOnly == TRx) {
		rxLock, err = state.Ctx.LockDir(nodeId, string(TRx))
		if err != nil {
			return err
		}
	}
	var txLock *os.File
	if !state.listOnly && (state.xxOnly == "" || state.xxOnly == TTx) {
		txLock, err = state.Ctx.LockDir(nodeId, string(TTx))
		if err != nil {
			return err
		}
	}
	started := time.Now()
	conf := noise.Config{
		CipherSuite: NoiseCipherSuite,
		Pattern:     noise.HandshakeIK,
		Initiator:   true,
		StaticKeypair: noise.DHKey{
			Private: state.Ctx.Self.NoisePrv[:],
			Public:  state.Ctx.Self.NoisePub[:],
		},
		PeerStatic: state.Node.NoisePub[:],
	}
	hs, err := noise.NewHandshakeState(conf)
	if err != nil {
		return err
	}
	state.hs = hs
	state.payloads = make(chan []byte)
	state.pings = make(chan struct{})
	state.infosTheir = make(map[[32]byte]*SPInfo)
	state.infosOurSeen = make(map[[32]byte]uint8)
	state.started = started
	state.rxLock = rxLock
	state.txLock = txLock

	var infosPayloads [][]byte
	if !state.listOnly && (state.xxOnly == "" || state.xxOnly == TTx) {
		infosPayloads = state.Ctx.infosOur(nodeId, state.Nice, &state.infosOurSeen)
	}
	var firstPayload []byte
	if len(infosPayloads) > 0 {
		firstPayload = infosPayloads[0]
	}
	// Pad first payload, to hide actual number of existing files
	for i := 0; i < (MaxSPSize-len(firstPayload))/SPHeadOverhead; i++ {
		firstPayload = append(firstPayload, SPHaltMarshalized...)
	}

	var buf []byte
	var payload []byte
	buf, _, _, err = state.hs.WriteMessage(nil, firstPayload)
	if err != nil {
		state.dirUnlock()
		return err
	}
	les := LEs{{"Node", nodeId}, {"Nice", int(state.Nice)}}
	state.Ctx.LogD("sp-start", les, "sending first message")
	conn.SetWriteDeadline(time.Now().Add(DefaultDeadline)) // #nosec G104
	if err = state.WriteSP(conn, buf, false); err != nil {
		state.Ctx.LogE("sp-start", les, err, "")
		state.dirUnlock()
		return err
	}
	state.Ctx.LogD("sp-start", les, "waiting for first message")
	conn.SetReadDeadline(time.Now().Add(DefaultDeadline)) // #nosec G104
	if buf, err = state.ReadSP(conn); err != nil {
		state.Ctx.LogE("sp-start", les, err, "")
		state.dirUnlock()
		return err
	}
	payload, state.csOur, state.csTheir, err = state.hs.ReadMessage(nil, buf)
	if err != nil {
		state.Ctx.LogE("sp-start", les, err, "")
		state.dirUnlock()
		return err
	}
	state.Ctx.LogD("sp-start", les, "starting workers")
	err = state.StartWorkers(conn, infosPayloads, payload)
	if err != nil {
		state.Ctx.LogE("sp-start", les, err, "")
		state.dirUnlock()
	}
	return err
}

func (state *SPState) StartR(conn ConnDeadlined) error {
	started := time.Now()
	conf := noise.Config{
		CipherSuite: NoiseCipherSuite,
		Pattern:     noise.HandshakeIK,
		Initiator:   false,
		StaticKeypair: noise.DHKey{
			Private: state.Ctx.Self.NoisePrv[:],
			Public:  state.Ctx.Self.NoisePub[:],
		},
	}
	hs, err := noise.NewHandshakeState(conf)
	if err != nil {
		return err
	}
	xxOnly := TRxTx("")
	state.hs = hs
	state.payloads = make(chan []byte)
	state.pings = make(chan struct{})
	state.infosOurSeen = make(map[[32]byte]uint8)
	state.infosTheir = make(map[[32]byte]*SPInfo)
	state.started = started
	state.xxOnly = xxOnly

	var buf []byte
	var payload []byte
	state.Ctx.LogD("sp-start", LEs{{"Nice", int(state.Nice)}}, "waiting for first message")
	conn.SetReadDeadline(time.Now().Add(DefaultDeadline)) // #nosec G104
	if buf, err = state.ReadSP(conn); err != nil {
		state.Ctx.LogE("sp-start", LEs{}, err, "")
		return err
	}
	if payload, _, _, err = state.hs.ReadMessage(nil, buf); err != nil {
		state.Ctx.LogE("sp-start", LEs{}, err, "")
		return err
	}

	var node *Node
	for _, n := range state.Ctx.Neigh {
		if subtle.ConstantTimeCompare(state.hs.PeerStatic(), n.NoisePub[:]) == 1 {
			node = n
			break
		}
	}
	if node == nil {
		peerId := Base32Codec.EncodeToString(state.hs.PeerStatic())
		state.Ctx.LogE("sp-start", LEs{{"Peer", peerId}}, errors.New("unknown peer"), "")
		return errors.New("Unknown peer: " + peerId)
	}
	state.Node = node
	state.rxRate = node.RxRate
	state.txRate = node.TxRate
	state.onlineDeadline = node.OnlineDeadline
	state.maxOnlineTime = node.MaxOnlineTime
	les := LEs{{"Node", node.Id}, {"Nice", int(state.Nice)}}

	if err = state.Ctx.ensureRxDir(node.Id); err != nil {
		return err
	}
	var rxLock *os.File
	if xxOnly == "" || xxOnly == TRx {
		rxLock, err = state.Ctx.LockDir(node.Id, string(TRx))
		if err != nil {
			return err
		}
	}
	state.rxLock = rxLock
	var txLock *os.File
	if xxOnly == "" || xxOnly == TTx {
		txLock, err = state.Ctx.LockDir(node.Id, string(TTx))
		if err != nil {
			return err
		}
	}
	state.txLock = txLock

	var infosPayloads [][]byte
	if xxOnly == "" || xxOnly == TTx {
		infosPayloads = state.Ctx.infosOur(node.Id, state.Nice, &state.infosOurSeen)
	}
	var firstPayload []byte
	if len(infosPayloads) > 0 {
		firstPayload = infosPayloads[0]
	}
	// Pad first payload, to hide actual number of existing files
	for i := 0; i < (MaxSPSize-len(firstPayload))/SPHeadOverhead; i++ {
		firstPayload = append(firstPayload, SPHaltMarshalized...)
	}

	state.Ctx.LogD("sp-start", les, "sending first message")
	buf, state.csTheir, state.csOur, err = state.hs.WriteMessage(nil, firstPayload)
	if err != nil {
		state.dirUnlock()
		return err
	}
	conn.SetWriteDeadline(time.Now().Add(DefaultDeadline)) // #nosec G104
	if err = state.WriteSP(conn, buf, false); err != nil {
		state.Ctx.LogE("sp-start", les, err, "")
		state.dirUnlock()
		return err
	}
	state.Ctx.LogD("sp-start", les, "starting workers")
	err = state.StartWorkers(conn, infosPayloads, payload)
	if err != nil {
		state.dirUnlock()
	}
	return err
}

func (state *SPState) closeFd(pth string) {
	s, exists := state.fds[pth]
	delete(state.fds, pth)
	if exists {
		s.fd.Close()
	}
}

func (state *SPState) FillExistingNoCK() {
	checkerJobs := make([]*[32]byte, 0)
	for job := range state.Ctx.JobsNoCK(state.Node.Id) {
		if job.PktEnc.Nice > state.Nice {
			continue
		}
		checkerJobs = append(checkerJobs, job.HshValue)
	}
	for _, job := range checkerJobs {
		state.checkerJobs <- job
	}
	state.wg.Done()
}

func (state *SPState) StartWorkers(
	conn ConnDeadlined,
	infosPayloads [][]byte,
	payload []byte,
) error {
	les := LEs{{"Node", state.Node.Id}, {"Nice", int(state.Nice)}}
	state.fds = make(map[string]FdAndFullSize)
	state.fileHashers = make(map[string]*HasherAndOffset)
	state.isDead = make(chan struct{})
	if state.maxOnlineTime > 0 {
		state.mustFinishAt = state.started.Add(state.maxOnlineTime)
	}

	// Checker
	if !state.NoCK {
		state.checkerJobs = make(chan *[32]byte)
		go state.SPChecker()
		state.wg.Add(1)
		go state.FillExistingNoCK()
	}

	// Remaining handshake payload sending
	if len(infosPayloads) > 1 {
		state.wg.Add(1)
		go func() {
			for _, payload := range infosPayloads[1:] {
				state.Ctx.LogD(
					"sp-work",
					append(les, LE{"Size", len(payload)}),
					"queuing remaining payload",
				)
				state.payloads <- payload
			}
			state.wg.Done()
		}()
	}

	// Processing of first payload and queueing its responses
	state.Ctx.LogD(
		"sp-work",
		append(les, LE{"Size", len(payload)}),
		"processing first payload",
	)
	replies, err := state.ProcessSP(payload)
	if err != nil {
		state.Ctx.LogE("sp-work", les, err, "")
		return err
	}
	state.wg.Add(1)
	go func() {
		for _, reply := range replies {
			state.Ctx.LogD(
				"sp-work",
				append(les, LE{"Size", len(reply)}),
				"queuing reply",
			)
			state.payloads <- reply
		}
		state.wg.Done()
	}()

	// Periodic jobs
	state.wg.Add(1)
	go func() {
		deadlineTicker := time.NewTicker(time.Second)
		pingTicker := time.NewTicker(PingTimeout)
		for {
			select {
			case <-state.isDead:
				state.wg.Done()
				deadlineTicker.Stop()
				pingTicker.Stop()
				return
			case now := <-deadlineTicker.C:
				if (now.Sub(state.RxLastNonPing) >= state.onlineDeadline &&
					now.Sub(state.TxLastNonPing) >= state.onlineDeadline) ||
					(state.maxOnlineTime > 0 && state.mustFinishAt.Before(now)) ||
					(now.Sub(state.RxLastSeen) >= 2*PingTimeout) {
					state.SetDead()
					conn.Close() // #nosec G104
				}
			case now := <-pingTicker.C:
				if now.After(state.TxLastSeen.Add(PingTimeout)) {
					state.wg.Add(1)
					go func() {
						state.pings <- struct{}{}
						state.wg.Done()
					}()
				}
			}
		}
	}()

	// Spool checker and INFOs sender of appearing files
	if !state.listOnly && (state.xxOnly == "" || state.xxOnly == TTx) {
		state.wg.Add(1)
		go func() {
			ticker := time.NewTicker(time.Second)
			for {
				select {
				case <-state.isDead:
					state.wg.Done()
					ticker.Stop()
					return
				case <-ticker.C:
					for _, payload := range state.Ctx.infosOur(
						state.Node.Id,
						state.Nice,
						&state.infosOurSeen,
					) {
						state.Ctx.LogD(
							"sp-work",
							append(les, LE{"Size", len(payload)}),
							"queuing new info",
						)
						state.payloads <- payload
					}
				}
			}
		}()
	}

	// Sender
	state.wg.Add(1)
	go func() {
		defer conn.Close()
		defer state.SetDead()
		defer state.wg.Done()
		for {
			if state.NotAlive() {
				return
			}
			var payload []byte
			var ping bool
			select {
			case <-state.pings:
				state.Ctx.LogD("sp-xmit", les, "got ping")
				payload = SPPingMarshalized
				ping = true
			case payload = <-state.payloads:
				state.Ctx.LogD(
					"sp-xmit",
					append(les, LE{"Size", len(payload)}),
					"got payload",
				)
			default:
				state.RLock()
				if len(state.queueTheir) == 0 {
					state.RUnlock()
					time.Sleep(100 * time.Millisecond)
					continue
				}
				freq := state.queueTheir[0].freq
				state.RUnlock()
				if state.txRate > 0 {
					time.Sleep(time.Second / time.Duration(state.txRate))
				}
				lesp := append(les, LEs{
					{"XX", string(TTx)},
					{"Pkt", Base32Codec.EncodeToString(freq.Hash[:])},
					{"Size", int64(freq.Offset)},
				}...)
				state.Ctx.LogD("sp-file", lesp, "queueing")
				pth := filepath.Join(
					state.Ctx.Spool,
					state.Node.Id.String(),
					string(TTx),
					Base32Codec.EncodeToString(freq.Hash[:]),
				)
				fdAndFullSize, exists := state.fds[pth]
				if !exists {
					fd, err := os.Open(pth)
					if err != nil {
						state.Ctx.LogE("sp-file", lesp, err, "")
						return
					}
					fi, err := fd.Stat()
					if err != nil {
						state.Ctx.LogE("sp-file", lesp, err, "")
						return
					}
					fdAndFullSize = FdAndFullSize{fd: fd, fullSize: fi.Size()}
					state.fds[pth] = fdAndFullSize
				}
				fd := fdAndFullSize.fd
				fullSize := fdAndFullSize.fullSize
				var buf []byte
				if freq.Offset < uint64(fullSize) {
					state.Ctx.LogD("sp-file", lesp, "seeking")
					if _, err = fd.Seek(int64(freq.Offset), io.SeekStart); err != nil {
						state.Ctx.LogE("sp-file", lesp, err, "")
						return
					}
					buf = make([]byte, MaxSPSize-SPHeadOverhead-SPFileOverhead)
					n, err := fd.Read(buf)
					if err != nil {
						state.Ctx.LogE("sp-file", lesp, err, "")
						return
					}
					buf = buf[:n]
					state.Ctx.LogD("sp-file", append(lesp, LE{"Size", n}), "read")
				}
				state.closeFd(pth)
				payload = MarshalSP(SPTypeFile, SPFile{
					Hash:    freq.Hash,
					Offset:  freq.Offset,
					Payload: buf,
				})
				ourSize := freq.Offset + uint64(len(buf))
				lesp = append(lesp, LE{"Size", int64(ourSize)})
				lesp = append(lesp, LE{"FullSize", fullSize})
				if state.Ctx.ShowPrgrs {
					Progress("Tx", lesp)
				}
				state.Lock()
				if len(state.queueTheir) > 0 && *state.queueTheir[0].freq.Hash == *freq.Hash {
					if ourSize == uint64(fullSize) {
						state.Ctx.LogD("sp-file", lesp, "finished")
						if len(state.queueTheir) > 1 {
							state.queueTheir = state.queueTheir[1:]
						} else {
							state.queueTheir = state.queueTheir[:0]
						}
					} else {
						state.queueTheir[0].freq.Offset += uint64(len(buf))
					}
				} else {
					state.Ctx.LogD("sp-file", lesp, "queue disappeared")
				}
				state.Unlock()
			}
			state.Ctx.LogD("sp-xmit", append(les, LE{"Size", len(payload)}), "sending")
			conn.SetWriteDeadline(time.Now().Add(DefaultDeadline)) // #nosec G104
			if err := state.WriteSP(conn, state.csOur.Encrypt(nil, nil, payload), ping); err != nil {
				state.Ctx.LogE("sp-xmit", les, err, "")
				return
			}
		}
	}()

	// Receiver
	state.wg.Add(1)
	go func() {
		for {
			if state.NotAlive() {
				break
			}
			state.Ctx.LogD("sp-recv", les, "waiting for payload")
			conn.SetReadDeadline(time.Now().Add(DefaultDeadline)) // #nosec G104
			payload, err := state.ReadSP(conn)
			if err != nil {
				if err == io.EOF {
					break
				}
				unmarshalErr := err.(*xdr.UnmarshalError)
				if os.IsTimeout(unmarshalErr.Err) {
					continue
				}
				if unmarshalErr.ErrorCode == xdr.ErrIO {
					break
				}
				state.Ctx.LogE("sp-recv", les, err, "")
				break
			}
			state.Ctx.LogD(
				"sp-recv",
				append(les, LE{"Size", len(payload)}),
				"got payload",
			)
			payload, err = state.csTheir.Decrypt(nil, nil, payload)
			if err != nil {
				state.Ctx.LogE("sp-recv", les, err, "")
				break
			}
			state.Ctx.LogD(
				"sp-recv",
				append(les, LE{"Size", len(payload)}),
				"processing",
			)
			replies, err := state.ProcessSP(payload)
			if err != nil {
				state.Ctx.LogE("sp-recv", les, err, "")
				break
			}
			state.wg.Add(1)
			go func() {
				for _, reply := range replies {
					state.Ctx.LogD(
						"sp-recv",
						append(les, LE{"Size", len(reply)}),
						"queuing reply",
					)
					state.payloads <- reply
				}
				state.wg.Done()
			}()
			if state.rxRate > 0 {
				time.Sleep(time.Second / time.Duration(state.rxRate))
			}
		}
		state.SetDead()
		state.wg.Done()
		state.SetDead()
		conn.Close() // #nosec G104
	}()

	return nil
}

func (state *SPState) Wait() {
	state.wg.Wait()
	close(state.payloads)
	close(state.pings)
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
	les := LEs{{"Node", state.Node.Id}, {"Nice", int(state.Nice)}}
	r := bytes.NewReader(payload)
	var err error
	var replies [][]byte
	var infosGot bool
	for r.Len() > 0 {
		state.Ctx.LogD("sp-process", les, "unmarshaling header")
		var head SPHead
		if _, err = xdr.Unmarshal(r, &head); err != nil {
			state.Ctx.LogE("sp-process", les, err, "")
			return nil, err
		}
		if head.Type != SPTypePing {
			state.RxLastNonPing = state.RxLastSeen
		}
		switch head.Type {
		case SPTypeHalt:
			state.Ctx.LogD("sp-process", append(les, LE{"Type", "halt"}), "")
			state.Lock()
			state.queueTheir = nil
			state.Unlock()

		case SPTypePing:
			state.Ctx.LogD("sp-process", append(les, LE{"Type", "ping"}), "")

		case SPTypeInfo:
			infosGot = true
			lesp := append(les, LE{"Type", "info"})
			state.Ctx.LogD("sp-process", lesp, "unmarshaling packet")
			var info SPInfo
			if _, err = xdr.Unmarshal(r, &info); err != nil {
				state.Ctx.LogE("sp-process", lesp, err, "")
				return nil, err
			}
			lesp = append(lesp, LEs{
				{"Pkt", Base32Codec.EncodeToString(info.Hash[:])},
				{"Size", int64(info.Size)},
				{"Nice", int(info.Nice)},
			}...)
			if !state.listOnly && info.Nice > state.Nice {
				state.Ctx.LogD("sp-process", lesp, "too nice")
				continue
			}
			state.Ctx.LogD("sp-process", lesp, "received")
			if !state.listOnly && state.xxOnly == TTx {
				continue
			}
			state.Lock()
			state.infosTheir[*info.Hash] = &info
			state.Unlock()
			state.Ctx.LogD("sp-process", lesp, "stating part")
			pktPath := filepath.Join(
				state.Ctx.Spool,
				state.Node.Id.String(),
				string(TRx),
				Base32Codec.EncodeToString(info.Hash[:]),
			)
			if _, err = os.Stat(pktPath); err == nil {
				state.Ctx.LogI("sp-info", lesp, "already done")
				if !state.listOnly {
					replies = append(replies, MarshalSP(SPTypeDone, SPDone{info.Hash}))
				}
				continue
			}
			if _, err = os.Stat(pktPath + SeenSuffix); err == nil {
				state.Ctx.LogI("sp-info", lesp, "already seen")
				if !state.listOnly {
					replies = append(replies, MarshalSP(SPTypeDone, SPDone{info.Hash}))
				}
				continue
			}
			if _, err = os.Stat(pktPath + NoCKSuffix); err == nil {
				state.Ctx.LogI("sp-info", lesp, "still non checksummed")
				continue
			}
			fi, err := os.Stat(pktPath + PartSuffix)
			var offset int64
			if err == nil {
				offset = fi.Size()
			}
			if !state.Ctx.IsEnoughSpace(int64(info.Size) - offset) {
				state.Ctx.LogI("sp-info", lesp, "not enough space")
				continue
			}
			state.Ctx.LogI("sp-info", append(lesp, LE{"Offset", offset}), "")
			if !state.listOnly && (state.onlyPkts == nil || state.onlyPkts[*info.Hash]) {
				replies = append(replies, MarshalSP(
					SPTypeFreq,
					SPFreq{info.Hash, uint64(offset)},
				))
			}

		case SPTypeFile:
			lesp := append(les, LE{"Type", "file"})
			state.Ctx.LogD("sp-process", lesp, "unmarshaling packet")
			var file SPFile
			if _, err = xdr.Unmarshal(r, &file); err != nil {
				state.Ctx.LogE("sp-process", lesp, err, "")
				return nil, err
			}
			lesp = append(lesp, LEs{
				{"XX", string(TRx)},
				{"Pkt", Base32Codec.EncodeToString(file.Hash[:])},
				{"Size", len(file.Payload)},
			}...)
			dirToSync := filepath.Join(
				state.Ctx.Spool,
				state.Node.Id.String(),
				string(TRx),
			)
			filePath := filepath.Join(dirToSync, Base32Codec.EncodeToString(file.Hash[:]))
			filePathPart := filePath + PartSuffix
			state.Ctx.LogD("sp-file", lesp, "opening part")
			fdAndFullSize, exists := state.fds[filePathPart]
			var fd *os.File
			if exists {
				fd = fdAndFullSize.fd
			} else {
				fd, err = os.OpenFile(
					filePathPart,
					os.O_RDWR|os.O_CREATE,
					os.FileMode(0666),
				)
				if err != nil {
					state.Ctx.LogE("sp-file", lesp, err, "")
					return nil, err
				}
				state.fds[filePathPart] = FdAndFullSize{fd: fd}
				if file.Offset == 0 {
					h, err := blake2b.New256(nil)
					if err != nil {
						panic(err)
					}
					state.fileHashers[filePath] = &HasherAndOffset{h: h}
				}
			}
			state.Ctx.LogD("sp-file", append(lesp, LE{"Offset", file.Offset}), "seeking")
			if _, err = fd.Seek(int64(file.Offset), io.SeekStart); err != nil {
				state.Ctx.LogE("sp-file", lesp, err, "")
				state.closeFd(filePathPart)
				return nil, err
			}
			state.Ctx.LogD("sp-file", lesp, "writing")
			if _, err = fd.Write(file.Payload); err != nil {
				state.Ctx.LogE("sp-file", lesp, err, "")
				state.closeFd(filePathPart)
				return nil, err
			}
			hasherAndOffset, hasherExists := state.fileHashers[filePath]
			if hasherExists {
				if hasherAndOffset.offset == file.Offset {
					if _, err = hasherAndOffset.h.Write(file.Payload); err != nil {
						panic(err)
					}
					hasherAndOffset.offset += uint64(len(file.Payload))
				} else {
					state.Ctx.LogE(
						"sp-file", lesp,
						errors.New("offset differs"),
						"deleting hasher",
					)
					delete(state.fileHashers, filePath)
					hasherExists = false
				}
			}
			ourSize := int64(file.Offset + uint64(len(file.Payload)))
			lesp[len(lesp)-1].V = ourSize
			fullsize := int64(0)
			state.RLock()
			infoTheir, ok := state.infosTheir[*file.Hash]
			state.RUnlock()
			if ok {
				fullsize = int64(infoTheir.Size)
			}
			lesp = append(lesp, LE{"FullSize", fullsize})
			if state.Ctx.ShowPrgrs {
				Progress("Rx", lesp)
			}
			if fullsize != ourSize {
				continue
			}
			err = fd.Sync()
			if err != nil {
				state.Ctx.LogE("sp-file", lesp, err, "sync")
				state.closeFd(filePathPart)
				continue
			}
			if hasherExists {
				if bytes.Compare(hasherAndOffset.h.Sum(nil), file.Hash[:]) != 0 {
					state.Ctx.LogE("sp-file", lesp, errors.New("checksum mismatch"), "")
					continue
				}
				if err = os.Rename(filePathPart, filePath); err != nil {
					state.Ctx.LogE("sp-file", lesp, err, "rename")
					continue
				}
				if err = DirSync(dirToSync); err != nil {
					state.Ctx.LogE("sp-file", lesp, err, "sync")
					continue
				}
				state.Ctx.LogI("sp-file", lesp, "done")
				state.wg.Add(1)
				go func() {
					state.payloads <- MarshalSP(SPTypeDone, SPDone{file.Hash})
					state.wg.Done()
				}()
				state.Lock()
				delete(state.infosTheir, *file.Hash)
				state.Unlock()
				if !state.Ctx.HdrUsage {
					state.closeFd(filePathPart)
					continue
				}
				if _, err = fd.Seek(0, io.SeekStart); err != nil {
					state.Ctx.LogE("sp-file", lesp, err, "seek")
					state.closeFd(filePathPart)
					continue
				}
				_, pktEncRaw, err := state.Ctx.HdrRead(fd)
				state.closeFd(filePathPart)
				if err != nil {
					state.Ctx.LogE("sp-file", lesp, err, "HdrRead")
					continue
				}
				state.Ctx.HdrWrite(pktEncRaw, filePath)
				continue
			}
			state.closeFd(filePathPart)
			if err = os.Rename(filePathPart, filePath+NoCKSuffix); err != nil {
				state.Ctx.LogE("sp-file", lesp, err, "rename")
				continue
			}
			if err = DirSync(dirToSync); err != nil {
				state.Ctx.LogE("sp-file", lesp, err, "sync")
				continue
			}
			state.Ctx.LogI("sp-file", lesp, "downloaded")
			state.Lock()
			delete(state.infosTheir, *file.Hash)
			state.Unlock()
			if !state.NoCK {
				state.checkerJobs <- file.Hash
			}

		case SPTypeDone:
			lesp := append(les, LE{"Type", "done"})
			state.Ctx.LogD("sp-process", lesp, "unmarshaling packet")
			var done SPDone
			if _, err = xdr.Unmarshal(r, &done); err != nil {
				state.Ctx.LogE("sp-process", lesp, err, "")
				return nil, err
			}
			lesp = append(lesp, LE{"Pkt", Base32Codec.EncodeToString(done.Hash[:])})
			state.Ctx.LogD("sp-done", lesp, "removing")
			pth := filepath.Join(
				state.Ctx.Spool,
				state.Node.Id.String(),
				string(TTx),
				Base32Codec.EncodeToString(done.Hash[:]),
			)
			err := os.Remove(pth)
			lesp = append(lesp, LE{"XX", string(TTx)})
			if err == nil {
				state.Ctx.LogI("sp-done", lesp, "")
				if state.Ctx.HdrUsage {
					os.Remove(pth + HdrSuffix)
				}
			} else {
				state.Ctx.LogE("sp-done", lesp, err, "")
			}

		case SPTypeFreq:
			lesp := append(les, LE{"Type", "freq"})
			state.Ctx.LogD("sp-process", lesp, "unmarshaling packet")
			var freq SPFreq
			if _, err = xdr.Unmarshal(r, &freq); err != nil {
				state.Ctx.LogE("sp-process", lesp, err, "")
				return nil, err
			}
			lesp = append(lesp, LE{"Pkt", Base32Codec.EncodeToString(freq.Hash[:])})
			lesp = append(lesp, LE{"Offset", freq.Offset})
			state.Ctx.LogD("sp-process", lesp, "queueing")
			nice, exists := state.infosOurSeen[*freq.Hash]
			if exists {
				if state.onlyPkts == nil || !state.onlyPkts[*freq.Hash] {
					state.Lock()
					insertIdx := 0
					var freqWithNice *FreqWithNice
					for insertIdx, freqWithNice = range state.queueTheir {
						if freqWithNice.nice > nice {
							break
						}
					}
					state.queueTheir = append(state.queueTheir, nil)
					copy(state.queueTheir[insertIdx+1:], state.queueTheir[insertIdx:])
					state.queueTheir[insertIdx] = &FreqWithNice{&freq, nice}
					state.Unlock()
				} else {
					state.Ctx.LogD("sp-process", lesp, "skipping")
				}
			} else {
				state.Ctx.LogD("sp-process", lesp, "unknown")
			}

		default:
			state.Ctx.LogE(
				"sp-process",
				append(les, LE{"Type", head.Type}),
				errors.New("unknown type"),
				"",
			)
			return nil, BadPktType
		}
	}
	if infosGot {
		var pkts int
		var size uint64
		state.RLock()
		for _, info := range state.infosTheir {
			pkts++
			size += info.Size
		}
		state.RUnlock()
		state.Ctx.LogI("sp-infos", LEs{
			{"XX", string(TRx)},
			{"Node", state.Node.Id},
			{"Pkts", pkts},
			{"Size", int64(size)},
		}, "")
	}
	return payloadsSplit(replies), nil
}
