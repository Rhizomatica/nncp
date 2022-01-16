//go:build !noyggdrasil
// +build !noyggdrasil

/*
NNCP -- Node to Node copy, utilities for store-and-forward data exchange
Copyright (C) 2016-2022 Sergey Matveev <stargrave@stargrave.org>

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
	"encoding/hex"
	"errors"
	"log"
	"net"
	"strings"

	iwt "github.com/Arceliar/ironwood/types"
	gologme "github.com/gologme/log"
	"github.com/neilalexander/utp"
	ycfg "github.com/yggdrasil-network/yggdrasil-go/src/config"
	ycore "github.com/yggdrasil-network/yggdrasil-go/src/core"
	"golang.org/x/crypto/ed25519"
)

var glog *gologme.Logger

func init() {
	glog = gologme.New(log.Writer(), "yggdrasil: ", gologme.Lmsgprefix)
	glog.EnableLevel("warn")
	glog.EnableLevel("error")
	glog.EnableLevel("info")
}

func NewYggdrasilConn(aliases map[string]string, in string) (ConnDeadlined, error) {
	// pub;prv;peer[, ...]
	cols := strings.Split(in, ";")
	if len(cols) < 3 {
		return nil, errors.New("invalid yggdrasil: address format")
	}
	pubHex, prvHex, peersRaw := cols[0], cols[1], cols[2]
	if v, ok := aliases[pubHex]; ok {
		pubHex = v
	}
	if v, ok := aliases[prvHex]; ok {
		prvHex = v
	}
	if v, ok := aliases[peersRaw]; ok {
		peersRaw = v
	}
	peers := strings.Split(peersRaw, ",")
	for i, peer := range peers {
		if v, ok := aliases[peer]; ok {
			peers[i] = v
		}
	}
	addrRaw, err := hex.DecodeString(pubHex)
	if err != nil {
		return nil, err
	}
	cfg := ycfg.NodeConfig{
		PrivateKey:      prvHex,
		Peers:           peers,
		NodeInfo:        map[string]interface{}{"name": "NNCP " + Version},
		NodeInfoPrivacy: true,
	}
	core := &ycore.Core{}
	if err := core.Start(&cfg, glog); err != nil {
		return nil, err
	}
	utpSock, err := utp.NewSocketFromPacketConnNoClose(core)
	if err != nil {
		return nil, err
	}
	addr := make(iwt.Addr, ed25519.PublicKeySize)
	copy(addr, addrRaw)
	return utpSock.DialAddr(addr)
}

func NewYggdrasilListener(aliases map[string]string, in string) (net.Listener, error) {
	// prv;bind[, ...];[pub, ...];[peer, ...]
	cols := strings.Split(in, ";")
	if len(cols) < 4 {
		return nil, errors.New("invalid -yggdrasil address format")
	}
	prvHex, bindsRaw, pubsRaw, peersRaw := cols[0], cols[1], cols[2], cols[3]
	if v, ok := aliases[prvHex]; ok {
		prvHex = v
	}
	if v, ok := aliases[bindsRaw]; ok {
		bindsRaw = v
	}
	binds := strings.Split(bindsRaw, ",")
	for i, bind := range binds {
		if v, ok := aliases[bind]; ok {
			binds[i] = v
		}
	}
	if v, ok := aliases[pubsRaw]; ok {
		pubsRaw = v
	}
	pubs := strings.Split(pubsRaw, ",")
	if len(pubs) == 1 && pubs[0] == "" {
		pubs = nil
	}
	for i, pub := range pubs {
		if v, ok := aliases[pub]; ok {
			pubs[i] = v
		}
	}
	if v, ok := aliases[peersRaw]; ok {
		peersRaw = v
	}
	peers := strings.Split(peersRaw, ",")
	if len(peers) == 1 && peers[0] == "" {
		peers = nil
	}
	for i, peer := range peers {
		if v, ok := aliases[peer]; ok {
			peers[i] = v
		}
	}
	cfg := ycfg.NodeConfig{
		PrivateKey:        prvHex,
		Listen:            binds,
		AllowedPublicKeys: pubs,
		Peers:             peers,
		NodeInfo:          map[string]interface{}{"name": "NNCP " + Version},
		NodeInfoPrivacy:   true,
	}
	core := &ycore.Core{}
	if err := core.Start(&cfg, glog); err != nil {
		return nil, err
	}
	utpSock, err := utp.NewSocketFromPacketConnNoClose(core)
	if err != nil {
		return nil, err
	}
	return utpSock, nil
}
