/*
NNCP -- Node-to-Node CoPy
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
	"errors"
	"path"

	"golang.org/x/crypto/ed25519"
	"gopkg.in/yaml.v2"
)

var (
	DefaultCfgPath      string = "/usr/local/etc/nncp.yaml"
	DefaultSendmailPath string = "/usr/sbin/sendmail"
)

type NodeYAML struct {
	Id       string
	ExchPub  string
	SignPub  string
	NoisePub string
	Incoming *string  `incoming,omitempty`
	Freq     *string  `freq,omitempty`
	Via      []string `via,omitempty`

	Addrs map[string]string `addrs,omitempty`
}

type NodeOurYAML struct {
	Id       string
	ExchPub  string
	ExchPrv  string
	SignPub  string
	SignPrv  string
	NoisePrv string
	NoisePub string
}

type FromToYAML struct {
	From string
	To   string
}

type NotifyYAML struct {
	File *FromToYAML `file,omitempty`
	Freq *FromToYAML `freq,omitempty`
}

type CfgYAML struct {
	Self  NodeOurYAML
	Neigh map[string]NodeYAML

	Spool    string
	Log      string
	Sendmail []string
	Notify   *NotifyYAML `notify,omitempty`
}

func NewNode(name string, yml NodeYAML) (*Node, error) {
	nodeId, err := NodeIdFromString(yml.Id)
	if err != nil {
		return nil, err
	}

	exchPub, err := FromBase32(yml.ExchPub)
	if err != nil {
		return nil, err
	}
	if len(exchPub) != 32 {
		return nil, errors.New("Invalid exchPub size")
	}

	signPub, err := FromBase32(yml.SignPub)
	if err != nil {
		return nil, err
	}
	if len(signPub) != ed25519.PublicKeySize {
		return nil, errors.New("Invalid signPub size")
	}

	noisePub, err := FromBase32(yml.NoisePub)
	if err != nil {
		return nil, err
	}
	if len(noisePub) != 32 {
		return nil, errors.New("Invalid noisePub size")
	}

	var incoming *string
	if yml.Incoming != nil {
		inc := path.Clean(*yml.Incoming)
		if !path.IsAbs(inc) {
			return nil, errors.New("Incoming path must be absolute")
		}
		incoming = &inc
	}

	var freq *string
	if yml.Freq != nil {
		fr := path.Clean(*yml.Freq)
		if !path.IsAbs(fr) {
			return nil, errors.New("Freq path must be absolute")
		}
		freq = &fr
	}

	node := Node{
		Name:     name,
		Id:       nodeId,
		ExchPub:  new([32]byte),
		SignPub:  ed25519.PublicKey(signPub),
		NoisePub: new([32]byte),
		Incoming: incoming,
		Freq:     freq,
		Addrs:    yml.Addrs,
	}
	copy(node.ExchPub[:], exchPub)
	copy(node.NoisePub[:], noisePub)
	return &node, nil
}

func NewNodeOur(yml NodeOurYAML) (*NodeOur, error) {
	id, err := NodeIdFromString(yml.Id)
	if err != nil {
		return nil, err
	}

	exchPub, err := FromBase32(yml.ExchPub)
	if err != nil {
		return nil, err
	}
	if len(exchPub) != 32 {
		return nil, errors.New("Invalid exchPub size")
	}

	exchPrv, err := FromBase32(yml.ExchPrv)
	if err != nil {
		return nil, err
	}
	if len(exchPrv) != 32 {
		return nil, errors.New("Invalid exchPrv size")
	}

	signPub, err := FromBase32(yml.SignPub)
	if err != nil {
		return nil, err
	}
	if len(signPub) != ed25519.PublicKeySize {
		return nil, errors.New("Invalid signPub size")
	}

	signPrv, err := FromBase32(yml.SignPrv)
	if err != nil {
		return nil, err
	}
	if len(signPrv) != ed25519.PrivateKeySize {
		return nil, errors.New("Invalid signPrv size")
	}

	noisePub, err := FromBase32(yml.NoisePub)
	if err != nil {
		return nil, err
	}
	if len(noisePub) != 32 {
		return nil, errors.New("Invalid noisePub size")
	}

	noisePrv, err := FromBase32(yml.NoisePrv)
	if err != nil {
		return nil, err
	}
	if len(noisePrv) != 32 {
		return nil, errors.New("Invalid noisePrv size")
	}

	node := NodeOur{
		Id:       id,
		ExchPub:  new([32]byte),
		ExchPrv:  new([32]byte),
		SignPub:  ed25519.PublicKey(signPub),
		SignPrv:  ed25519.PrivateKey(signPrv),
		NoisePub: new([32]byte),
		NoisePrv: new([32]byte),
	}
	copy(node.ExchPub[:], exchPub)
	copy(node.ExchPrv[:], exchPrv)
	copy(node.NoisePub[:], noisePub)
	copy(node.NoisePrv[:], noisePrv)
	return &node, nil
}

func (nodeOur *NodeOur) ToYAML() string {
	yml := NodeOurYAML{
		Id:       nodeOur.Id.String(),
		ExchPub:  ToBase32(nodeOur.ExchPub[:]),
		ExchPrv:  ToBase32(nodeOur.ExchPrv[:]),
		SignPub:  ToBase32(nodeOur.SignPub[:]),
		SignPrv:  ToBase32(nodeOur.SignPrv[:]),
		NoisePub: ToBase32(nodeOur.NoisePub[:]),
		NoisePrv: ToBase32(nodeOur.NoisePrv[:]),
	}
	raw, err := yaml.Marshal(&yml)
	if err != nil {
		panic(err)
	}
	return string(raw)
}

func CfgParse(data []byte) (*Ctx, error) {
	var cfgYAML CfgYAML
	err := yaml.Unmarshal(data, &cfgYAML)
	if err != nil {
		return nil, err
	}
	self, err := NewNodeOur(cfgYAML.Self)
	if err != nil {
		return nil, err
	}
	spoolPath := path.Clean(cfgYAML.Spool)
	if !path.IsAbs(spoolPath) {
		return nil, errors.New("Spool path must be absolute")
	}
	logPath := path.Clean(cfgYAML.Log)
	if !path.IsAbs(logPath) {
		return nil, errors.New("Log path must be absolute")
	}
	ctx := Ctx{
		Spool:    spoolPath,
		LogPath:  logPath,
		Self:     self,
		Neigh:    make(map[NodeId]*Node, len(cfgYAML.Neigh)),
		Alias:    make(map[string]*NodeId),
		Sendmail: cfgYAML.Sendmail,
	}
	if cfgYAML.Notify != nil {
		if cfgYAML.Notify.File != nil {
			ctx.NotifyFile = cfgYAML.Notify.File
		}
		if cfgYAML.Notify.Freq != nil {
			ctx.NotifyFreq = cfgYAML.Notify.Freq
		}
	}
	vias := make(map[NodeId][]string)
	for name, neighYAML := range cfgYAML.Neigh {
		neigh, err := NewNode(name, neighYAML)
		if err != nil {
			return nil, err
		}
		ctx.Neigh[*neigh.Id] = neigh
		if _, already := ctx.Alias[name]; already {
			return nil, errors.New("Node names conflict")
		}
		ctx.Alias[name] = neigh.Id
		vias[*neigh.Id] = neighYAML.Via
	}
	for neighId, viasRaw := range vias {
		for _, viaRaw := range viasRaw {
			foundNodeId, err := ctx.FindNode(viaRaw)
			if err != nil {
				return nil, err
			}
			ctx.Neigh[neighId].Via = append(
				ctx.Neigh[neighId].Via,
				foundNodeId.Id,
			)
		}
	}
	return &ctx, nil
}
