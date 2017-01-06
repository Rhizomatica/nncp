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
)

type Ctx struct {
	Self  *NodeOur
	Neigh map[NodeId]*Node
	Alias map[string]*NodeId

	Spool    string
	Sendmail []string

	LogPath    string
	Debug      bool
	NotifyFile *FromToYAML
	NotifyFreq *FromToYAML
}

func (ctx *Ctx) FindNode(id string) (*Node, error) {
	nodeId, known := ctx.Alias[id]
	if known {
		return ctx.Neigh[*nodeId], nil
	}
	nodeId, err := NodeIdFromString(id)
	if err != nil {
		return nil, err
	}
	node, known := ctx.Neigh[*nodeId]
	if !known {
		return nil, errors.New("Unknown node")
	}
	return node, nil
}
