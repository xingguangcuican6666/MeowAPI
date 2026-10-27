/*
Copyright (C) 2023-2026 xingguangcuican6666

This file is part of new-api, which is licensed under the GNU Affero General
Public License v3.0. Original project: https://github.com/QuantumNous/new-api

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as
published by the Free Software Foundation, either version 3 of the
License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program. If not, see <https://www.gnu.org/licenses/>.
*/

package service

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/gorilla/websocket"
)

// Node link state is deliberately stored in local files, not the options
// table: a child node switches its database to the master's through the
// tunnel, so anything living in the options table would be lost on the swap
// (and on every later boot). File permissions are restricted to the owner.

const (
	NodeLinkRoleMaster = "master"
	NodeLinkRoleChild  = "child"

	NodeLinkDBModeOverwrite = "overwrite"
	NodeLinkDBModeMerge     = "merge"

	nodeLinkDataDir    = "data"
	nodeLinkChildFile  = "node_link_child.json"
	nodeLinkMasterFile = "node_link_master.json"
)

// NodeLinkChildState is the child-side link configuration.
type NodeLinkChildState struct {
	Role        string `json:"role"`
	MasterURL   string `json:"master_url"`
	Token       string `json:"token"`
	DBMode      string `json:"db_mode"`
	NodeName    string `json:"node_name"`
	TunnelDSN   string `json:"tunnel_dsn"`  // master DB credentials pointed at the local tunnel listener
	LocalDSN    string `json:"local_dsn"`   // DSN to restore on disconnect
	ListenPort  int    `json:"listen_port"` // local 127.0.0.1 tunnel listener
	Connected   bool   `json:"connected"`
	MasterName  string `json:"master_name,omitempty"`
	ConnectedAt int64  `json:"connected_at,omitempty"`
}

// NodeLinkChildRecord is the master-side registry entry for one child.
type NodeLinkChildRecord struct {
	Name         string `json:"name"`
	Token        string `json:"token"`
	DBMode       string `json:"db_mode"`
	Version      string `json:"version,omitempty"`
	Hostname     string `json:"hostname,omitempty"`
	RegisteredAt int64  `json:"registered_at"`
	LastSeenAt   int64  `json:"last_seen_at"`
}

// NodeLinkMasterState is the master-side link configuration.
type NodeLinkMasterState struct {
	Role     string                `json:"role"`
	Tokens   []string              `json:"tokens"`
	Children []NodeLinkChildRecord `json:"children"`
}

var (
	nodeLinkChildStateMu  sync.Mutex
	nodeLinkChildState    *NodeLinkChildState
	nodeLinkMasterStateMu sync.Mutex
	nodeLinkMasterState   *NodeLinkMasterState
)

func nodeLinkStatePath(file string) string {
	return filepath.Join(nodeLinkDataDir, file)
}

func writeNodeLinkFile(path string, value any) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	// 0600: the files carry pairing tokens and (child side) database
	// credentials for the tunnel.
	return os.WriteFile(path, data, 0o600)
}

func readNodeLinkFile(path string, value any) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if err := json.Unmarshal(data, value); err != nil {
		return false, fmt.Errorf("node link state %s is corrupted: %w", path, err)
	}
	return true, nil
}

// GetNodeLinkChildState returns the persisted child-side link state, or nil
// when this node has no link configured.
func GetNodeLinkChildState() *NodeLinkChildState {
	nodeLinkChildStateMu.Lock()
	defer nodeLinkChildStateMu.Unlock()
	if nodeLinkChildState != nil {
		return nodeLinkChildState
	}
	var state NodeLinkChildState
	exists, err := readNodeLinkFile(nodeLinkStatePath(nodeLinkChildFile), &state)
	if err != nil || !exists || state.Role != NodeLinkRoleChild {
		return nil
	}
	nodeLinkChildState = &state
	return nodeLinkChildState
}

func saveNodeLinkChildState(state *NodeLinkChildState) error {
	nodeLinkChildStateMu.Lock()
	defer nodeLinkChildStateMu.Unlock()
	if err := writeNodeLinkFile(nodeLinkStatePath(nodeLinkChildFile), state); err != nil {
		return err
	}
	nodeLinkChildState = state
	return nil
}

func clearNodeLinkChildState() error {
	nodeLinkChildStateMu.Lock()
	defer nodeLinkChildStateMu.Unlock()
	nodeLinkChildState = nil
	if err := os.Remove(nodeLinkStatePath(nodeLinkChildFile)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// GetNodeLinkMasterState returns the persisted master-side link state, or nil
// when this node has never accepted a child.
func GetNodeLinkMasterState() *NodeLinkMasterState {
	nodeLinkMasterStateMu.Lock()
	defer nodeLinkMasterStateMu.Unlock()
	if nodeLinkMasterState != nil {
		return nodeLinkMasterState
	}
	var state NodeLinkMasterState
	exists, err := readNodeLinkFile(nodeLinkStatePath(nodeLinkMasterFile), &state)
	if err != nil || !exists || state.Role != NodeLinkRoleMaster {
		return nil
	}
	nodeLinkMasterState = &state
	return nodeLinkMasterState
}

func saveNodeLinkMasterState(state *NodeLinkMasterState) error {
	nodeLinkMasterStateMu.Lock()
	defer nodeLinkMasterStateMu.Unlock()
	if err := writeNodeLinkFile(nodeLinkStatePath(nodeLinkMasterFile), state); err != nil {
		return err
	}
	nodeLinkMasterState = state
	return nil
}

// nodeLinkWSWriter adapts a websocket connection to io.Writer so database
// protocol bytes can be piped with io.Copy in both bridge directions.
type nodeLinkWSWriter struct{ conn *websocket.Conn }

func (w nodeLinkWSWriter) Write(p []byte) (int, error) {
	if err := w.conn.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}
