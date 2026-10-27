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
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"

	"github.com/gorilla/websocket"
	gormmysql "gorm.io/driver/mysql"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

// Child-side node link. The child dials the master (outbound only, so it
// needs no public IP), registers with a pairing token, and exposes the master
// database on a 127.0.0.1 listener through the websocket tunnel; its own
// database connection is then re-pointed at that listener.

var (
	nodeLinkTunnelListener net.Listener
	nodeLinkTunnelMu       sync.Mutex
)

type nodeLinkRegisterResponse struct {
	Success    bool   `json:"success"`
	Message    string `json:"message"`
	MasterName string `json:"master_name"`
	Data       struct {
		MasterName string `json:"master_name"`
		DB         struct {
			Type     string `json:"type"`
			User     string `json:"user"`
			Password string `json:"password"`
			Database string `json:"database"`
			Params   string `json:"params"`
		} `json:"db"`
	} `json:"data"`
}

func nodeLinkPostRegister(masterURL, token, name, dbMode string) (*nodeLinkRegisterResponse, error) {
	endpoint := strings.TrimSuffix(masterURL, "/") + "/api/node_link/register"
	payload, _ := json.Marshal(map[string]string{
		"token":    token,
		"name":     name,
		"db_mode":  dbMode,
		"version":  common.Version,
		"hostname": localHostname(),
	})
	resp, err := (&http.Client{Timeout: 30 * time.Second}).Post(endpoint, "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, fmt.Errorf("连接主节点失败: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var parsed nodeLinkRegisterResponse
	if err := json.Unmarshal(body, &parsed); err != nil {
		return nil, fmt.Errorf("主节点响应解析失败 (HTTP %d): %s", resp.StatusCode, string(body))
	}
	if !parsed.Success {
		message := parsed.Message
		if message == "" {
			message = string(body)
		}
		return nil, fmt.Errorf("主节点拒绝注册: %s", message)
	}
	return &parsed, nil
}

func localHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return ""
	}
	return hostname
}

// buildTunnelDSN composes the child's effective database DSN: the master's
// credentials against the local tunnel listener.
func buildTunnelDSN(dbType, user, password, database, params string, listenPort int) (string, error) {
	switch dbType {
	case "mysql":
		if params == "" {
			params = "charset=utf8mb4&parseTime=True&loc=Local"
		}
		return fmt.Sprintf("%s:%s@tcp(127.0.0.1:%d)/%s?%s", user, password, listenPort, database, params), nil
	case "postgres":
		return fmt.Sprintf("postgres://%s:%s@127.0.0.1:%d/%s?sslmode=disable", url.PathEscape(user), url.PathEscape(password), listenPort, database), nil
	default:
		return "", fmt.Errorf("主节点数据库类型 %s 不支持隧道", dbType)
	}
}

// startNodeLinkTunnelListener binds 127.0.0.1 and bridges every accepted TCP
// connection to the master tunnel endpoint over websocket.
func startNodeLinkTunnelListener(masterURL, token string) (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, fmt.Errorf("启动本地隧道监听失败: %w", err)
	}
	go acceptNodeLinkTunnelConns(listener, masterURL, token)
	return listener.Addr().(*net.TCPAddr).Port, nil
}

func acceptNodeLinkTunnelConns(listener net.Listener, masterURL, token string) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go bridgeNodeLinkConn(conn, masterURL, token)
	}
}

// nodeLinkTunnelWSURL converts the master HTTP base URL into the tunnel
// websocket endpoint (https -> wss, http -> ws).
func nodeLinkTunnelWSURL(masterURL, token string) string {
	endpoint := strings.TrimSuffix(masterURL, "/") + "/api/node_link/tunnel?token=" + url.QueryEscape(token)
	if strings.HasPrefix(endpoint, "https://") {
		return "wss://" + strings.TrimPrefix(endpoint, "https://")
	}
	return "ws://" + strings.TrimPrefix(endpoint, "http://")
}

func bridgeNodeLinkConn(dbConn net.Conn, masterURL, token string) {
	defer dbConn.Close()
	wsConn, _, err := websocket.DefaultDialer.Dial(nodeLinkTunnelWSURL(masterURL, token), nil)
	if err != nil {
		common.SysError("node link tunnel dial failed: " + err.Error())
		return
	}
	defer wsConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer dbConn.Close()
		// websocket -> database
		for {
			_, message, err := wsConn.ReadMessage()
			if err != nil {
				return
			}
			if _, err := dbConn.Write(message); err != nil {
				return
			}
		}
	}()
	// database -> websocket
	_, _ = io.Copy(nodeLinkWSWriter{conn: wsConn}, dbConn)
	<-done
}

// swapNodeLinkDatabase replaces the process-wide database handles with a pool
// opened on the tunnel DSN. In-flight requests keep their old pool until they
// release it.
func swapNodeLinkDatabase(tunnelDSN string) error {
	db, err := gorm.Open(openNodeLinkDialector(tunnelDSN), &gorm.Config{})
	if err != nil {
		return fmt.Errorf("通过隧道连接主节点数据库失败: %w", err)
	}
	sqlDB, err := db.DB()
	if err != nil {
		return err
	}
	sqlDB.SetMaxOpenConns(64)
	sqlDB.SetMaxIdleConns(16)

	previousDB, previousLogDB := model.DB, model.LOG_DB
	model.DB = db
	model.LOG_DB = db
	if previousDB != nil {
		if sqlPrevious, err := previousDB.DB(); err == nil {
			go func() {
				time.Sleep(30 * time.Second)
				_ = sqlPrevious.Close()
			}()
		}
	}
	if previousLogDB != nil && previousLogDB != previousDB {
		if sqlPrevious, err := previousLogDB.DB(); err == nil {
			go func() {
				time.Sleep(30 * time.Second)
				_ = sqlPrevious.Close()
			}()
		}
	}
	// Options and pricing caches were loaded from the local database; reload
	// them from the master's database now that handles are swapped.
	model.InitOptionMap()
	return nil
}

// NodeLinkConnect activates the child link: register with the master, run the
// chosen database retention mode, start the tunnel listener and switch the
// process database handles to the master database.
func NodeLinkConnect(masterURL, token, name, dbMode string) error {
	if strings.TrimSpace(masterURL) == "" || strings.TrimSpace(token) == "" {
		return fmt.Errorf("主节点地址和配对令牌不能为空")
	}
	if GetNodeLinkChildState() != nil {
		return fmt.Errorf("本节点已配置子节点连接，请先断开后再重新连接")
	}
	if GetNodeLinkMasterState() != nil {
		return fmt.Errorf("本节点已作为主节点配置了节点互联，请先移除子节点后再接入")
	}
	if common.MainDatabaseType() == common.DatabaseTypeSQLite {
		return fmt.Errorf("子节点为 SQLite 时无法执行数据库保留模式，请先切换到 MySQL 或 PostgreSQL")
	}
	response, err := nodeLinkPostRegister(masterURL, token, name, dbMode)
	if err != nil {
		return err
	}

	listenPort, err := startNodeLinkTunnelListener(masterURL, token)
	if err != nil {
		return err
	}
	tunnelDSN, err := buildTunnelDSN(
		response.Data.DB.Type, response.Data.DB.User, response.Data.DB.Password,
		response.Data.DB.Database, response.Data.DB.Params, listenPort,
	)
	if err != nil {
		return err
	}

	originalDSN := os.Getenv("SQL_DSN")
	switch dbMode {
	case NodeLinkDBModeMerge:
		masterDB, openErr := gorm.Open(openNodeLinkDialector(tunnelDSN), &gorm.Config{})
		if openErr != nil {
			stopNodeLinkTunnelListener()
			return fmt.Errorf("通过隧道打开主节点数据库失败: %w", openErr)
		}
		report, mergeErr := mergeLocalDatabaseInto(masterDB)
		sqlMaster, _ := masterDB.DB()
		if sqlMaster != nil {
			_ = sqlMaster.Close()
		}
		if mergeErr != nil {
			stopNodeLinkTunnelListener()
			return fmt.Errorf("合并同步失败: %w", mergeErr)
		}
		common.SysLog(fmt.Sprintf("node link merge finished: %+v", report))
	case NodeLinkDBModeOverwrite:
		// The local database is abandoned as-is; nothing to do before the swap.
	}

	state := &NodeLinkChildState{
		Role:        NodeLinkRoleChild,
		MasterURL:   strings.TrimSuffix(masterURL, "/"),
		Token:       token,
		DBMode:      dbMode,
		NodeName:    name,
		TunnelDSN:   tunnelDSN,
		LocalDSN:    originalDSN,
		ListenPort:  listenPort,
		Connected:   true,
		MasterName:  response.Data.MasterName,
		ConnectedAt: common.GetTimestamp(),
	}
	if err := swapNodeLinkDatabase(tunnelDSN); err != nil {
		stopNodeLinkTunnelListener()
		return err
	}
	return saveNodeLinkChildState(state)
}

// NodeLinkAdopt applies a master-initiated link: the remote master pushed its
// address and pairing token, so this node becomes a child automatically.
func NodeLinkAdopt(masterURL, token, name, dbMode string) error {
	if GetNodeLinkMasterState() != nil {
		return fmt.Errorf("本节点已作为主节点配置了节点互联，请先移除子节点后再接入")
	}
	if existing := GetNodeLinkChildState(); existing != nil {
		return fmt.Errorf("本节点已配置子节点连接，请先断开后再接入")
	}
	return NodeLinkConnect(masterURL, token, name, dbMode)
}

// NodeLinkDisconnect deactivates the child link and restores the original
// database connection. Data already written to the master stays there.
func NodeLinkDisconnect() error {
	state := GetNodeLinkChildState()
	if state == nil {
		return fmt.Errorf("本节点未配置子节点连接")
	}
	stopNodeLinkTunnelListener()
	if state.LocalDSN != "" {
		if err := swapNodeLinkDatabase(state.LocalDSN); err != nil {
			return fmt.Errorf("恢复本地数据库连接失败: %w", err)
		}
	}
	return clearNodeLinkChildState()
}

func stopNodeLinkTunnelListener() {
	nodeLinkTunnelMu.Lock()
	defer nodeLinkTunnelMu.Unlock()
	if nodeLinkTunnelListener != nil {
		_ = nodeLinkTunnelListener.Close()
		nodeLinkTunnelListener = nil
	}
}

// ActivateNodeLinkOnBoot re-arms the tunnel listener and returns the DSN the
// process should boot with when a child link is configured.
func ActivateNodeLinkOnBoot() (string, bool) {
	state := GetNodeLinkChildState()
	if state == nil || !state.Connected || state.TunnelDSN == "" {
		return "", false
	}
	nodeLinkTunnelMu.Lock()
	defer nodeLinkTunnelMu.Unlock()
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", state.ListenPort))
	if err != nil {
		common.SysError("node link tunnel listener failed to start: " + err.Error())
		return "", false
	}
	nodeLinkTunnelListener = listener
	go acceptNodeLinkTunnelConns(listener, state.MasterURL, state.Token)
	common.SysLog(fmt.Sprintf("node link tunnel listening on 127.0.0.1:%d, master=%s", state.ListenPort, state.MasterURL))
	return state.TunnelDSN, true
}

func openNodeLinkDialector(dsn string) gorm.Dialector {
	if strings.HasPrefix(dsn, "postgres://") || strings.HasPrefix(dsn, "postgresql://") {
		return postgres.New(postgres.Config{DSN: dsn, PreferSimpleProtocol: true})
	}
	return gormmysql.Open(dsn)
}
