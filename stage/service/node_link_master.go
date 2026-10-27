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
	"time"

	"github.com/QuantumNous/new-api/common"
	sqlmysql "github.com/go-sql-driver/mysql"

	"github.com/gin-gonic/gin"
	"github.com/gorilla/websocket"
)

// Master-side node link. The master keeps using its own database; children
// register with a pairing token and reach the master database through the
// tunnel endpoint below.

var nodeLinkTunnelUpgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// GenerateNodeLinkToken creates a new pairing token children present when
// registering.
func GenerateNodeLinkToken() (string, error) {
	state := GetNodeLinkMasterState()
	if state == nil {
		state = &NodeLinkMasterState{Role: NodeLinkRoleMaster}
	} else {
		copied := *state
		copied.Tokens = append([]string(nil), state.Tokens...)
		copied.Children = append([]NodeLinkChildRecord(nil), state.Children...)
		state = &copied
	}
	token := "nlk-" + common.GetRandomString(32)
	state.Tokens = append(state.Tokens, token)
	if err := saveNodeLinkMasterState(state); err != nil {
		return "", err
	}
	return token, nil
}

func findNodeLinkChildByToken(state *NodeLinkMasterState, token string) *NodeLinkChildRecord {
	for i := range state.Children {
		if state.Children[i].Token == token {
			return &state.Children[i]
		}
	}
	return nil
}

type nodeLinkDBTarget struct {
	dbType   string
	host     string
	port     string
	user     string
	password string
	database string
	params   string
}

// masterDatabaseTunnelTarget parses the master's primary database DSN into
// the dial target and credentials shared with children. SQLite has no TCP
// endpoint and cannot be shared through the tunnel.
func masterDatabaseTunnelTarget() (*nodeLinkDBTarget, error) {
	dsn := os.Getenv("SQL_DSN")
	var info *nodeLinkDBTarget
	switch common.MainDatabaseType() {
	case common.DatabaseTypeMySQL:
		cfg, err := sqlmysql.ParseDSN(dsn)
		if err != nil {
			return nil, fmt.Errorf("解析主节点 MySQL DSN 失败: %w", err)
		}
		host, port, splitErr := net.SplitHostPort(cfg.Addr)
		if splitErr != nil {
			host, port = cfg.Addr, "3306"
		}
		info = &nodeLinkDBTarget{
			dbType: "mysql", host: host, port: port,
			user: cfg.User, password: cfg.Passwd, database: cfg.DBName,
			params: "charset=utf8mb4&parseTime=True&loc=Local",
		}
	case common.DatabaseTypePostgreSQL:
		parsed, err := url.Parse(dsn)
		if err != nil {
			return nil, fmt.Errorf("解析主节点 PostgreSQL DSN 失败: %w", err)
		}
		port := parsed.Port()
		if port == "" {
			port = "5432"
		}
		info = &nodeLinkDBTarget{dbType: "postgres", host: parsed.Hostname(), port: port}
		if parsed.User != nil {
			info.user = parsed.User.Username()
			info.password, _ = parsed.User.Password()
		}
		info.database = strings.TrimPrefix(parsed.Path, "/")
	default:
		return nil, fmt.Errorf("主节点数据库为 SQLite，节点互联隧道要求主节点使用 MySQL 或 PostgreSQL")
	}
	if info.host == "" || info.user == "" || info.database == "" {
		return nil, fmt.Errorf("主节点数据库 DSN 缺少主机、用户或库名，无法建立隧道")
	}
	return info, nil
}

// NodeLinkRegisterChild validates a pairing token, auto-derives the master
// role when this node has no link configured yet, and registers the child.
// It returns the database credentials the child must use through its local
// tunnel listener.
func NodeLinkRegisterChild(name, token, dbMode, version, hostname string) (map[string]any, error) {
	if strings.TrimSpace(name) == "" {
		return nil, fmt.Errorf("子节点名称不能为空")
	}
	if dbMode != NodeLinkDBModeOverwrite && dbMode != NodeLinkDBModeMerge {
		return nil, fmt.Errorf("数据库保留模式必须是 overwrite 或 merge")
	}
	state := GetNodeLinkMasterState()
	if state == nil {
		state = &NodeLinkMasterState{Role: NodeLinkRoleMaster}
	}
	tokenKnown := false
	for _, known := range state.Tokens {
		if known == token {
			tokenKnown = true
			break
		}
	}
	if !tokenKnown {
		return nil, fmt.Errorf("配对令牌无效")
	}

	target, err := masterDatabaseTunnelTarget()
	if err != nil {
		return nil, err
	}

	now := common.GetTimestamp()
	copied := *state
	copied.Role = NodeLinkRoleMaster
	copied.Tokens = append([]string(nil), state.Tokens...)
	copied.Children = append([]NodeLinkChildRecord(nil), state.Children...)
	if existing := findNodeLinkChildByToken(&copied, token); existing != nil {
		existing.Name = name
		existing.DBMode = dbMode
		existing.Version = version
		existing.Hostname = hostname
		existing.LastSeenAt = now
	} else {
		copied.Children = append(copied.Children, NodeLinkChildRecord{
			Name: name, Token: token, DBMode: dbMode, Version: version,
			Hostname: hostname, RegisteredAt: now, LastSeenAt: now,
		})
	}
	if err := saveNodeLinkMasterState(&copied); err != nil {
		return nil, err
	}

	masterName := common.NodeName
	if strings.TrimSpace(masterName) == "" {
		if hostname, hostErr := os.Hostname(); hostErr == nil {
			masterName = hostname
		}
	}
	return map[string]any{
		"master_name": masterName,
		"db": map[string]any{
			"type":     target.dbType,
			"user":     target.user,
			"password": target.password,
			"database": target.database,
			"params":   target.params,
		},
	}, nil
}

// NodeLinkChildHeartbeat refreshes a child's last-seen timestamp.
func NodeLinkChildHeartbeat(token string) error {
	state := GetNodeLinkMasterState()
	if state == nil {
		return fmt.Errorf("本节点未配置任何节点互联")
	}
	copied := *state
	copied.Children = append([]NodeLinkChildRecord(nil), state.Children...)
	child := findNodeLinkChildByToken(&copied, token)
	if child == nil {
		return fmt.Errorf("子节点未注册")
	}
	child.LastSeenAt = common.GetTimestamp()
	return saveNodeLinkMasterState(&copied)
}

// NodeLinkRemoveChild revokes a child; its tunnel connections stop working.
func NodeLinkRemoveChild(name string) error {
	state := GetNodeLinkMasterState()
	if state == nil {
		return fmt.Errorf("本节点未配置任何节点互联")
	}
	copied := *state
	copied.Children = make([]NodeLinkChildRecord, 0, len(state.Children))
	for _, child := range state.Children {
		if child.Name != name {
			copied.Children = append(copied.Children, child)
		}
	}
	return saveNodeLinkMasterState(&copied)
}

// DialMasterDatabaseTarget dials the master's own database endpoint for one
// tunnelled connection.
func DialMasterDatabaseTarget() (net.Conn, error) {
	target, err := masterDatabaseTunnelTarget()
	if err != nil {
		return nil, err
	}
	conn, dialErr := net.DialTimeout("tcp", net.JoinHostPort(target.host, target.port), 10*time.Second)
	if dialErr != nil {
		return nil, fmt.Errorf("连接主节点数据库失败: %w", dialErr)
	}
	return conn, nil
}

// NodeLinkTunnelHandler upgrades a child connection and bridges it to the
// master database. Each tunnelled TCP connection maps to one database
// connection; the protocol inside is opaque bytes.
func NodeLinkTunnelHandler(c *gin.Context) {
	token := c.Query("token")
	if token == "" {
		token = strings.TrimPrefix(c.GetHeader("Authorization"), "Bearer ")
	}
	state := GetNodeLinkMasterState()
	if state == nil || findNodeLinkChildByToken(state, token) == nil {
		c.JSON(http.StatusUnauthorized, gin.H{"success": false, "message": "节点互联令牌无效"})
		return
	}
	_ = NodeLinkChildHeartbeat(token)

	wsConn, err := nodeLinkTunnelUpgrader.Upgrade(c.Writer, c.Request, nil)
	if err != nil {
		return
	}
	defer wsConn.Close()

	dbConn, err := DialMasterDatabaseTarget()
	if err != nil {
		common.SysError("node link tunnel db dial failed: " + err.Error())
		_ = wsConn.WriteControl(websocket.CloseMessage,
			websocket.FormatCloseMessage(4000, err.Error()), time.Now().Add(time.Second))
		return
	}
	defer dbConn.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		defer wsConn.Close()
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
	wsConn.Close()
	<-done
	_ = NodeLinkChildHeartbeat(token)
}

// NodeLinkPushAdopt registers a reachable remote node as a child: this master
// pushes its pairing info to the remote adopt endpoint using the remote
// operator's root access token. The remote auto-derives its child role and
// dials back with an outbound-only tunnel.
func NodeLinkPushAdopt(remoteURL, remoteAccessToken, name, dbMode, masterURL string) error {
	if strings.TrimSpace(remoteURL) == "" || strings.TrimSpace(remoteAccessToken) == "" {
		return fmt.Errorf("远端地址和远端 root 访问令牌不能为空")
	}
	if dbMode != NodeLinkDBModeOverwrite && dbMode != NodeLinkDBModeMerge {
		return fmt.Errorf("数据库保留模式必须是 overwrite 或 merge")
	}
	state := GetNodeLinkMasterState()
	var token string
	if state != nil && len(state.Tokens) > 0 {
		token = state.Tokens[len(state.Tokens)-1]
	} else {
		generated, err := GenerateNodeLinkToken()
		if err != nil {
			return err
		}
		token = generated
	}
	endpoint := strings.TrimSuffix(remoteURL, "/") + "/api/node_link/adopt"
	payload, _ := json.Marshal(map[string]string{
		"master_url": masterURL,
		"token":      token,
		"name":       name,
		"db_mode":    dbMode,
	})
	req, err := http.NewRequest(http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", remoteAccessToken)
	// The adopt may run a database merge before answering, so allow a long
	// round trip.
	resp, err := (&http.Client{Timeout: 10 * time.Minute}).Do(req)
	if err != nil {
		return fmt.Errorf("连接远端节点失败: %w", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var parsed struct {
		Success bool   `json:"success"`
		Message string `json:"message"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return fmt.Errorf("远端响应解析失败 (HTTP %d): %s", resp.StatusCode, string(body))
	}
	if !parsed.Success {
		message := parsed.Message
		if message == "" {
			message = string(body)
		}
		return fmt.Errorf("远端拒绝接入: %s", message)
	}
	return nil
}
