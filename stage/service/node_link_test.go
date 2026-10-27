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
	"fmt"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/gorilla/websocket"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func setupNodeLinkTest(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	previousDir, _ := os.Getwd()
	require.NoError(t, os.Chdir(dir))
	t.Cleanup(func() { _ = os.Chdir(previousDir) })
	gin.SetMode(gin.TestMode)

	// Registration validates the master database tunnel target, so point the
	// DSN at a loopback placeholder and select the MySQL dialect.
	t.Setenv("SQL_DSN", "user:pass@tcp(127.0.0.1:33061)/masterdb?parseTime=true")
	previousMain, previousLog := common.MainDatabaseType(), common.LogDatabaseType()
	common.SetDatabaseTypes(common.DatabaseTypeMySQL, common.DatabaseTypeMySQL)
	t.Cleanup(func() { common.SetDatabaseTypes(previousMain, previousLog) })
}

func TestNodeLinkRegisterAutoDerivesMasterRole(t *testing.T) {
	setupNodeLinkTest(t)

	token, err := GenerateNodeLinkToken()
	require.NoError(t, err)
	assert.Equal(t, NodeLinkRoleMaster, GetNodeLinkMasterState().Role)

	_, err = NodeLinkRegisterChild("child-a", "bad-token", NodeLinkDBModeOverwrite, "test", "host-a")
	require.ErrorContains(t, err, "配对令牌无效")

	data, err := NodeLinkRegisterChild("child-a", token, NodeLinkDBModeMerge, "test", "host-a")
	require.NoError(t, err)
	expectedMasterName := common.NodeName
	if strings.TrimSpace(expectedMasterName) == "" {
		hostname, _ := os.Hostname()
		expectedMasterName = hostname
	}
	assert.Equal(t, expectedMasterName, data["master_name"])

	state := GetNodeLinkMasterState()
	require.NotNil(t, state)
	assert.Equal(t, NodeLinkRoleMaster, state.Role)
	require.Len(t, state.Children, 1)
	assert.Equal(t, "child-a", state.Children[0].Name)
	assert.Equal(t, NodeLinkDBModeMerge, state.Children[0].DBMode)
}

func TestNodeLinkTunnelBridgesDatabaseTraffic(t *testing.T) {
	setupNodeLinkTest(t)

	// Fake "database" upstream: echoes a marker so the bridge can be verified.
	fakeDB, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = fakeDB.Close() })
	go func() {
		for {
			conn, err := fakeDB.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				buf := make([]byte, 512)
				read, _ := conn.Read(buf)
				_, _ = conn.Write([]byte("db-ack:" + string(buf[:read])))
			}(conn)
		}
	}()
	host, port, _ := net.SplitHostPort(fakeDB.Addr().String())
	t.Setenv("SQL_DSN", fmt.Sprintf("user:pass@tcp(%s:%s)/masterdb?parseTime=true", host, port))

	token, err := GenerateNodeLinkToken()
	require.NoError(t, err)
	_, err = NodeLinkRegisterChild("child-a", token, NodeLinkDBModeOverwrite, "test", "host-a")
	require.NoError(t, err)

	gin.SetMode(gin.TestMode)
	router := gin.New()
	router.GET("/api/node_link/tunnel", NodeLinkTunnelHandler)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	listenPort, err := startNodeLinkTunnelListener(server.URL, token)
	require.NoError(t, err)

	// A rejected token must not upgrade the tunnel websocket.
	_, _, err = websocket.DefaultDialer.Dial(
		server.URL+"/api/node_link/tunnel?token=bad", nil)
	require.Error(t, err)

	// The tunnel path: client -> child listener -> websocket -> fake DB -> back.
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", listenPort))
	require.NoError(t, err)
	reply, err := bridgeAndEcho(conn, "ping")
	require.NoError(t, err)
	assert.Equal(t, "db-ack:ping", reply)
}

// bridgeAndEcho writes one request over the tunnel and reads the reply.
func bridgeAndEcho(conn net.Conn, request string) (string, error) {
	defer conn.Close()
	if _, err := conn.Write([]byte(request)); err != nil {
		return "", err
	}
	buf := make([]byte, 512)
	conn.SetReadDeadline(readDeadline())
	read, err := conn.Read(buf)
	if err != nil {
		return "", err
	}
	return string(buf[:read]), nil
}

func TestNodeLinkMergeRekeysAndResolvesConflicts(t *testing.T) {
	setupNodeLinkTest(t)

	openTempDB := func(name string) *gorm.DB {
		db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), name+".db")), &gorm.Config{})
		require.NoError(t, err)
		require.NoError(t, db.AutoMigrate(
			&model.Option{}, &model.Channel{}, &model.Ability{}, &model.User{}, &model.Token{},
		))
		return db
	}

	previousDB, previousLogDB := model.DB, model.LOG_DB
	t.Cleanup(func() {
		model.DB, model.LOG_DB = previousDB, previousLogDB
	})

	local := openTempDB("local")
	master := openTempDB("master")
	model.DB = local

	// Master state: one existing user, channel, token and the shared option.
	require.NoError(t, master.Create(&model.User{Id: 1, Username: "root", Email: "root@master", Group: "default", AffCode: "mst1"}).Error)
	require.NoError(t, master.Create(&model.Channel{Id: 1, Name: "master-channel", Models: "m", Group: "default"}).Error)
	require.NoError(t, master.Create(&model.Token{Id: 1, UserId: 1, Key: "master-key"}).Error)
	require.NoError(t, master.Create(&model.Option{Key: "shared", Value: "master"}).Error)

	// Child state: a distinct user with a token and channel, plus the shared
	// option (must not overwrite the master value) and a conflicting identity.
	require.NoError(t, local.Create(&model.Option{Key: "shared", Value: "child"}).Error)
	require.NoError(t, local.Create(&model.Option{Key: "child-only", Value: "v"}).Error)
	require.NoError(t, local.Create(&model.User{Id: 7, Username: "root", Email: "root@master", Group: "default", AffCode: "cld7"}).Error)
	require.NoError(t, local.Create(&model.User{Id: 8, Username: "alice", Email: "alice@child", Group: "default", AffCode: "cld8"}).Error)
	require.NoError(t, local.Create(&model.Token{Id: 3, UserId: 8, Key: "child-key"}).Error)
	require.NoError(t, local.Create(&model.Token{Id: 4, UserId: 8, Key: "master-key"}).Error)
	require.NoError(t, local.Create(&model.Channel{Id: 9, Name: "child-channel", Models: "m", Group: "default"}).Error)

	report, err := mergeLocalDatabaseInto(master)
	require.NoError(t, err)
	assert.EqualValues(t, 1, report.ChannelsAdded)
	assert.EqualValues(t, 1, report.UsersAdded)
	assert.EqualValues(t, 1, report.UsersSkipped)
	assert.EqualValues(t, 1, report.TokensAdded)
	assert.EqualValues(t, 1, report.TokensSkipped)

	var shared model.Option
	require.NoError(t, master.Where("key = ?", "shared").First(&shared).Error)
	assert.Equal(t, "master", shared.Value, "the master value must win on conflicts")
	var childOnly model.Option
	require.NoError(t, master.Where("key = ?", "child-only").First(&childOnly).Error)
	assert.Equal(t, "v", childOnly.Value)

	var alice model.User
	require.NoError(t, master.Where("username = ?", "alice").First(&alice).Error)
	assert.NotEqual(t, 8, alice.Id, "imported rows must be re-keyed")
	assert.NotEqual(t, 1, alice.Id)
	assert.NotEqual(t, "", alice.AffCode)

	var childToken model.Token
	require.NoError(t, master.Where("key = ?", "child-key").First(&childToken).Error)
	assert.Equal(t, alice.Id, childToken.UserId, "token ownership must follow the re-keyed user")

	var childChannel model.Channel
	require.NoError(t, master.Where("name = ?", "child-channel").First(&childChannel).Error)
	assert.NotEqual(t, 9, childChannel.Id, "imported channels must be re-keyed")
	var abilityCount int64
	require.NoError(t, master.Model(&model.Ability{}).Where("channel_id = ?", childChannel.Id).Count(&abilityCount).Error)
	assert.Positive(t, abilityCount, "imported channels must regenerate abilities")

	// Nothing on the master was modified or deleted.
	var masterUser model.User
	require.NoError(t, master.First(&masterUser, 1).Error)
	assert.Equal(t, "root", masterUser.Username)
	var masterToken model.Token
	require.NoError(t, master.Where("key = ?", "master-key").First(&masterToken).Error)
	assert.Equal(t, 1, masterToken.UserId)
}

func readDeadline() time.Time {
	return time.Now().Add(5 * time.Second)
}
