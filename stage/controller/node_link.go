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

package controller

import (
	"net/http"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/service"

	"github.com/gin-gonic/gin"
)

// Node link APIs. The dashboard endpoints require root; the register, tunnel
// and adopt endpoints authenticate with pairing tokens or the remote node's
// root access token because they are called by peer servers, not browsers.

type nodeLinkConnectRequest struct {
	MasterURL string `json:"master_url"`
	Token     string `json:"token"`
	Name      string `json:"name"`
	DBMode    string `json:"db_mode"`
}

func GetNodeLinkStatus(c *gin.Context) {
	data := gin.H{
		"role":      "none",
		"node_name": common.NodeName,
		"version":   common.Version,
	}
	if child := service.GetNodeLinkChildState(); child != nil {
		data["role"] = service.NodeLinkRoleChild
		data["child"] = gin.H{
			"master_url":   child.MasterURL,
			"master_name":  child.MasterName,
			"db_mode":      child.DBMode,
			"node_name":    child.NodeName,
			"listen_port":  child.ListenPort,
			"connected":    child.Connected,
			"connected_at": child.ConnectedAt,
			"has_local":    child.LocalDSN != "",
		}
	}
	if master := service.GetNodeLinkMasterState(); master != nil {
		children := make([]gin.H, 0, len(master.Children))
		for _, child := range master.Children {
			children = append(children, gin.H{
				"name":          child.Name,
				"db_mode":       child.DBMode,
				"version":       child.Version,
				"hostname":      child.Hostname,
				"registered_at": child.RegisteredAt,
				"last_seen_at":  child.LastSeenAt,
			})
		}
		tokens := make([]string, 0, len(master.Tokens))
		tokens = append(tokens, master.Tokens...)
		data["role"] = service.NodeLinkRoleMaster
		data["master"] = gin.H{"children": children, "tokens": tokens}
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": data})
}

func CreateNodeLinkToken(c *gin.Context) {
	token, err := service.GenerateNodeLinkToken()
	if err != nil {
		common.ApiError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": gin.H{"token": token}})
}

func ConnectNodeLink(c *gin.Context) {
	var req nodeLinkConnectRequest
	if err := common.DecodeJson(c.Request.Body, &req); err != nil {
		common.ApiErrorI18n(c, i18n.MsgInvalidParams)
		return
	}
	if err := service.NodeLinkConnect(req.MasterURL, req.Token, req.Name, req.DBMode); err != nil {
		common.ApiError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func PushAdoptNodeLink(c *gin.Context) {
	var req struct {
		RemoteURL         string `json:"remote_url"`
		RemoteAccessToken string `json:"remote_access_token"`
		Name              string `json:"name"`
		DBMode            string `json:"db_mode"`
		MasterURL         string `json:"master_url"`
	}
	if err := common.DecodeJson(c.Request.Body, &req); err != nil {
		common.ApiErrorI18n(c, i18n.MsgInvalidParams)
		return
	}
	if err := service.NodeLinkPushAdopt(req.RemoteURL, req.RemoteAccessToken, req.Name, req.DBMode, req.MasterURL); err != nil {
		common.ApiError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func AdoptNodeLink(c *gin.Context) {
	var req nodeLinkConnectRequest
	if err := common.DecodeJson(c.Request.Body, &req); err != nil {
		common.ApiErrorI18n(c, i18n.MsgInvalidParams)
		return
	}
	if err := service.NodeLinkAdopt(req.MasterURL, req.Token, req.Name, req.DBMode); err != nil {
		common.ApiError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func DisconnectNodeLink(c *gin.Context) {
	if err := service.NodeLinkDisconnect(); err != nil {
		common.ApiError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

func RemoveNodeLinkChild(c *gin.Context) {
	name := strings.TrimSpace(c.Param("name"))
	if name == "" {
		common.ApiErrorMsg(c, "子节点名称不能为空")
		return
	}
	if err := service.NodeLinkRemoveChild(name); err != nil {
		common.ApiError(c, err)
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true})
}

// RegisterNodeLink is called by a child node dialing out to this master.
func RegisterNodeLink(c *gin.Context) {
	var req struct {
		Token    string `json:"token"`
		Name     string `json:"name"`
		DBMode   string `json:"db_mode"`
		Version  string `json:"version"`
		Hostname string `json:"hostname"`
	}
	if err := common.DecodeJson(c.Request.Body, &req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": "invalid params"})
		return
	}
	data, err := service.NodeLinkRegisterChild(req.Name, req.Token, req.DBMode, req.Version, req.Hostname)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"success": false, "message": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"success": true, "data": data})
}
