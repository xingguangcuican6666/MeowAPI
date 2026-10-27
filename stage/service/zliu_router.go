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
	"context"
	"crypto/sha1"
	"encoding/hex"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/setting/model_setting"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
)

// zliu 微路由客户端：把 zliu-auto 虚拟模型的请求交给本机路由器判定，返回应改写成的
// 真实模型名。路由器只做判定不代发上游；判定基于每会话服务端累积的 EMA 上下文，因此
// 每次只喂"本轮增量"消息 + 上一条消息正文（prev_turn_text），并附一个稳定的 session 键。
//
// 该客户端永不返回错误：任何失败（超时、连接失败、路由器报错）都按 FailOpenModel 兜底，
// 绝不阻断用户请求。只有在真正拿到 target 时 decided 才为 true。

type zliuRouterMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type zliuRouterRequest struct {
	SessionID    string              `json:"session_id"`
	Messages     []zliuRouterMessage `json:"messages"`
	PrevTurnText string              `json:"prev_turn_text,omitempty"`
	UpdateState  bool                `json:"update_state"`
}

// ResolveZliuRouteModel 为一条 zliu-auto 请求判定应使用的真实模型名。
// bodyBytes 为请求体原文（JSON）。第二个返回值表示路由器是否真正给出了判定。
func ResolveZliuRouteModel(c *gin.Context, bodyBytes []byte) (string, bool) {
	s := model_setting.GetZliuRouterSettings()

	msgs, prevTurn := extractZliuTurn(bodyBytes)
	reqBody, err := common.Marshal(zliuRouterRequest{
		SessionID:    resolveZliuSession(c, bodyBytes, s.SessionHeader),
		Messages:     msgs,
		PrevTurnText: prevTurn,
		UpdateState:  true,
	})
	if err != nil {
		logger.LogWarn(c, "zliu_router: marshal request failed: "+err.Error())
		return s.FailOpenModel(), false
	}

	timeout := time.Duration(s.TimeoutMs) * time.Millisecond
	if timeout <= 0 {
		timeout = 300 * time.Millisecond
	}
	ctx, cancel := context.WithTimeout(c.Request.Context(), timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, s.EndpointURL, bytes.NewReader(reqBody))
	if err != nil {
		logger.LogWarn(c, "zliu_router: build request failed: "+err.Error())
		return s.FailOpenModel(), false
	}
	req.Header.Set("Content-Type", "application/json")

	// 端点是运营方配置的本机地址（非用户可控），用普通出站客户端，不走 SSRF 拦截。
	resp, err := GetHttpClient().Do(req)
	if err != nil {
		logger.LogWarn(c, "zliu_router: call failed, fail-open: "+err.Error())
		return s.FailOpenModel(), false
	}
	defer resp.Body.Close()

	respBytes, err := io.ReadAll(io.LimitReader(resp.Body, 1<<16))
	if err != nil || resp.StatusCode != http.StatusOK {
		logger.LogWarn(c, "zliu_router: bad response status, fail-open")
		return s.FailOpenModel(), false
	}

	target := gjson.GetBytes(respBytes, "target").String()
	if target == "" {
		logger.LogWarn(c, "zliu_router: no target in response, fail-open: "+gjson.GetBytes(respBytes, "error").String())
		return s.FailOpenModel(), false
	}
	model := s.ModelForTarget(target)
	if model == "" {
		return s.FailOpenModel(), false
	}
	return model, true
}

// resolveZliuSession 按优先级解析会话键：请求头 -> 请求体 user / metadata.user_id ->
// 首条用户消息哈希（在一段会话内随轮次增长而保持稳定）-> "default"。
func resolveZliuSession(c *gin.Context, body []byte, header string) string {
	if header != "" {
		if v := strings.TrimSpace(c.GetHeader(header)); v != "" {
			return v
		}
	}
	if v := strings.TrimSpace(gjson.GetBytes(body, "user").String()); v != "" {
		return "u:" + v
	}
	if v := strings.TrimSpace(gjson.GetBytes(body, "metadata.user_id").String()); v != "" {
		return "u:" + v
	}
	if first := firstMessageText(body); first != "" {
		sum := sha1.Sum([]byte(first))
		return "h:" + hex.EncodeToString(sum[:8])
	}
	return "default"
}

// extractZliuTurn 从完整历史里切出"本轮增量"（最后一条 assistant/model 消息之后的所有消息），
// 并返回该增量之前最后一条消息的正文作为 prev_turn_text。兼容 OpenAI / Anthropic 两种消息体。
func extractZliuTurn(body []byte) ([]zliuRouterMessage, string) {
	arr := gjson.GetBytes(body, "messages").Array()
	if len(arr) == 0 {
		return nil, ""
	}
	lastAssistant := -1
	for i, m := range arr {
		if role := m.Get("role").String(); role == "assistant" || role == "model" {
			lastAssistant = i
		}
	}
	var msgs []zliuRouterMessage
	for i := lastAssistant + 1; i < len(arr); i++ {
		role := arr[i].Get("role").String()
		if role == "" {
			role = "user"
		}
		msgs = append(msgs, zliuRouterMessage{Role: role, Content: zliuMessageText(arr[i].Get("content"))})
	}
	prevTurn := ""
	if lastAssistant >= 0 {
		prevTurn = zliuMessageText(arr[lastAssistant].Get("content"))
	}
	// 历史以 assistant 结尾时增量为空，退回最后一条消息，保证路由器至少有查询文本。
	if len(msgs) == 0 {
		last := arr[len(arr)-1]
		role := last.Get("role").String()
		if role == "" {
			role = "user"
		}
		msgs = append(msgs, zliuRouterMessage{Role: role, Content: zliuMessageText(last.Get("content"))})
	}
	return msgs, prevTurn
}

// zliuMessageText 取一条消息的文本：content 为字符串直接返回；为数组则拼接各 text 分片
// （OpenAI 的 {type:"text",text} 与 Anthropic 的 text block 同形）。
func zliuMessageText(content gjson.Result) string {
	if content.Type == gjson.String {
		return content.String()
	}
	if content.IsArray() {
		var b strings.Builder
		for _, part := range content.Array() {
			if t := part.Get("text"); t.Exists() {
				if b.Len() > 0 {
					b.WriteByte('\n')
				}
				b.WriteString(t.String())
			}
		}
		return b.String()
	}
	return ""
}

func firstMessageText(body []byte) string {
	arr := gjson.GetBytes(body, "messages").Array()
	for _, m := range arr {
		if m.Get("role").String() == "user" {
			if t := zliuMessageText(m.Get("content")); t != "" {
				return t
			}
		}
	}
	if len(arr) > 0 {
		return zliuMessageText(arr[0].Get("content"))
	}
	return ""
}
