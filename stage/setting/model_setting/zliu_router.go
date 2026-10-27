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

package model_setting

import (
	"github.com/QuantumNous/new-api/setting/config"
)

// ZliuRouterSettings 配置 zliu 微路由：把一个虚拟模型（默认 zliu-auto）的请求交给
// 本机路由器判定，动态改写成"快模型/强模型"两者之一，再走正常的渠道选择与计费。
//
// 路由器是独立的 C++ 服务（HTTP，POST /route），只做判定不代发上游请求；
// 判定基于每会话 EMA 上下文，故需要一个稳定的 session 键（见 service 层解析顺序）。
// 整套能力默认关闭（Enabled=false），且只在请求模型名等于 TriggerModel 时才介入，
// 对其余所有模型零影响。任何失败都不阻断请求，按 FailOpenTarget 兜底成真实模型。
type ZliuRouterSettings struct {
	Enabled bool `json:"enabled"`
	// EndpointURL 路由器 HTTP 判定端点，形如 http://127.0.0.1:18081/route（仅本机）。
	EndpointURL string `json:"endpoint_url"`
	// TriggerModel 触发路由的虚拟模型名；仅当请求模型名与其完全相等时才介入。
	TriggerModel string `json:"trigger_model"`
	// FastModel / StrongModel：路由器 target=="opus" 映射到 StrongModel，其余映射到 FastModel。
	FastModel   string `json:"fast_model"`
	StrongModel string `json:"strong_model"`
	// SessionHeader 会话键请求头（首选来源）；为空则跳过，退到请求体 user 字段、再退到首条消息哈希。
	SessionHeader string `json:"session_header"`
	// TimeoutMs 调用路由器的超时（毫秒）；超时按 FailOpenTarget 兜底。
	TimeoutMs int `json:"timeout_ms"`
	// FailOpenTarget 判定失败时的兜底目标："strong"（默认，不降级质量）或 "fast"。
	FailOpenTarget string `json:"fail_open_target"`
}

var defaultZliuRouterSettings = ZliuRouterSettings{
	Enabled:        false,
	EndpointURL:    "http://127.0.0.1:18081/route",
	TriggerModel:   "zliu-auto",
	FastModel:      "deepseek-chat",
	StrongModel:    "claude-opus-4",
	SessionHeader:  "X-Zliu-Session",
	TimeoutMs:      300,
	FailOpenTarget: "strong",
}

var zliuRouterSettings = defaultZliuRouterSettings

func init() {
	config.GlobalConfig.Register("zliu_router", &zliuRouterSettings)
}

func GetZliuRouterSettings() *ZliuRouterSettings {
	return &zliuRouterSettings
}

// ModelForTarget 把路由器返回的 target 映射成真实模型名。
// 约定：target=="opus" 走强模型，其余（含 "deepseek"、空串）走快模型。
func (s *ZliuRouterSettings) ModelForTarget(target string) string {
	if target == "opus" {
		return s.StrongModel
	}
	return s.FastModel
}

// FailOpenModel 返回判定失败时应改写成的真实模型名。
func (s *ZliuRouterSettings) FailOpenModel() string {
	if s.FailOpenTarget == "fast" {
		return s.FastModel
	}
	return s.StrongModel
}
