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

// Package data_capture 把经过网关的会话（请求体+响应体）以 JSONL 追加写入按天滚动的文件，
// 供离线训练数据采集使用。所有写入失败都静默降级（仅记录系统日志），绝不影响主请求链路。
package data_capture

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/setting/operation_setting"
)

// CaptureRecord 是落盘的单条会话记录。RequestBody 保留原始 JSON；ResponseBody 统一存字符串
// （流式为原始 SSE 文本，非流式为 JSON），由离线管线自行解析。
type CaptureRecord struct {
	Timestamp    int64           `json:"timestamp"`
	RequestId    string          `json:"request_id,omitempty"`
	UserId       int             `json:"user_id,omitempty"`
	TokenName    string          `json:"token_name,omitempty"`
	Endpoint     string          `json:"endpoint"`
	Model        string          `json:"model,omitempty"`
	IsStream     bool            `json:"is_stream"`
	StatusCode   int             `json:"status_code"`
	RequestBody  json.RawMessage `json:"request_body,omitempty"`
	ResponseBody string          `json:"response_body,omitempty"`
}

// sink 持有当天日期与打开的文件句柄，跨天时滚动到新文件。
type sink struct {
	mu   sync.Mutex
	day  string
	file *os.File
	dir  string
}

var defaultSink = &sink{}

// Write 把一条记录追加写入当天的 JSONL 文件。任何错误只记录系统日志，不返回给调用方。
func Write(record *CaptureRecord) {
	defaultSink.write(record)
}

func (s *sink) write(record *CaptureRecord) {
	line, err := common.Marshal(record)
	if err != nil {
		common.SysError("data_capture: marshal record failed: " + err.Error())
		return
	}
	line = append(line, '\n')

	s.mu.Lock()
	defer s.mu.Unlock()

	f, err := s.currentFile()
	if err != nil {
		common.SysError("data_capture: open capture file failed: " + err.Error())
		return
	}
	if _, err := f.Write(line); err != nil {
		common.SysError("data_capture: write capture file failed: " + err.Error())
	}
}

// currentFile 返回当天文件句柄，跨天或目录变更时重新打开。调用方须持有 s.mu。
func (s *sink) currentFile() (*os.File, error) {
	dir := captureDir()
	today := time.Now().Format("2006-01-02")

	if s.file != nil && s.day == today && s.dir == dir {
		return s.file, nil
	}

	if s.file != nil {
		_ = s.file.Close()
		s.file = nil
	}

	if err := os.MkdirAll(dir, 0755); err != nil {
		return nil, err
	}

	path := filepath.Join(dir, fmt.Sprintf("captures-%s.jsonl", today))
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}

	s.file = f
	s.day = today
	s.dir = dir
	return f, nil
}

// captureDir 解析输出目录：配置为空时回退到 <LogDir>/captures 或 ./logs/captures。
func captureDir() string {
	if dir := operation_setting.GetDataCaptureSetting().Dir; dir != "" {
		return filepath.Clean(dir)
	}
	base := "./logs"
	if common.LogDir != nil && *common.LogDir != "" {
		base = *common.LogDir
	}
	return filepath.Join(base, "captures")
}
