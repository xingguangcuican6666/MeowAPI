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

package middleware

import (
	"bytes"
	"encoding/json"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/service/data_capture"
	"github.com/QuantumNous/new-api/setting/operation_setting"

	"github.com/gin-gonic/gin"
)

// captureResponseWriter 包装 gin.ResponseWriter，把响应体旁路复制一份到有大小上限的缓冲区，
// 用于会话数据采集。缓冲区超出上限后不再缓存，避免大响应占用过多内存。
// 该 writer 只 tee 数据，不改变发往客户端的字节流。
type captureResponseWriter struct {
	gin.ResponseWriter
	body    *bytes.Buffer
	maxSize int
}

func (w *captureResponseWriter) Write(b []byte) (int, error) {
	if w.body.Len() < w.maxSize {
		remain := w.maxSize - w.body.Len()
		if remain >= len(b) {
			w.body.Write(b)
		} else {
			w.body.Write(b[:remain])
		}
	}
	return w.ResponseWriter.Write(b)
}

func (w *captureResponseWriter) WriteString(s string) (int, error) {
	return w.Write([]byte(s))
}

// DataCapture 在开关开启时，把 chat/completions 类会话的请求体与响应体落盘为 JSONL。
// 关闭时零开销直接放行。采集逻辑用 recover 兜底，任何异常都不会冒泡到请求链路。
func DataCapture() gin.HandlerFunc {
	return func(c *gin.Context) {
		setting := operation_setting.GetDataCaptureSetting()
		if !setting.Enabled {
			c.Next()
			return
		}

		maxBytes := setting.MaxBodyBytes()
		writer := &captureResponseWriter{
			ResponseWriter: c.Writer,
			body:           bytes.NewBuffer(nil),
			maxSize:        maxBytes,
		}
		c.Writer = writer

		c.Next()

		recordCapture(c, writer, maxBytes)
	}
}

func recordCapture(c *gin.Context, writer *captureResponseWriter, maxBytes int) {
	defer func() {
		if r := recover(); r != nil {
			common.SysError("data_capture: recovered from panic while recording capture")
		}
	}()

	requestBody := readRequestBody(c, maxBytes)
	isStream := strings.HasPrefix(c.Writer.Header().Get("Content-Type"), "text/event-stream")

	data_capture.Write(&data_capture.CaptureRecord{
		Timestamp:    common.GetTimestamp(),
		RequestId:    c.GetString(common.RequestIdKey),
		UserId:       c.GetInt("id"),
		TokenName:    c.GetString("token_name"),
		Endpoint:     c.Request.URL.Path,
		Model:        c.GetString("original_model"),
		IsStream:     isStream,
		StatusCode:   c.Writer.Status(),
		RequestBody:  requestBody,
		ResponseBody: writer.body.String(),
	})
}

// readRequestBody 从已缓存的 BodyStorage 读取客户端原始请求体，超出上限则截断。
// 截断后不再是合法 JSON，用 RawMessage 原样保留，由离线管线处理。
func readRequestBody(c *gin.Context, maxBytes int) json.RawMessage {
	storage, err := common.GetBodyStorage(c)
	if err != nil {
		return nil
	}
	data, err := storage.Bytes()
	if err != nil {
		return nil
	}
	if len(data) > maxBytes {
		data = data[:maxBytes]
	}
	return json.RawMessage(data)
}
