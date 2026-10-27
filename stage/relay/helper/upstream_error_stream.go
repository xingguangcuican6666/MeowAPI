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

package helper

import (
	"fmt"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/logger"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/QuantumNous/new-api/service"

	"github.com/gin-gonic/gin"
)

// looksLikeUpstreamErrorFrame reports whether a raw SSE data payload (with the
// leading "data:" prefix already stripped) is an upstream error frame: a JSON
// object with a non-empty top-level "error" object, or an event whose top-level
// "type" is "error" (Claude / OpenAI Responses). The cheap substring gate keeps
// normal content frames off the JSON parser.
func looksLikeUpstreamErrorFrame(data string) bool {
	trimmed := strings.TrimSpace(data)
	if len(trimmed) == 0 || trimmed[0] != '{' {
		return false
	}
	if !strings.Contains(trimmed, "\"error\"") {
		return false
	}
	var probe struct {
		Error common.RawMessage `json:"error"`
		Type  string            `json:"type"`
	}
	if err := common.Unmarshal([]byte(trimmed), &probe); err != nil {
		return false
	}
	if len(probe.Error) > 0 && common.GetJsonType(probe.Error) == "object" {
		return true
	}
	return probe.Type == "error"
}

// MaybeWriteSanitizedStreamError inspects a raw upstream SSE data payload (with
// the leading "data:" prefix already stripped) and, when upstream-error
// sanitization applies to the caller and the payload looks like an upstream
// error frame, logs the verbatim frame and writes a standardized error frame in
// the client's relay format instead of the original. It returns true when it
// handled the frame, signaling the caller to stop forwarding upstream data.
//
// Callers that own the sole write path (custom scan loops) call this before
// forwarding a frame and break on true. StreamScannerHandler calls it while
// holding its write mutex.
func MaybeWriteSanitizedStreamError(c *gin.Context, info *relaycommon.RelayInfo, data string) bool {
	if info == nil || !service.ShouldSanitizeUpstreamForClient(c) {
		return false
	}
	if !looksLikeUpstreamErrorFrame(data) {
		return false
	}
	logger.LogError(c, fmt.Sprintf("upstream stream error frame sanitized for client: %s", common.LocalLogPreview(data)))
	writeSanitizedStreamErrorFrame(c, info, data)
	return true
}

// writeSanitizedStreamErrorFrame emits a single standardized error frame. The
// human-readable message is replaced by the fixed phrasing; the machine-readable
// type/code parsed from the upstream frame are preserved so clients can still
// branch on them. Mid-stream the HTTP status is already 200, so the generic
// fallback phrasing is used.
func writeSanitizedStreamErrorFrame(c *gin.Context, info *relaycommon.RelayInfo, data string) {
	message := service.StandardUpstreamMessage(c, 0)

	var probe struct {
		Error struct {
			Type string `json:"type"`
			Code any    `json:"code"`
		} `json:"error"`
		Type string `json:"type"`
	}
	_ = common.Unmarshal([]byte(strings.TrimSpace(data)), &probe)

	switch info.RelayFormat {
	case types.RelayFormatClaude:
		errType := probe.Error.Type
		if errType == "" {
			errType = "upstream_error"
		}
		_ = ClaudeData(c, dto.ClaudeResponse{
			Type:  "error",
			Error: types.ClaudeError{Type: errType, Message: message},
		})
	case types.RelayFormatOpenAIResponses:
		errObj := buildStandardErrorObject(message, probe.Error.Type, probe.Error.Code)
		if payload, err := common.Marshal(gin.H{"type": "error", "error": errObj}); err == nil {
			c.Render(-1, common.CustomEvent{Data: "event: error\n"})
			c.Render(-1, common.CustomEvent{Data: "data: " + string(payload)})
			_ = FlushWriter(c)
		}
	default:
		errObj := buildStandardErrorObject(message, probe.Error.Type, probe.Error.Code)
		if payload, err := common.Marshal(gin.H{"error": errObj}); err == nil {
			_ = StringData(c, string(payload))
		}
	}
}

// buildStandardErrorObject assembles the OpenAI-shaped error object, keeping the
// upstream type/code when present and falling back to a generic marker.
func buildStandardErrorObject(message, upstreamType string, upstreamCode any) gin.H {
	errObj := gin.H{"message": message, "type": "upstream_error"}
	if upstreamType != "" {
		errObj["type"] = upstreamType
	}
	if upstreamCode != nil {
		errObj["code"] = upstreamCode
	}
	return errObj
}
