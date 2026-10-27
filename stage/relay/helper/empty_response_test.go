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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/QuantumNous/new-api/relaykit/types"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newEmptyResponseGuardTest(t *testing.T, enabled bool) (*gin.Context, *httptest.ResponseRecorder, *EmptyResponseGuard) {
	t.Helper()

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)

	info := &relaycommon.RelayInfo{
		ChannelMeta: &relaycommon.ChannelMeta{
			ChannelOtherSettings: dto.ChannelOtherSettings{
				EmptyResponseRetryOverrideEnabled: true,
				EmptyResponseRetryEnabled:         enabled,
			},
		},
	}

	return c, recorder, BeginEmptyResponseGuard(c, info)
}

func TestEmptyResponseGuardRetractsEmptyResponse(t *testing.T) {
	c, recorder, guard := newEmptyResponseGuardTest(t, true)

	SetEventStreamHeaders(c)
	require.NoError(t, StringData(c, `{"choices":[{"delta":{"role":"assistant","content":""},"finish_reason":"stop"}]}`))
	Done(c)

	apiErr := guard.Commit(&dto.Usage{PromptTokens: 12})
	require.NotNil(t, apiErr)
	assert.Equal(t, types.ErrorCodeEmptyResponseRetry, apiErr.GetErrorCode())
	assert.Equal(t, http.StatusBadGateway, apiErr.StatusCode)

	assert.Empty(t, recorder.Body.String(), "an empty upstream response must not reach the client")
	assert.Empty(t, recorder.Header().Get("Content-Type"))
	// The retry attempt writes a fresh response, so it must be able to set the
	// SSE headers again.
	_, headersMarked := c.Get(eventStreamHeadersSetKey)
	assert.False(t, headersMarked)
}

func TestEmptyResponseGuardForwardsResponseWithContent(t *testing.T) {
	c, recorder, guard := newEmptyResponseGuardTest(t, true)

	body := `{"choices":[{"message":{"role":"assistant","content":"hi"}}],"usage":{"completion_tokens":1}}`
	c.Writer.Header().Set("Content-Type", "application/json")
	c.Writer.WriteHeader(http.StatusOK)
	_, err := c.Writer.WriteString(body)
	require.NoError(t, err)

	require.Nil(t, guard.Commit(&dto.Usage{PromptTokens: 12, CompletionTokens: 1}))
	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
	assert.JSONEq(t, body, recorder.Body.String())
}

func TestEmptyResponseGuardStopsWithholdingAfterProbeLimit(t *testing.T) {
	c, recorder, guard := newEmptyResponseGuardTest(t, true)

	oversized := strings.Repeat("x", emptyResponseProbeLimit+1)
	_, err := c.Writer.WriteString(oversized)
	require.NoError(t, err)
	assert.Equal(t, oversized, recorder.Body.String(), "a response past the probe limit streams through")

	// Zero output tokens no longer matter: the client already has the bytes.
	require.Nil(t, guard.Commit(&dto.Usage{}))
}

func TestEmptyResponseGuardIsInertWhenDisabled(t *testing.T) {
	c, recorder, guard := newEmptyResponseGuardTest(t, false)

	_, err := c.Writer.WriteString("passed through")
	require.NoError(t, err)
	require.Nil(t, guard.Commit(&dto.Usage{}))
	assert.Equal(t, "passed through", recorder.Body.String())
}

func TestPingDataStopsWithholding(t *testing.T) {
	c, recorder, guard := newEmptyResponseGuardTest(t, true)

	SetEventStreamHeaders(c)
	require.NoError(t, PingData(c))
	assert.Equal(t, ": PING\n\n", recorder.Body.String())
	assert.Equal(t, "text/event-stream", recorder.Header().Get("Content-Type"))

	require.Nil(t, guard.Commit(&dto.Usage{}), "a client that has been pinged can no longer be retried")
}

func TestEmptyResponseRetrySettingResolution(t *testing.T) {
	cases := []struct {
		name             string
		globalEnabled    bool
		globalInPlace    bool
		settings         dto.ChannelOtherSettings
		wantEnabled      bool
		wantRetryInPlace bool
	}{
		{
			name:             "follows global when the channel does not override",
			globalEnabled:    true,
			globalInPlace:    true,
			settings:         dto.ChannelOtherSettings{},
			wantEnabled:      true,
			wantRetryInPlace: true,
		},
		{
			name:          "channel override turns the feature off",
			globalEnabled: true,
			globalInPlace: true,
			settings: dto.ChannelOtherSettings{
				EmptyResponseRetryOverrideEnabled: true,
			},
			wantEnabled:      false,
			wantRetryInPlace: false,
		},
		{
			name:          "channel override turns the feature on and keeps retries in place",
			globalEnabled: false,
			globalInPlace: false,
			settings: dto.ChannelOtherSettings{
				EmptyResponseRetryOverrideEnabled: true,
				EmptyResponseRetryEnabled:         true,
				EmptyResponseRetryInPlace:         true,
			},
			wantEnabled:      true,
			wantRetryInPlace: true,
		},
		{
			name:          "channel override asks for another channel instead",
			globalEnabled: false,
			globalInPlace: true,
			settings: dto.ChannelOtherSettings{
				EmptyResponseRetryOverrideEnabled: true,
				EmptyResponseRetryEnabled:         true,
			},
			wantEnabled:      true,
			wantRetryInPlace: false,
		},
	}

	originalEnabled := common.EmptyResponseRetryEnabled
	originalInPlace := common.EmptyResponseRetryInPlaceEnabled
	t.Cleanup(func() {
		common.EmptyResponseRetryEnabled = originalEnabled
		common.EmptyResponseRetryInPlaceEnabled = originalInPlace
	})

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			common.EmptyResponseRetryEnabled = testCase.globalEnabled
			common.EmptyResponseRetryInPlaceEnabled = testCase.globalInPlace

			info := &relaycommon.RelayInfo{
				ChannelMeta: &relaycommon.ChannelMeta{ChannelOtherSettings: testCase.settings},
			}
			assert.Equal(t, testCase.wantEnabled, EmptyResponseRetryEnabled(info))
			assert.Equal(t, testCase.wantRetryInPlace, EmptyResponseRetryInPlaceEnabled(info))
		})
	}
}

func TestIsEmptyUpstreamResponse(t *testing.T) {
	cases := []struct {
		name  string
		body  string
		usage *dto.Usage
		empty bool
	}{
		{
			name:  "openai empty message",
			body:  `{"choices":[{"message":{"role":"assistant","content":""},"finish_reason":"stop"}],"usage":{"prompt_tokens":9}}`,
			usage: &dto.Usage{PromptTokens: 9},
			empty: true,
		},
		{
			name:  "openai message with content",
			body:  `{"choices":[{"message":{"role":"assistant","content":"hello"}}]}`,
			usage: &dto.Usage{PromptTokens: 9},
			empty: false,
		},
		{
			name:  "openai empty message but reported output tokens",
			body:  `{"choices":[{"message":{"role":"assistant","content":""}}]}`,
			usage: &dto.Usage{PromptTokens: 9, CompletionTokens: 4},
			empty: false,
		},
		{
			name:  "openai stream without content",
			body:  "data: {\"choices\":[{\"delta\":{\"role\":\"assistant\"}}]}\n\ndata: {\"choices\":[{\"delta\":{},\"finish_reason\":\"stop\"}]}\n\ndata: [DONE]\n\n",
			usage: &dto.Usage{},
			empty: true,
		},
		{
			name:  "openai stream with tool call",
			body:  "data: {\"choices\":[{\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"name\":\"get_weather\",\"arguments\":\"\"}}]}}]}\n\ndata: [DONE]\n\n",
			usage: &dto.Usage{},
			empty: false,
		},
		{
			name:  "claude stream without content",
			body:  "event: message_start\ndata: {\"type\":\"message_start\",\"message\":{\"role\":\"assistant\",\"content\":[]}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n",
			usage: &dto.Usage{},
			empty: true,
		},
		{
			name:  "claude stream with content delta",
			body:  "event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"delta\":{\"type\":\"text_delta\",\"text\":\"hi\"}}\n\n",
			usage: &dto.Usage{},
			empty: false,
		},
		{
			name:  "gemini empty candidates",
			body:  `{"candidates":[{"content":{"role":"model"},"finishReason":"STOP"}]}`,
			usage: &dto.Usage{},
			empty: true,
		},
		{
			name:  "gemini candidate with part text",
			body:  `{"candidates":[{"content":{"role":"model","parts":[{"text":"hi"}]}}]}`,
			usage: &dto.Usage{},
			empty: false,
		},
		{
			name:  "responses failed frame is a definitive outcome",
			body:  "data: {\"type\":\"response.created\",\"response\":{\"id\":\"first\",\"status\":\"in_progress\"}}\n\ndata: {\"type\":\"response.failed\",\"response\":{\"id\":\"first\",\"status\":\"failed\",\"usage\":null,\"error\":{\"code\":\"server_error\",\"message\":\"boom\"}}}\n\n",
			usage: &dto.Usage{},
			empty: false,
		},
		{
			name:  "responses completed with zero usage is a definitive outcome",
			body:  "data: {\"type\":\"response.created\",\"response\":{\"id\":\"first\",\"status\":\"in_progress\"}}\n\ndata: {\"type\":\"response.completed\",\"response\":{\"id\":\"first\",\"status\":\"completed\",\"usage\":{\"input_tokens\":0,\"output_tokens\":0,\"total_tokens\":0}}}\n\n",
			usage: &dto.Usage{},
			empty: false,
		},
		{
			name:  "responses error frame is a definitive outcome",
			body:  "data: {\"type\":\"error\",\"code\":\"context_length_exceeded\",\"message\":\"Input too long\",\"param\":null,\"sequence_number\":2}\n\n",
			usage: &dto.Usage{},
			empty: false,
		},
		{
			name:  "missing usage and empty body",
			body:  "",
			usage: nil,
			empty: true,
		},
		{
			name:  "unparsable body counts as content-free",
			body:  "not json at all",
			usage: &dto.Usage{},
			empty: true,
		},
	}

	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			assert.Equal(t, testCase.empty, isEmptyUpstreamResponse([]byte(testCase.body), testCase.usage))
		})
	}
}
