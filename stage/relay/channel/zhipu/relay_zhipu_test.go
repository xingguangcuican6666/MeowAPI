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

package zhipu

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

const (
	zhipuSecret    = "acct-sk-LEAK"
	zhipuRequestID = "req-zhipu-stream"
	zhipuModel     = "chatglm_turbo"

	// zhipuStreamTail is what a stream sends after the frames under test: more
	// model output, then the finish event whose meta frame carries the usage.
	zhipuStreamTail = "event:add\nid:1\ndata:trailing output\n\n" +
		"event:finish\nid:1\n" +
		`meta:{"request_id":"req-1","task_id":"task-1","task_status":"SUCCESS","usage":{"prompt_tokens":3,"completion_tokens":4,"total_tokens":7}}` + "\n" +
		"data:\n\n"
)

// closeNotifyRecorder adds the http.CloseNotifier that gin's Context.Stream
// requires; httptest.ResponseRecorder does not implement it.
type closeNotifyRecorder struct {
	*httptest.ResponseRecorder
}

func (closeNotifyRecorder) CloseNotify() <-chan bool { return make(chan bool) }

// zhipuClientError and zhipuClientFrame decode the SSE payloads a client
// receives: either a chat completion chunk or a standardized error frame.
type zhipuClientError struct {
	Message string `json:"message"`
	Type    string `json:"type"`
	Code    any    `json:"code"`
}

type zhipuClientFrame struct {
	Choices []struct {
		Delta struct {
			Content string `json:"content"`
		} `json:"delta"`
	} `json:"choices"`
	Error *zhipuClientError `json:"error"`
}

func newZhipuRelayInfo() *relaycommon.RelayInfo {
	return &relaycommon.RelayInfo{ChannelMeta: &relaycommon.ChannelMeta{UpstreamModelName: zhipuModel}}
}

func newZhipuResponse(upstream string) *http.Response {
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(upstream)),
	}
}

// captureErrorLog redirects the error log, where logger.LogError writes, into a
// buffer for the rest of the test.
func captureErrorLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	common.LogWriterMu.Lock()
	previous := gin.DefaultErrorWriter
	gin.DefaultErrorWriter = &logs
	common.LogWriterMu.Unlock()
	t.Cleanup(func() {
		common.LogWriterMu.Lock()
		gin.DefaultErrorWriter = previous
		common.LogWriterMu.Unlock()
	})
	return &logs
}

// createZhipuAdmin stores an administrator in a private in-memory database and
// returns its id. model.DB is restored when the test ends.
func createZhipuAdmin(t *testing.T) int {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&model.User{}))
	admin := &model.User{
		Username: "zhipu-admin",
		Password: "unused",
		Role:     common.RoleAdminUser,
		Status:   common.UserStatusEnabled,
		AffCode:  "zhipu-admin",
	}
	require.NoError(t, db.Create(admin).Error)

	previous := model.DB
	model.DB = db
	t.Cleanup(func() {
		model.DB = previous
		require.NoError(t, sqlDB.Close())
	})
	return admin.Id
}

// setSanitizeUpstreamError sets setting.SanitizeUpstreamErrorEnabled for the
// rest of the test and restores the previous value when it ends.
func setSanitizeUpstreamError(t *testing.T, enabled bool) {
	t.Helper()
	previous := setting.SanitizeUpstreamErrorEnabled
	setting.SanitizeUpstreamErrorEnabled = enabled
	t.Cleanup(func() { setting.SanitizeUpstreamErrorEnabled = previous })
}

// zhipuStreamRun is the outcome of one pass of zhipuStreamHandler.
type zhipuStreamRun struct {
	c      *gin.Context
	frames []string // payload of every "data:" frame the client received
	usage  *dto.Usage
	logs   string
}

// runZhipuStream feeds upstream through zhipuStreamHandler as the given user
// (0 is an ordinary, non-admin caller) and collects what the client received.
func runZhipuStream(t *testing.T, upstream string, userID int) zhipuStreamRun {
	t.Helper()
	logs := captureErrorLog(t)
	recorder := closeNotifyRecorder{httptest.NewRecorder()}
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	c.Set(common.RequestIdKey, zhipuRequestID)
	c.Set("id", userID)

	usage, apiErr := zhipuStreamHandler(c, newZhipuRelayInfo(), newZhipuResponse(upstream))
	require.Nil(t, apiErr)

	var frames []string
	for _, block := range strings.Split(recorder.Body.String(), "\n\n") {
		if block = strings.TrimSpace(block); block == "" {
			continue
		}
		payload, ok := strings.CutPrefix(block, "data: ")
		require.True(t, ok, "the client received a block that is not a data frame: %q", block)
		frames = append(frames, payload)
	}
	return zhipuStreamRun{c: c, frames: frames, usage: usage, logs: logs.String()}
}

// decode splits the frames the client received into the model output text of
// its chat completion chunks and the error objects it was sent, in order. The
// final [DONE] marker is in neither.
func (r zhipuStreamRun) decode(t *testing.T) (contents []string, errs []zhipuClientError) {
	t.Helper()
	for _, payload := range r.frames {
		if payload == "[DONE]" {
			continue
		}
		var frame zhipuClientFrame
		require.NoError(t, common.UnmarshalJsonStr(payload, &frame), "client frame: %s", payload)
		if frame.Error != nil {
			errs = append(errs, *frame.Error)
			continue
		}
		for _, choice := range frame.Choices {
			if choice.Delta.Content != "" {
				contents = append(contents, choice.Delta.Content)
			}
		}
	}
	return contents, errs
}

// clientBody is everything the client received, for leak checks.
func (r zhipuStreamRun) clientBody() string {
	return strings.Join(r.frames, "\n")
}

func assertZhipuMetaUsage(t *testing.T, usage *dto.Usage) {
	t.Helper()
	require.NotNil(t, usage)
	assert.Equal(t, 3, usage.PromptTokens)
	assert.Equal(t, 4, usage.CompletionTokens)
	assert.Equal(t, 7, usage.TotalTokens)
}

// zhipuErrorObject is the OpenAI-style error payload a failing stream can
// carry, with an upstream account identifier that must never reach a client.
const zhipuErrorObject = `{"error":{"code":"1002","message":"upstream account ` + zhipuSecret + ` balance exhausted"}}`

func TestIsZhipuStreamFailure(t *testing.T) {
	tests := []struct {
		name  string
		event string
		text  string
		want  bool
	}{
		{"add event with plain text", "add", "hello", false},
		{"add event resembling an error object", "add", zhipuErrorObject, false},
		{"add event resembling a failed envelope", "add", `{"code":1113,"msg":"x","success":false}`, false},
		{"error event with plain text", "error", "anything", true},
		{"error event with an error object", "error", zhipuErrorObject, true},
		{"interrupted event", "interrupted", "", true},
		{"finish event without text", "finish", "", false},
		{"no event with plain text", "", "hello", false},
		{"no event with an error object", "", zhipuErrorObject, true},
		{"no event with a failed envelope", "", `{"code":1113,"msg":"x","success":false}`, true},
		{"no event with a successful envelope", "", `{"code":0,"msg":"ok","success":true}`, false},
		{"no event with a code and message only", "", `{"code":0,"msg":"ok"}`, false},
		{"no event with a string error", "", `{"error":"none"}`, false},
		{"no event with an unrelated object", "", `{"foo":"bar"}`, false},
		{"no event with truncated JSON", "", `{"error":`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, isZhipuStreamFailure(tt.event, tt.text))
		})
	}
}

func TestZhipuStreamStandardizesUpstreamFailureForClient(t *testing.T) {
	tests := []struct {
		name    string
		failure string
	}{
		{"error event carrying an error object", "event:error\nid:1\ndata:" + zhipuErrorObject + "\n\n"},
		{"error event carrying plain text", "event:error\nid:1\ndata:upstream account " + zhipuSecret + " balance exhausted\n\n"},
		{"interrupted event", "event:interrupted\nid:1\ndata:" + zhipuSecret + " interrupted by moderation\n\n"},
		{"error object without an event line", "data:" + zhipuErrorObject + "\n\n"},
		{"failed envelope without an event line", `data:{"code":1113,"msg":"` + zhipuSecret + ` insufficient balance","success":false}` + "\n\n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setSanitizeUpstreamError(t, true)
			run := runZhipuStream(t, "event:add\nid:0\ndata:partial\n\n"+tt.failure+zhipuStreamTail, 0)

			contents, errs := run.decode(t)
			assert.Equal(t, []string{"partial"}, contents, "output before the failure is still delivered, nothing after it")
			require.Len(t, errs, 1)
			assert.Equal(t, service.StandardUpstreamMessage(run.c, 0), errs[0].Message)
			assert.Contains(t, errs[0].Message, zhipuRequestID)
			assert.Equal(t, "upstream_error", errs[0].Type)
			assert.Nil(t, errs[0].Code)
			require.Len(t, run.frames, 3, "output chunk, one error frame, [DONE]")
			assert.Equal(t, "[DONE]", run.frames[2])

			assert.NotContains(t, run.clientBody(), zhipuSecret)
			assert.NotContains(t, run.clientBody(), "trailing output")

			// The verbatim text stays available to administrators through the log,
			// and the trailing usage still settles the request.
			assert.Contains(t, run.logs, zhipuSecret)
			assert.Contains(t, run.logs, "zhipu upstream stream error")
			assertZhipuMetaUsage(t, run.usage)
		})
	}
}

func TestZhipuStreamForwardsModelOutputUnchanged(t *testing.T) {
	setSanitizeUpstreamError(t, true)
	// Model output that merely looks like an error payload, sent as "add"
	// events, followed by lines without an event that are not failures either.
	outputs := []string{
		"hello",
		zhipuErrorObject,
		`{"code":1113,"msg":"written by the model","success":false}`,
		`{"foo":"bar"}`,
	}
	var upstream strings.Builder
	for _, output := range outputs {
		upstream.WriteString("event:add\nid:0\ndata:" + output + "\n\n")
	}
	upstream.WriteString(`data:{"code":0,"msg":"ok","success":true}` + "\n\n")
	upstream.WriteString("data:plain text without an event\n\n")
	upstream.WriteString(zhipuStreamTail)

	run := runZhipuStream(t, upstream.String(), 0)

	contents, errs := run.decode(t)
	assert.Empty(t, errs)
	assert.Equal(t, append(outputs, `{"code":0,"msg":"ok","success":true}`, "plain text without an event", "trailing output"), contents)
	assert.Equal(t, "[DONE]", run.frames[len(run.frames)-1])
	assert.NotContains(t, run.logs, "zhipu upstream stream error")
	assertZhipuMetaUsage(t, run.usage)
}

func TestZhipuStreamKeepsUpstreamTextVerbatimWhenNotSanitizing(t *testing.T) {
	upstream := "event:add\nid:0\ndata:partial\n\nevent:error\nid:1\ndata:" + zhipuErrorObject + "\n\n" + zhipuStreamTail
	tests := []struct {
		name      string
		sanitize  bool
		adminUser bool
	}{
		{"sanitizer disabled", false, false},
		{"administrator", true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setSanitizeUpstreamError(t, tt.sanitize)
			userID := 0
			if tt.adminUser {
				userID = createZhipuAdmin(t)
			}

			run := runZhipuStream(t, upstream, userID)

			contents, errs := run.decode(t)
			assert.Empty(t, errs, "no standardized error frame is written")
			assert.Equal(t, []string{"partial", zhipuErrorObject, "trailing output"}, contents)
			assert.Equal(t, "[DONE]", run.frames[len(run.frames)-1])
			assert.Contains(t, run.logs, zhipuSecret)
			assertZhipuMetaUsage(t, run.usage)
		})
	}
}

func TestZhipuStreamSettlesOnEstimateWhenFailureEndsTheStream(t *testing.T) {
	upstream := "event:error\nid:1\ndata:" + zhipuSecret + " boom\n\n"

	t.Run("sanitized", func(t *testing.T) {
		setSanitizeUpstreamError(t, true)
		run := runZhipuStream(t, upstream, 0)

		require.NotNil(t, run.usage, "the caller dereferences the usage, so it must not be nil")
		assert.Zero(t, run.usage.CompletionTokens, "the failure text is not billed as model output")
		contents, errs := run.decode(t)
		assert.Empty(t, contents)
		require.Len(t, errs, 1)
		assert.Equal(t, service.StandardUpstreamMessage(run.c, 0), errs[0].Message)
		assert.NotContains(t, run.clientBody(), zhipuSecret)
		assert.Contains(t, run.logs, zhipuSecret)
	})

	t.Run("verbatim", func(t *testing.T) {
		setSanitizeUpstreamError(t, false)
		run := runZhipuStream(t, upstream, 0)

		require.NotNil(t, run.usage)
		assert.Positive(t, run.usage.CompletionTokens, "the text the client received is counted")
		contents, errs := run.decode(t)
		assert.Empty(t, errs)
		assert.Equal(t, []string{zhipuSecret + " boom"}, contents)
	})
}

func TestZhipuHandlerReturnsUpstreamFailureAsUpstreamError(t *testing.T) {
	body := `{"code":1113,"msg":"upstream account ` + zhipuSecret + ` balance exhausted","success":false}`
	tests := []struct {
		name      string
		sanitize  bool
		adminUser bool
		wantLeak  bool
	}{
		{"ordinary caller", true, false, false},
		{"sanitizer disabled", false, false, true},
		{"administrator", true, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			setSanitizeUpstreamError(t, tt.sanitize)
			userID := 0
			if tt.adminUser {
				userID = createZhipuAdmin(t)
			}
			recorder := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(recorder)
			c.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
			c.Set(common.RequestIdKey, zhipuRequestID)
			c.Set("id", userID)

			usage, apiErr := zhipuHandler(c, newZhipuRelayInfo(), newZhipuResponse(body))

			require.NotNil(t, apiErr)
			assert.Nil(t, usage)
			assert.Empty(t, recorder.Body.String(), "the handler hands the error to the relay exit instead of writing it")
			assert.False(t, apiErr.IsLocalError(), "an upstream failure must stay eligible for standardization")
			assert.Contains(t, apiErr.Error(), zhipuSecret, "the verbatim text stays on the error for the admin log")

			// The relay exit standardizes the client-facing message.
			service.StandardizeUpstreamError(c, apiErr)
			clientMessage := apiErr.ToOpenAIError().Message
			if tt.wantLeak {
				assert.Contains(t, clientMessage, zhipuSecret)
				return
			}
			assert.NotContains(t, clientMessage, zhipuSecret)
			assert.Equal(t, service.StandardUpstreamMessage(c, apiErr.StatusCode), clientMessage)
		})
	}
}
