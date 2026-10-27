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
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/model_setting"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tidwall/gjson"
)

// 生产在启动时调用 InitHttpClient()；测试进程未走启动流程，这里按需初始化一次，
// 否则 service.GetHttpClient() 为 nil，POST 时 panic。
var zliuHTTPClientOnce sync.Once

func ensureZliuHTTPClient() { zliuHTTPClientOnce.Do(service.InitHttpClient) }

// withZliuSettings 快照并覆盖全局 zliu 路由配置，测试结束后还原，避免污染其它用例。
func withZliuSettings(t *testing.T, mutate func(s *model_setting.ZliuRouterSettings)) {
	t.Helper()
	ensureZliuHTTPClient()
	s := model_setting.GetZliuRouterSettings()
	saved := *s
	t.Cleanup(func() { *s = saved })
	mutate(s)
}

// newZliuTestContext 造一个带 JSON 体的 gin 上下文，body 走 c.Request.Body（GetBodyStorage 会懒加载）。
func newZliuTestContext(t *testing.T, body string) (*gin.Context, *httptest.ResponseRecorder) {
	t.Helper()
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	return c, recorder
}

func TestZliuRouterRewritesModelOnTrigger(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_, _ = w.Write([]byte(`{"target":"opus"}`))
	}))
	t.Cleanup(srv.Close)

	withZliuSettings(t, func(s *model_setting.ZliuRouterSettings) {
		s.Enabled = true
		s.EndpointURL = srv.URL + "/route"
		s.TriggerModel = "zliu-auto"
		s.FastModel = "deepseek-chat"
		s.StrongModel = "claude-opus-4"
		s.TimeoutMs = 2000
	})

	c, _ := newZliuTestContext(t, `{"model":"zliu-auto","messages":[{"role":"user","content":"帮我重构这段并发代码"}]}`)
	mr := &ModelRequest{Model: "zliu-auto"}
	maybeApplyZliuRouter(c, mr)

	assert.Equal(t, "claude-opus-4", mr.Model, "target=opus 应映射到强模型")
	// 请求体的 model 字段也被改写（供 pass-through 渠道）。
	storage, err := common.GetBodyStorage(c)
	require.NoError(t, err)
	raw, err := storage.Bytes()
	require.NoError(t, err)
	assert.Equal(t, "claude-opus-4", gjson.GetBytes(raw, "model").String())
	// 路由器收到的载荷含本轮增量消息。
	assert.Equal(t, "帮我重构这段并发代码", gjson.Get(gotBody, "messages.0.content").String())
	assert.True(t, gjson.Get(gotBody, "update_state").Bool())
}

func TestZliuRouterIgnoresNonTriggerModel(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		_, _ = w.Write([]byte(`{"target":"opus"}`))
	}))
	t.Cleanup(srv.Close)

	withZliuSettings(t, func(s *model_setting.ZliuRouterSettings) {
		s.Enabled = true
		s.EndpointURL = srv.URL + "/route"
		s.TriggerModel = "zliu-auto"
	})

	c, _ := newZliuTestContext(t, `{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}]}`)
	mr := &ModelRequest{Model: "gpt-4o"}
	maybeApplyZliuRouter(c, mr)

	assert.Equal(t, "gpt-4o", mr.Model, "非触发模型不应被改写")
	assert.False(t, called, "非触发模型不应调用路由器")
}

func TestZliuRouterDisabledIsNoop(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
	}))
	t.Cleanup(srv.Close)

	withZliuSettings(t, func(s *model_setting.ZliuRouterSettings) {
		s.Enabled = false
		s.EndpointURL = srv.URL + "/route"
		s.TriggerModel = "zliu-auto"
	})

	c, _ := newZliuTestContext(t, `{"model":"zliu-auto","messages":[{"role":"user","content":"hi"}]}`)
	mr := &ModelRequest{Model: "zliu-auto"}
	maybeApplyZliuRouter(c, mr)

	assert.Equal(t, "zliu-auto", mr.Model)
	assert.False(t, called)
}

func TestZliuRouterFailOpenOnRouterError(t *testing.T) {
	withZliuSettings(t, func(s *model_setting.ZliuRouterSettings) {
		s.Enabled = true
		s.EndpointURL = "http://127.0.0.1:1/route" // 必然连接失败
		s.TriggerModel = "zliu-auto"
		s.FastModel = "deepseek-chat"
		s.StrongModel = "claude-opus-4"
		s.FailOpenTarget = "strong"
		s.TimeoutMs = 200
	})

	c, _ := newZliuTestContext(t, `{"model":"zliu-auto","messages":[{"role":"user","content":"hi"}]}`)
	mr := &ModelRequest{Model: "zliu-auto"}
	maybeApplyZliuRouter(c, mr)

	// 路由器不可达时兜底成强模型，绝不阻断（模型名已是真实模型，非 zliu-auto）。
	assert.Equal(t, "claude-opus-4", mr.Model)
}

func TestZliuRouterHandlesAnthropicBody(t *testing.T) {
	var gotBody string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		gotBody = string(b)
		_, _ = w.Write([]byte(`{"target":"deepseek"}`))
	}))
	t.Cleanup(srv.Close)

	withZliuSettings(t, func(s *model_setting.ZliuRouterSettings) {
		s.Enabled = true
		s.EndpointURL = srv.URL + "/route"
		s.TriggerModel = "zliu-auto"
		s.FastModel = "deepseek-chat"
		s.StrongModel = "claude-opus-4"
		s.TimeoutMs = 2000
	})

	// Anthropic messages 形态：content 为 block 数组。
	body := `{"model":"zliu-auto","messages":[` +
		`{"role":"user","content":[{"type":"text","text":"第一个问题"}]},` +
		`{"role":"assistant","content":[{"type":"text","text":"这是回答"}]},` +
		`{"role":"user","content":[{"type":"text","text":"继续追问"}]}` +
		`]}`
	c, _ := newZliuTestContext(t, body)
	mr := &ModelRequest{Model: "zliu-auto"}
	maybeApplyZliuRouter(c, mr)

	assert.Equal(t, "deepseek-chat", mr.Model, "target=deepseek 应映射到快模型")
	// 本轮增量应是最后一条 user 消息，prev_turn_text 应是上一条 assistant 正文。
	assert.Equal(t, "继续追问", gjson.Get(gotBody, "messages.0.content").String())
	assert.Equal(t, "这是回答", gjson.Get(gotBody, "prev_turn_text").String())
}
