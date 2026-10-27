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
	"bytes"
	"errors"
	"net/http"
	"strings"
	"sync"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/logger"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/QuantumNous/new-api/relaykit/types"

	"github.com/gin-gonic/gin"
)

const (
	// emptyResponseProbeLimit bounds how many downstream body bytes an
	// EmptyResponseGuard withholds while deciding whether the upstream reply is
	// empty. Empty replies are a few hundred bytes at most, so a response that
	// grows past this is definitely not empty: the guard hands over what it
	// holds and streams the rest straight through. Keeping the limit small also
	// keeps the first-byte delay it adds to streaming responses short.
	emptyResponseProbeLimit = 4 << 10

	eventStreamHeadersSetKey = "event_stream_headers_set"
)

// EmptyResponseGuard withholds the downstream response until the upstream reply
// is known to carry output, so a 200 that contains nothing usable can be
// retried on another channel instead of reaching the client.
//
// A zero guard (feature disabled for this request) is inert: every method is a
// no-op, so call sites need no branching.
type EmptyResponseGuard struct {
	c      *gin.Context
	writer *bufferingResponseWriter
}

// BeginEmptyResponseGuard starts intercepting downstream writes when empty
// response retry applies to this request. Call Commit or Release before
// returning so the original writer is restored.
func BeginEmptyResponseGuard(c *gin.Context, info *relaycommon.RelayInfo) *EmptyResponseGuard {
	if c == nil || c.Writer == nil || c.Writer.Written() || !EmptyResponseRetryEnabled(info) {
		return &EmptyResponseGuard{}
	}
	writer := &bufferingResponseWriter{
		ResponseWriter: c.Writer,
		header:         c.Writer.Header().Clone(),
	}
	c.Writer = writer
	return &EmptyResponseGuard{c: c, writer: writer}
}

// EmptyResponseRetryEnabled reports whether the selected channel should treat an
// upstream 200 carrying no output as a failure. The per-channel override wins
// over the global switch.
func EmptyResponseRetryEnabled(info *relaycommon.RelayInfo) bool {
	if info == nil || info.ChannelMeta == nil {
		return false
	}
	if info.ChannelOtherSettings.EmptyResponseRetryOverrideEnabled {
		return info.ChannelOtherSettings.EmptyResponseRetryEnabled
	}
	return common.EmptyResponseRetryEnabled
}

// EmptyResponseRetryInPlaceEnabled reports whether an empty response should be
// retried on the same channel and key, up to the retry limit, instead of moving
// to the next candidate channel. The per-channel override that governs empty
// response retry governs this too.
func EmptyResponseRetryInPlaceEnabled(info *relaycommon.RelayInfo) bool {
	if info == nil || info.ChannelMeta == nil {
		return common.EmptyResponseRetryInPlaceEnabled
	}
	if info.ChannelOtherSettings.EmptyResponseRetryOverrideEnabled {
		return info.ChannelOtherSettings.EmptyResponseRetryInPlace
	}
	return common.EmptyResponseRetryInPlaceEnabled
}

// Release hands the withheld response to the client and stops intercepting.
func (g *EmptyResponseGuard) Release() {
	if g == nil || g.writer == nil {
		return
	}
	g.writer.stopBuffering()
	g.c.Writer = g.writer.ResponseWriter
	g.writer = nil
}

// Commit releases the withheld response, or reports a retryable error when the
// upstream answered 200 with neither content nor output tokens. Nothing reaches
// the client in the latter case, so the caller can retry on another channel.
func (g *EmptyResponseGuard) Commit(usage *dto.Usage) *types.NewAPIError {
	if g == nil || g.writer == nil {
		return nil
	}
	body, retractable := g.writer.retractableBody()
	if !retractable || !isEmptyUpstreamResponse(body, usage) {
		g.Release()
		return nil
	}

	g.c.Writer = g.writer.ResponseWriter
	g.writer = nil
	// The next attempt writes to a fresh response, so it must be allowed to set
	// the SSE headers again.
	delete(g.c.Keys, eventStreamHeadersSetKey)
	logger.LogWarn(g.c, "upstream returned an empty response with status 200, retrying on another channel")

	return types.NewOpenAIError(errors.New("upstream returned an empty response with status 200"),
		types.ErrorCodeEmptyResponseRetry, http.StatusBadGateway)
}

// isEmptyUpstreamResponse reports whether the response the gateway is about to
// forward carries no model output at all. All signals must agree: the reported
// or counted output tokens are zero, the payload holds no visible content, and
// the payload carries no definitive Responses outcome. Requiring all of them
// keeps a channel that under-reports usage, a payload shape the content walk does
// not recognise, or an explicit failure the upstream already reported, from
// being discarded as if the upstream had answered with nothing.
func isEmptyUpstreamResponse(body []byte, usage *dto.Usage) bool {
	return !hasOutputTokens(usage) && !payloadHasVisibleContent(body) && !payloadReportsDefinitiveOutcome(body)
}

// responsesOutcomeTypes are the Responses API stream events (and the bare error
// frame) that report a definitive server-side outcome: the request completed,
// failed, or ended incomplete, or the upstream raised an error. Their presence
// means the upstream gave its final word — which the client must see and billing
// must settle as that outcome — rather than the silent empty 200 this guard
// exists to retry. A failed or zero-output completion is still an answer, and a
// business error such as context_length_exceeded must never be retried.
var responsesOutcomeTypes = map[string]struct{}{
	"response.completed":  {},
	"response.failed":     {},
	"response.incomplete": {},
	"error":               {},
}

// payloadReportsDefinitiveOutcome reports whether the buffered payload carries a
// Responses API terminal or error frame. These frames are protocol-specific
// enough (top-level "type") that the chat, Claude and Gemini empty shapes the
// guard still retries never match them.
func payloadReportsDefinitiveOutcome(body []byte) bool {
	for _, payload := range jsonPayloads(body) {
		var frame struct {
			Type string `json:"type"`
		}
		if err := common.Unmarshal(payload, &frame); err != nil {
			continue
		}
		if _, ok := responsesOutcomeTypes[frame.Type]; ok {
			return true
		}
	}
	return false
}

func hasOutputTokens(usage *dto.Usage) bool {
	if usage == nil {
		return false
	}
	details := usage.CompletionTokenDetails
	return usage.CompletionTokens > 0 || usage.OutputTokens > 0 ||
		details.TextTokens > 0 || details.AudioTokens > 0 ||
		details.ImageTokens > 0 || details.ReasoningTokens > 0
}

// contentBearingKeys lists the JSON keys whose non-empty value means the payload
// carries model output. Between them they cover the OpenAI, Claude, Gemini and
// Responses shapes the relay forwards downstream. The list errs on the generous
// side: mistaking framing for output only costs a retry that would have been
// taken, while missing output would discard a real answer.
var contentBearingKeys = map[string]struct{}{
	"content":           {},
	"text":              {},
	"refusal":           {},
	"reasoning":         {},
	"reasoning_content": {},
	"thinking":          {},
	"audio":             {},
	"transcript":        {},
	"b64_json":          {},
	"url":               {},
	"data":              {},
	"name":              {},
	"arguments":         {},
	"partial_json":      {},
	"executable_code":   {},
	"inline_data":       {},
	// Responses API streaming carries model output text in a top-level "delta"
	// string (e.g. response.output_text.delta). Chat/Claude "delta" values are
	// objects, not strings, so they walk their own child keys and are unaffected.
	"delta": {},
}

// toolCallKeys hold tool invocations, which count as output as soon as the array
// is non-empty: the first chunk of a streamed tool call often carries no
// arguments yet.
var toolCallKeys = map[string]struct{}{
	"tool_calls":    {},
	"tool_use":      {},
	"function_call": {},
	"functionCall":  {},
}

// payloadHasVisibleContent walks the buffered downstream payload, whether it is a
// single JSON body or an SSE stream, and reports whether any content-bearing
// field holds a non-empty value.
func payloadHasVisibleContent(body []byte) bool {
	for _, payload := range jsonPayloads(body) {
		var decoded any
		if err := common.Unmarshal(payload, &decoded); err != nil {
			continue
		}
		if valueHasVisibleContent("", decoded) {
			return true
		}
	}
	return false
}

// jsonPayloads splits an SSE stream into its data payloads, or yields the whole
// body when it is not an SSE stream.
func jsonPayloads(body []byte) [][]byte {
	payloads := make([][]byte, 0, 8)
	for _, line := range bytes.Split(body, []byte("\n")) {
		line = bytes.TrimSpace(line)
		if !bytes.HasPrefix(line, []byte("data:")) {
			continue
		}
		payload := bytes.TrimSpace(line[len("data:"):])
		if len(payload) == 0 || bytes.HasPrefix(payload, []byte("[DONE]")) {
			continue
		}
		payloads = append(payloads, payload)
	}
	if len(payloads) == 0 {
		if trimmed := bytes.TrimSpace(body); len(trimmed) > 0 {
			payloads = append(payloads, trimmed)
		}
	}
	return payloads
}

func valueHasVisibleContent(key string, value any) bool {
	switch typed := value.(type) {
	case string:
		_, contentBearing := contentBearingKeys[key]
		return contentBearing && strings.TrimSpace(typed) != ""
	case map[string]any:
		if _, isToolCall := toolCallKeys[key]; isToolCall && len(typed) > 0 {
			return true
		}
		for childKey, childValue := range typed {
			if valueHasVisibleContent(childKey, childValue) {
				return true
			}
		}
	case []any:
		if _, isToolCall := toolCallKeys[key]; isToolCall && len(typed) > 0 {
			return true
		}
		// Array elements inherit the key so `"content": ["hi"]` and
		// `"content": [{"text": "hi"}]` are both recognised.
		for _, element := range typed {
			if valueHasVisibleContent(key, element) {
				return true
			}
		}
	}
	return false
}

// StopEmptyResponseBuffering hands a withheld response to the client right away.
// Keep-alive pings call this: once anything has reached the client the response
// can no longer be retracted, and stalling a waiting client is worse than
// giving up the retry.
func StopEmptyResponseBuffering(c *gin.Context) {
	if c == nil {
		return
	}
	if writer, ok := c.Writer.(*bufferingResponseWriter); ok {
		writer.stopBuffering()
	}
}

// bufferingResponseWriter is the gin.ResponseWriter an EmptyResponseGuard swaps
// in. It accumulates status, headers and body instead of sending them, until it
// is told to stop buffering or the body outgrows emptyResponseProbeLimit.
type bufferingResponseWriter struct {
	gin.ResponseWriter

	mu         sync.Mutex
	header     http.Header
	body       bytes.Buffer
	status     int
	size       int
	started    bool
	handedOver bool
}

func (w *bufferingResponseWriter) Header() http.Header {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.isBuffering() {
		return w.header
	}
	return w.ResponseWriter.Header()
}

func (w *bufferingResponseWriter) WriteHeader(code int) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.isBuffering() {
		w.ResponseWriter.WriteHeader(code)
		return
	}
	// gin ignores non-positive codes; c.Render(-1, ...) relies on that.
	if code > 0 {
		w.status = code
	}
}

func (w *bufferingResponseWriter) WriteHeaderNow() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.isBuffering() {
		w.ResponseWriter.WriteHeaderNow()
	}
}

func (w *bufferingResponseWriter) Write(data []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.started = true
	w.size += len(data)
	if !w.isBuffering() {
		return w.ResponseWriter.Write(data)
	}
	w.body.Write(data)
	// Hand over as soon as the buffered payload is known to carry output. For a
	// streaming response this is the first content frame: withholding it any
	// longer would stall the client (it receives nothing, so it can neither make
	// progress nor cancel) until the probe limit or the stream ends. An empty
	// reply carries no such frame, so it stays withheld and remains retractable.
	if w.body.Len() > emptyResponseProbeLimit || payloadHasVisibleContent(w.body.Bytes()) {
		w.handOver()
	}
	return len(data), nil
}

func (w *bufferingResponseWriter) WriteString(s string) (int, error) {
	return w.Write([]byte(s))
}

func (w *bufferingResponseWriter) Status() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.isBuffering() {
		return w.ResponseWriter.Status()
	}
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

func (w *bufferingResponseWriter) Size() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.isBuffering() {
		return w.ResponseWriter.Size()
	}
	if !w.started {
		return -1
	}
	return w.size
}

func (w *bufferingResponseWriter) Written() bool {
	return w.Size() != -1
}

func (w *bufferingResponseWriter) Flush() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.isBuffering() {
		w.ResponseWriter.Flush()
	}
}

// Unwrap lets http.NewResponseController reach the real writer, keeping
// ExtendWriteDeadline working while the guard is installed.
func (w *bufferingResponseWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

// isBuffering must be called with w.mu held.
func (w *bufferingResponseWriter) isBuffering() bool {
	return !w.handedOver
}

// retractableBody returns the withheld body along with whether nothing has
// reached the client yet, so the whole response can still be dropped in favour
// of a retry.
func (w *bufferingResponseWriter) retractableBody() ([]byte, bool) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.handedOver {
		return nil, false
	}
	return w.body.Bytes(), true
}

// stopBuffering sends whatever is withheld and lets later writes through.
func (w *bufferingResponseWriter) stopBuffering() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.handOver()
}

// handOver must be called with w.mu held.
func (w *bufferingResponseWriter) handOver() {
	if w.handedOver {
		return
	}
	w.handedOver = true

	dst := w.ResponseWriter.Header()
	for key := range dst {
		delete(dst, key)
	}
	for key, values := range w.header {
		dst[key] = values
	}
	if w.status > 0 {
		w.ResponseWriter.WriteHeader(w.status)
	}
	if w.body.Len() > 0 {
		_, _ = w.ResponseWriter.Write(w.body.Bytes())
	}
	w.body.Reset()
}
