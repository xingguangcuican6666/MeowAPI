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

package relay

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/logger"
	"github.com/QuantumNous/new-api/middleware"
	"github.com/QuantumNous/new-api/model"
	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/QuantumNous/new-api/service"

	"github.com/gin-gonic/gin"
	"github.com/tidwall/gjson"
	"github.com/tidwall/sjson"
)

const (
	// imageUpscaleInternalFlag marks the synthetic inner relay context so the
	// upscale hook never arms recursively on the target channel.
	imageUpscaleInternalFlag = "image_upscale_internal"
	// imageUpscaleHeader reports the post-processing outcome to the client.
	imageUpscaleHeader = "X-New-Api-Image-Upscale"

	// maxImageUpscaleBodyBytes bounds the buffered generation response. A larger
	// upstream payload disables the hook and the original body passes through.
	maxImageUpscaleBodyBytes = 256 << 20
	// maxImageUpscaleImageBytes bounds a single generated image submitted to the
	// target channel, whether decoded from b64_json or downloaded from a url.
	maxImageUpscaleImageBytes = 64 << 20
)

// imageUpscaleCapture buffers the upstream image response so the hook can
// replace it with the upscaled payload after the relay succeeded.
type imageUpscaleCapture struct {
	body      bytes.Buffer
	status    int
	truncated bool
	limit     int
}

func (cap *imageUpscaleCapture) write(p []byte) (int, error) {
	if cap.body.Len()+len(p) > cap.limit {
		cap.truncated = true
		// Pretend success so the relay path keeps running; the capture is
		// discarded later and the original bytes cannot be recovered anyway.
		return len(p), nil
	}
	return cap.body.Write(p)
}

// imageUpscaleCaptureWriter swallows writes into the capture buffer while
// keeping the shared header map live, so upstream headers set during the relay
// are preserved for the final client write.
type imageUpscaleCaptureWriter struct {
	gin.ResponseWriter
	capture *imageUpscaleCapture
}

func (w *imageUpscaleCaptureWriter) WriteHeader(code int) {
	if w.capture.status == 0 {
		w.capture.status = code
	}
}

func (w *imageUpscaleCaptureWriter) Write(p []byte) (int, error) {
	return w.capture.write(p)
}

func (w *imageUpscaleCaptureWriter) WriteString(s string) (int, error) {
	return w.capture.write([]byte(s))
}

func (w *imageUpscaleCaptureWriter) Flush() {}

type imageUpscaleHook struct {
	config  *dto.ImageUpscaleConfig
	capture *imageUpscaleCapture
}

// armImageUpscaleHook returns a hook when the current channel wants image
// post-processing and the caller is not already an internal upscale relay.
// Both JSON and SSE responses are handled; the mode is decided after the
// upstream response has been captured.
func armImageUpscaleHook(c *gin.Context, info *relaycommon.RelayInfo) *imageUpscaleHook {
	if c == nil || c.GetBool(imageUpscaleInternalFlag) {
		return nil
	}
	if info == nil || info.IsChannelTest {
		return nil
	}
	config := info.ChannelOtherSettings.ImageUpscale
	if config == nil || !config.Enabled {
		return nil
	}
	if !config.MatchesModel(info.OriginModelName) {
		return nil
	}
	return &imageUpscaleHook{config: config, capture: &imageUpscaleCapture{limit: maxImageUpscaleBodyBytes}}
}

func (h *imageUpscaleHook) writer(original gin.ResponseWriter) *imageUpscaleCaptureWriter {
	return &imageUpscaleCaptureWriter{ResponseWriter: original, capture: h.capture}
}

type upscaleSourceImage struct {
	data     []byte
	filename string
	mimeType string
}

type upscaledImageEntry struct {
	base64Data string
}

// imageUpscaleSink writes the final client response after post-processing and
// applies the configured on_error policy on failure.
type imageUpscaleSink struct {
	c          *gin.Context
	realWriter gin.ResponseWriter
	status     int
	fallback   []byte
	policy     string
}

func (s *imageUpscaleSink) writeFinal(body []byte, headerValue string) {
	if headerValue != "" {
		s.realWriter.Header().Set(imageUpscaleHeader, headerValue)
	}
	if isSSEPayload(body) {
		// SSE replies are chunked; a stale Content-Length from the capture
		// phase would corrupt the replayed stream.
		s.realWriter.Header().Del("Content-Length")
	} else {
		s.realWriter.Header().Set("Content-Length", strconv.Itoa(len(body)))
	}
	s.realWriter.WriteHeader(s.status)
	if _, err := s.realWriter.Write(body); err != nil {
		logger.LogWarn(s.c, "failed to write image response: "+err.Error())
	}
}

// failOrFallback applies the on_error policy. Nothing has been written to the
// client yet, so the fail policy can still reject the request cleanly (the
// caller returns the error before any replay); the fallback policy writes the
// original captured response.
func (s *imageUpscaleSink) failOrFallback(reason string) *types.NewAPIError {
	logger.LogWarn(s.c, "image upscale "+reason)
	if s.policy == dto.ImageUpscaleOnErrorFail {
		return types.NewErrorWithStatusCode(
			fmt.Errorf("image upscale failed: %s", reason),
			types.ErrorCodeBadResponse, http.StatusBadGateway, types.ErrOptionWithSkipRetry())
	}
	s.writeFinal(s.fallback, "fallback")
	return nil
}

// process runs the upscale chain and writes the final response body to the
// real client writer. Any post-processing failure follows the configured
// on_error policy: the default fallback returns the original generation
// untouched, the fail policy errors the request after a successful generation.
func (h *imageUpscaleHook) process(c *gin.Context, info *relaycommon.RelayInfo, imageReq *dto.ImageRequest) *types.NewAPIError {
	status := h.capture.status
	if status == 0 {
		status = http.StatusOK
	}
	body := h.capture.body.Bytes()
	sink := &imageUpscaleSink{
		c:          c,
		realWriter: c.Writer,
		status:     status,
		fallback:   body,
		policy:     h.config.NormalizedOnError(),
	}

	if h.capture.truncated || len(body) == 0 {
		return sink.failOrFallback(fmt.Sprintf("captured response is empty or exceeds %d bytes", maxImageUpscaleBodyBytes))
	}

	if isSSEPayload(body) {
		return h.processStream(c, imageReq, body, sink)
	}

	images, extractErr := extractGeneratedImages(c, body)
	if extractErr != nil {
		return sink.failOrFallback("failed to extract generated images: " + extractErr.Error())
	}
	if len(images) == 0 {
		return sink.failOrFallback("generation response contains no image")
	}

	upscaled := make([]upscaledImageEntry, 0, len(images))
	for i, img := range images {
		entry, upscaleErr := h.upscaleOne(c, imageReq, img)
		if upscaleErr != nil {
			return sink.failOrFallback(fmt.Sprintf("image %d/%d via channel #%d model %s failed: %s",
				i+1, len(images), h.config.TargetChannelID, h.config.NormalizedTargetModel(), upscaleErr.Error()))
		}
		upscaled = append(upscaled, entry)
	}

	newBody, buildErr := rebuildImageResponse(body, upscaled)
	if buildErr != nil {
		return sink.failOrFallback("failed to rebuild response: " + buildErr.Error())
	}

	logger.LogInfo(c, fmt.Sprintf("image upscale applied: %d image(s) processed by channel #%d model %s",
		len(upscaled), h.config.TargetChannelID, h.config.NormalizedTargetModel()))
	sink.writeFinal(newBody, "applied")
	return nil
}

// processStream upscales the images carried by image stream completed events
// and replays the captured SSE with the final payloads replaced. Everything
// else — partial previews, usage events, framing — is replayed verbatim.
func (h *imageUpscaleHook) processStream(c *gin.Context, imageReq *dto.ImageRequest, body []byte, sink *imageUpscaleSink) *types.NewAPIError {
	segments := strings.Split(string(body), "\n\n")
	payloads := make(map[int][]byte, 4)
	imageIndexes := make([]int, 0, 4)
	for i, segment := range segments {
		payload, ok := sseDataPayload(segment)
		if !ok || !isCompletedImagePayload(payload) {
			continue
		}
		payloads[i] = payload
		imageIndexes = append(imageIndexes, i)
	}
	if len(imageIndexes) == 0 {
		return sink.failOrFallback("stream response contains no completed image event")
	}

	for n, eventIndex := range imageIndexes {
		source, extractErr := extractStreamImage(c, payloads[eventIndex])
		if extractErr != nil {
			return sink.failOrFallback("failed to extract stream image: " + extractErr.Error())
		}
		entry, upscaleErr := h.upscaleOne(c, imageReq, source)
		if upscaleErr != nil {
			return sink.failOrFallback(fmt.Sprintf("stream image %d/%d via channel #%d model %s failed: %s",
				n+1, len(imageIndexes), h.config.TargetChannelID, h.config.NormalizedTargetModel(), upscaleErr.Error()))
		}
		newPayload, mutateErr := sjson.SetBytes(payloads[eventIndex], "b64_json", entry.base64Data)
		if mutateErr == nil {
			newPayload, mutateErr = sjson.DeleteBytes(newPayload, "url")
		}
		if mutateErr != nil {
			return sink.failOrFallback("failed to rebuild stream event: " + mutateErr.Error())
		}
		payloads[eventIndex] = newPayload
	}

	replayed := &bytes.Buffer{}
	replayed.Grow(len(body))
	for i, segment := range segments {
		if payload, ok := payloads[i]; ok {
			segment = rewriteSSEDataLine(segment, payload)
		}
		replayed.WriteString(segment)
		replayed.WriteString("\n\n")
	}

	logger.LogInfo(c, fmt.Sprintf("image upscale applied (stream): %d image(s) processed by channel #%d model %s",
		len(imageIndexes), h.config.TargetChannelID, h.config.NormalizedTargetModel()))
	sink.writeFinal(replayed.Bytes(), "applied")
	return nil
}

// isSSEPayload reports whether the captured body is a server-sent events
// stream rather than a plain JSON document.
func isSSEPayload(body []byte) bool {
	trimmed := bytes.TrimLeft(body, " \t\r\n")
	return bytes.HasPrefix(trimmed, []byte("event:")) || bytes.HasPrefix(trimmed, []byte("data:"))
}

// sseDataPayload returns the JSON payload of an event's single data line.
func sseDataPayload(segment string) ([]byte, bool) {
	for _, line := range strings.Split(segment, "\n") {
		payload, found := strings.CutPrefix(line, "data:")
		if !found {
			continue
		}
		payload = strings.TrimSpace(payload)
		if payload == "" || payload == "[DONE]" {
			return nil, false
		}
		return []byte(payload), true
	}
	return nil, false
}

// isCompletedImagePayload recognizes image stream events that carry a final
// image (image_generation.completed / image_edit.completed and variants).
func isCompletedImagePayload(payload []byte) bool {
	eventType := gjson.GetBytes(payload, "type").String()
	if !strings.HasSuffix(eventType, ".completed") {
		return false
	}
	return gjson.GetBytes(payload, "b64_json").Exists() || gjson.GetBytes(payload, "url").Exists()
}

// extractStreamImage converts one completed stream event payload into the
// source image bytes for the upscale relay.
func extractStreamImage(c *gin.Context, payload []byte) (upscaleSourceImage, error) {
	if b64 := gjson.GetBytes(payload, "b64_json"); b64.Exists() && b64.Type == gjson.String {
		decoded, err := decodeImageBase64(b64.String())
		if err != nil {
			return upscaleSourceImage{}, fmt.Errorf("failed to decode stream b64_json: %w", err)
		}
		return newUpscaleSourceImage(decoded), nil
	}
	if urlValue := gjson.GetBytes(payload, "url"); urlValue.Exists() && urlValue.Type == gjson.String {
		downloaded, err := downloadUpscaleSourceImage(c, urlValue.String())
		if err != nil {
			return upscaleSourceImage{}, fmt.Errorf("failed to download stream url: %w", err)
		}
		return newUpscaleSourceImage(downloaded), nil
	}
	return upscaleSourceImage{}, errors.New("stream event has neither b64_json nor url")
}

// rewriteSSEDataLine replaces the data line of one captured SSE event.
func rewriteSSEDataLine(segment string, payload []byte) string {
	lines := strings.Split(segment, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "data:") {
			lines[i] = "data: " + string(payload)
			break
		}
	}
	return strings.Join(lines, "\n")
}

// upscaleOne relays one generated image through the configured target channel
// and model as an OpenAI image edits request, and returns the upscaled image
// as base64. The inner call runs the standard relay pipeline, so the target
// model's pricing, model mapping, and consume log all apply unchanged.
func (h *imageUpscaleHook) upscaleOne(parent *gin.Context, imageReq *dto.ImageRequest, img upscaleSourceImage) (upscaledImageEntry, *types.NewAPIError) {
	targetModel := h.config.NormalizedTargetModel()
	channel, err := model.CacheGetChannel(h.config.TargetChannelID)
	if err != nil {
		return upscaledImageEntry{}, types.NewError(
			fmt.Errorf("failed to load upscale target channel #%d: %w", h.config.TargetChannelID, err),
			types.ErrorCodeGetChannelFailed, types.ErrOptionWithSkipRetry())
	}
	if channel.Status != common.ChannelStatusEnabled {
		return upscaledImageEntry{}, types.NewError(
			fmt.Errorf("upscale target channel #%d is disabled", channel.Id),
			types.ErrorCodeGetChannelFailed, types.ErrOptionWithSkipRetry())
	}

	prompt := strings.TrimSpace(imageReq.Prompt)
	if prompt == "" {
		prompt = "upscale"
	}

	multipartBody, contentType, buildErr := buildUpscaleEditBody(targetModel, prompt, img)
	if buildErr != nil {
		return upscaledImageEntry{}, types.NewError(buildErr, types.ErrorCodeConvertRequestFailed, types.ErrOptionWithSkipRetry())
	}

	recorder := httptest.NewRecorder()
	inner, _ := gin.CreateTestContext(recorder)
	inner.Keys = make(map[string]any, len(parent.Keys)+1)
	for key, value := range parent.Keys {
		inner.Keys[key] = value
	}
	inner.Set(imageUpscaleInternalFlag, true)
	inner.Request = httptest.NewRequestWithContext(parent.Request.Context(), http.MethodPost, "/v1/images/edits", bytes.NewReader(multipartBody))
	inner.Request.Header.Set("Content-Type", contentType)

	if setupErr := middleware.SetupContextForSelectedChannel(inner, channel, targetModel); setupErr != nil {
		return upscaledImageEntry{}, setupErr
	}

	ctx, cancel := context.WithTimeout(parent.Request.Context(), time.Duration(h.config.EffectiveTimeoutSeconds())*time.Second)
	defer cancel()
	inner.Request = inner.Request.WithContext(ctx)

	editRequest := &dto.ImageRequest{Model: targetModel, Prompt: prompt, N: common.GetPointer(uint(1))}
	innerInfo, genErr := relaycommon.GenRelayInfo(inner, types.RelayFormatOpenAIImage, editRequest, nil)
	if genErr != nil {
		return upscaledImageEntry{}, types.NewError(genErr, types.ErrorCodeGenRelayInfoFailed, types.ErrOptionWithSkipRetry())
	}
	if billingErr := PrepareRequestBilling(inner, innerInfo); billingErr != nil {
		return upscaledImageEntry{}, billingErr
	}
	if billingErr := service.PrepareTieredBillingForSelectedGroup(inner, innerInfo); billingErr != nil {
		refundFailedUpscaleBilling(inner, innerInfo, billingErr)
		return upscaledImageEntry{}, billingErr
	}
	innerInfo.InitChannelMeta(inner)
	if relayErr := ImageHelper(inner, innerInfo); relayErr != nil {
		refundFailedUpscaleBilling(inner, innerInfo, relayErr)
		return upscaledImageEntry{}, relayErr
	}

	return parseUpscaleEditResponse(inner, recorder.Body.Bytes())
}

func refundFailedUpscaleBilling(c *gin.Context, info *relaycommon.RelayInfo, apiErr *types.NewAPIError) {
	if err := RefundFailedRequestBilling(c, info, apiErr); err != nil {
		logger.LogWarn(c, "failed to refund upscale billing: "+err.Error())
	}
}

// buildUpscaleEditBody encodes one image as the canonical OpenAI image edits
// multipart payload that the target route receives through the relay pipeline.
func buildUpscaleEditBody(targetModel string, prompt string, img upscaleSourceImage) ([]byte, string, error) {
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	for field, value := range map[string]string{"model": targetModel, "prompt": prompt, "n": "1"} {
		if err := writer.WriteField(field, value); err != nil {
			return nil, "", fmt.Errorf("failed to write edits form field %s: %w", field, err)
		}
	}
	header := make(textproto.MIMEHeader)
	header.Set("Content-Disposition", fmt.Sprintf(`form-data; name="image"; filename=%q`, img.filename))
	header.Set("Content-Type", img.mimeType)
	part, err := writer.CreatePart(header)
	if err != nil {
		return nil, "", fmt.Errorf("failed to create edits image part: %w", err)
	}
	if _, err := part.Write(img.data); err != nil {
		return nil, "", fmt.Errorf("failed to write edits image part: %w", err)
	}
	if err := writer.Close(); err != nil {
		return nil, "", fmt.Errorf("failed to finalize edits body: %w", err)
	}
	return body.Bytes(), writer.FormDataContentType(), nil
}

// parseUpscaleEditResponse extracts the upscaled image from the inner relay
// response as base64, downloading url-mode results when necessary.
func parseUpscaleEditResponse(c *gin.Context, body []byte) (upscaledImageEntry, *types.NewAPIError) {
	invalid := func(message string) *types.NewAPIError {
		return types.NewError(errors.New("upscale "+message), types.ErrorCodeBadResponse, types.ErrOptionWithSkipRetry())
	}
	first := gjson.GetBytes(body, "data.0")
	if !first.Exists() {
		return upscaledImageEntry{}, invalid("response contains no image data")
	}
	if b64 := first.Get("b64_json"); b64.Exists() && b64.Type == gjson.String {
		normalized, err := normalizeImageBase64(b64.String())
		if err != nil {
			return upscaledImageEntry{}, invalid("response b64_json is invalid: " + err.Error())
		}
		return upscaledImageEntry{base64Data: normalized}, nil
	}
	if urlValue := first.Get("url"); urlValue.Exists() && urlValue.Type == gjson.String {
		downloaded, err := downloadUpscaleSourceImage(c, urlValue.String())
		if err != nil {
			return upscaledImageEntry{}, invalid("response url download failed: " + err.Error())
		}
		return upscaledImageEntry{base64Data: base64.StdEncoding.EncodeToString(downloaded)}, nil
	}
	return upscaledImageEntry{}, invalid("response has neither b64_json nor url")
}

// extractGeneratedImages collects every generated image from the buffered
// generation response as raw bytes, in order.
func extractGeneratedImages(c *gin.Context, body []byte) ([]upscaleSourceImage, error) {
	data := gjson.GetBytes(body, "data")
	if !data.IsArray() {
		return nil, errors.New("generation response data is not an array")
	}
	entries := data.Array()
	images := make([]upscaleSourceImage, 0, len(entries))
	for i, entry := range entries {
		if b64 := entry.Get("b64_json"); b64.Exists() && b64.Type == gjson.String {
			decoded, err := decodeImageBase64(b64.String())
			if err != nil {
				return nil, fmt.Errorf("failed to decode data[%d].b64_json: %w", i, err)
			}
			images = append(images, newUpscaleSourceImage(decoded))
			continue
		}
		if urlValue := entry.Get("url"); urlValue.Exists() && urlValue.Type == gjson.String {
			downloaded, err := downloadUpscaleSourceImage(c, urlValue.String())
			if err != nil {
				return nil, fmt.Errorf("failed to download data[%d].url: %w", i, err)
			}
			images = append(images, newUpscaleSourceImage(downloaded))
			continue
		}
		return nil, fmt.Errorf("data[%d] has neither b64_json nor url", i)
	}
	return images, nil
}

// rebuildImageResponse replaces the data array with the upscaled images and
// keeps the original created timestamp and usage untouched.
func rebuildImageResponse(originalBody []byte, upscaled []upscaledImageEntry) ([]byte, error) {
	root := gjson.ParseBytes(originalBody)
	originalData := root.Get("data").Array()

	type rebuiltImageEntry struct {
		B64Json       string `json:"b64_json"`
		RevisedPrompt string `json:"revised_prompt,omitempty"`
	}
	payload := struct {
		Created int64               `json:"created"`
		Data    []rebuiltImageEntry `json:"data"`
		Usage   json.RawMessage     `json:"usage,omitempty"`
	}{Data: make([]rebuiltImageEntry, 0, len(upscaled))}
	if created := root.Get("created"); created.Exists() {
		payload.Created = created.Int()
	} else {
		payload.Created = time.Now().Unix()
	}
	if usage := root.Get("usage"); usage.Exists() && usage.Raw != "" && usage.Raw != "null" {
		payload.Usage = json.RawMessage(usage.Raw)
	}
	for i := range upscaled {
		entry := rebuiltImageEntry{B64Json: upscaled[i].base64Data}
		if i < len(originalData) {
			entry.RevisedPrompt = originalData[i].Get("revised_prompt").String()
		}
		payload.Data = append(payload.Data, entry)
	}
	return common.Marshal(payload)
}

func newUpscaleSourceImage(data []byte) upscaleSourceImage {
	mimeType := http.DetectContentType(data)
	if !strings.HasPrefix(mimeType, "image/") {
		mimeType = "image/png"
	}
	return upscaleSourceImage{
		data:     data,
		filename: "image" + imageMimeExtension(mimeType),
		mimeType: mimeType,
	}
}

func imageMimeExtension(mimeType string) string {
	switch mimeType {
	case "image/jpeg":
		return ".jpg"
	case "image/webp":
		return ".webp"
	case "image/gif":
		return ".gif"
	default:
		return ".png"
	}
}

// decodeImageBase64 decodes a raw or data-url base64 image payload.
func decodeImageBase64(value string) ([]byte, error) {
	if _, rest, found := strings.Cut(value, ";base64,"); found {
		value = rest
	} else if strings.HasPrefix(value, "data:") {
		return nil, errors.New("unsupported data url")
	}
	value = strings.TrimSpace(value)
	maxEncoded := maxImageUpscaleImageBytes/3*4 + 4
	if len(value) > maxEncoded {
		return nil, fmt.Errorf("image exceeds %d bytes", maxImageUpscaleImageBytes)
	}
	decoded := make([]byte, base64.StdEncoding.DecodedLen(len(value)))
	n, err := base64.StdEncoding.Decode(decoded, []byte(value))
	if err != nil {
		n, err = base64.RawStdEncoding.Decode(decoded, []byte(value))
		if err != nil {
			return nil, err
		}
	}
	return decoded[:n], nil
}

// normalizeImageBase64 returns the base64 payload without a data-url prefix.
func normalizeImageBase64(value string) (string, error) {
	if _, rest, found := strings.Cut(value, ";base64,"); found {
		value = rest
	} else if strings.HasPrefix(value, "data:") {
		return "", errors.New("unsupported data url")
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return "", errors.New("empty base64 payload")
	}
	return value, nil
}

// downloadUpscaleSourceImage fetches an http(s) image url through the shared
// protected download path (SSRF validation and optional worker offload) with a
// bounded size.
func downloadUpscaleSourceImage(c *gin.Context, rawURL string) ([]byte, error) {
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, errors.New("invalid image url")
	}
	resp, err := service.DoDownloadRequest(parsed.String(), "image upscale")
	if err != nil {
		return nil, err
	}
	defer service.CloseResponseBodyGracefully(resp)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d", resp.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxImageUpscaleImageBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxImageUpscaleImageBytes {
		return nil, fmt.Errorf("image exceeds %d bytes", maxImageUpscaleImageBytes)
	}
	return data, nil
}
