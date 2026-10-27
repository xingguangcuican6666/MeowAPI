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
	"encoding/base64"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	relaycommon "github.com/QuantumNous/new-api/relay/common"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/QuantumNous/new-api/service"
	"github.com/QuantumNous/new-api/setting/system_setting"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var testUpscalePNG = append([]byte{0x89, 'P', 'N', 'G', 0x0D, 0x0A, 0x1A, 0x0A}, make([]byte, 16)...)

func newHookTestContext(t *testing.T) *gin.Context {
	t.Helper()
	c, _ := gin.CreateTestContext(httptest.NewRecorder())
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/images/generations", nil)
	return c
}

// initTestDownloadPath initializes the shared outbound http client and disables
// SSRF protection so url-mode tests can reach the local httptest server. The
// previous fetch settings are restored when the test ends.
func initTestDownloadPath(t *testing.T) {
	t.Helper()
	service.InitHttpClient()
	fetchSetting := system_setting.GetFetchSetting()
	previousProtection := fetchSetting.EnableSSRFProtection
	previousPrivateIP := fetchSetting.AllowPrivateIp
	fetchSetting.EnableSSRFProtection = false
	fetchSetting.AllowPrivateIp = true
	t.Cleanup(func() {
		fetchSetting.EnableSSRFProtection = previousProtection
		fetchSetting.AllowPrivateIp = previousPrivateIP
	})
}

func TestImageUpscaleConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *dto.ImageUpscaleConfig
		wantErr bool
	}{
		{"nil config", nil, false},
		{"disabled incomplete", &dto.ImageUpscaleConfig{Enabled: false}, false},
		{"enabled valid", &dto.ImageUpscaleConfig{Enabled: true, TargetChannelID: 166, TargetModel: "upscale-nomos-2x"}, false},
		{"enabled with policy and timeout", &dto.ImageUpscaleConfig{Enabled: true, TargetChannelID: 1, TargetModel: " m ", OnError: "fail", TimeoutSeconds: 10}, false},
		{"enabled missing channel", &dto.ImageUpscaleConfig{Enabled: true, TargetModel: "m"}, true},
		{"enabled zero channel", &dto.ImageUpscaleConfig{Enabled: true, TargetChannelID: 0, TargetModel: "m"}, true},
		{"enabled missing model", &dto.ImageUpscaleConfig{Enabled: true, TargetChannelID: 1}, true},
		{"enabled blank model", &dto.ImageUpscaleConfig{Enabled: true, TargetChannelID: 1, TargetModel: "   "}, true},
		{"invalid on_error", &dto.ImageUpscaleConfig{Enabled: true, TargetChannelID: 1, TargetModel: "m", OnError: "explode"}, true},
		{"negative timeout", &dto.ImageUpscaleConfig{Enabled: true, TargetChannelID: 1, TargetModel: "m", TimeoutSeconds: -1}, true},
		{"timeout above max", &dto.ImageUpscaleConfig{Enabled: true, TargetChannelID: 1, TargetModel: "m", TimeoutSeconds: 3601}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestImageUpscaleConfigDefaults(t *testing.T) {
	config := &dto.ImageUpscaleConfig{}
	assert.Equal(t, dto.ImageUpscaleOnErrorFallback, config.NormalizedOnError())
	assert.Equal(t, 300, config.EffectiveTimeoutSeconds())

	config = &dto.ImageUpscaleConfig{OnError: "FAIL", TimeoutSeconds: 99999}
	assert.Equal(t, dto.ImageUpscaleOnErrorFail, config.NormalizedOnError())
	assert.Equal(t, 3600, config.EffectiveTimeoutSeconds())

	config = &dto.ImageUpscaleConfig{TimeoutSeconds: 15}
	assert.Equal(t, 15, config.EffectiveTimeoutSeconds())
}

func TestImageUpscaleConfigMatchesModel(t *testing.T) {
	config := &dto.ImageUpscaleConfig{}
	assert.True(t, config.MatchesModel("gpt-image-2.5-flare"), "empty allowlist matches everything")

	config = &dto.ImageUpscaleConfig{Models: []string{" gpt-image-2.5-flare ", "", "gpt-image-2.5-sunburst"}}
	assert.True(t, config.MatchesModel("gpt-image-2.5-flare"))
	assert.True(t, config.MatchesModel("gpt-image-2.5-sunburst"))
	assert.False(t, config.MatchesModel("gpt-image-2.5-other"))
	assert.False(t, config.MatchesModel("  "), "blank model names never match")

	config = &dto.ImageUpscaleConfig{Models: []string{"   "}}
	assert.True(t, config.MatchesModel("gpt-image-2.5-flare"), "blank-only allowlist degenerates to no restriction")
}

func TestImageUpscaleCaptureTruncation(t *testing.T) {
	capture := &imageUpscaleCapture{limit: 8}
	captureCtx, _ := gin.CreateTestContext(httptest.NewRecorder())
	writer := &imageUpscaleCaptureWriter{ResponseWriter: captureCtx.Writer, capture: capture}

	writer.WriteHeader(http.StatusCreated)
	n, err := writer.Write([]byte("0123"))
	require.NoError(t, err)
	assert.Equal(t, 4, n)
	assert.False(t, capture.truncated)

	// A write that would exceed the limit is dropped whole and keeps reporting
	// success so the relay path is unaffected.
	n, err = writer.Write([]byte("01234567"))
	require.NoError(t, err)
	assert.Equal(t, 8, n)
	assert.True(t, capture.truncated)
	assert.Equal(t, 4, capture.body.Len())
	assert.Equal(t, http.StatusCreated, capture.status)
}

func TestDecodeAndNormalizeImageBase64(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString(testUpscalePNG)

	decoded, err := decodeImageBase64(encoded)
	require.NoError(t, err)
	assert.Equal(t, testUpscalePNG, decoded)

	decoded, err = decodeImageBase64("data:image/png;base64," + encoded)
	require.NoError(t, err)
	assert.Equal(t, testUpscalePNG, decoded)

	normalized, err := normalizeImageBase64("data:image/png;base64," + encoded)
	require.NoError(t, err)
	assert.Equal(t, encoded, normalized)

	normalized, err = normalizeImageBase64(" " + encoded + " ")
	require.NoError(t, err)
	assert.Equal(t, encoded, normalized)

	_, err = decodeImageBase64("data:text/html;base64,!!!not base64!!!")
	require.Error(t, err)

	_, err = decodeImageBase64("data:text/html,inline")
	require.Error(t, err)

	_, err = normalizeImageBase64("data:image/png;base64,   ")
	require.Error(t, err)
}

func TestNewUpscaleSourceImage(t *testing.T) {
	img := newUpscaleSourceImage(testUpscalePNG)
	assert.Equal(t, "image/png", img.mimeType)
	assert.Equal(t, "image.png", img.filename)

	jpeg := append([]byte{0xFF, 0xD8, 0xFF, 0xE0}, make([]byte, 12)...)
	img = newUpscaleSourceImage(jpeg)
	assert.Equal(t, "image/jpeg", img.mimeType)
	assert.Equal(t, "image.jpg", img.filename)
}

func TestBuildUpscaleEditBody(t *testing.T) {
	img := newUpscaleSourceImage(testUpscalePNG)
	body, contentType, err := buildUpscaleEditBody("upscale-nomos-2x", "a cat", img)
	require.NoError(t, err)
	require.NotEmpty(t, contentType)

	mediaType, params, err := mime.ParseMediaType(contentType)
	require.NoError(t, err)
	assert.Equal(t, "multipart/form-data", mediaType)

	reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	form, err := reader.ReadForm(1 << 20)
	require.NoError(t, err)
	defer func() { _ = form.RemoveAll() }()

	assert.Equal(t, []string{"upscale-nomos-2x"}, form.Value["model"])
	assert.Equal(t, []string{"a cat"}, form.Value["prompt"])
	assert.Equal(t, []string{"1"}, form.Value["n"])
	require.Len(t, form.File["image"], 1)
	file, err := form.File["image"][0].Open()
	require.NoError(t, err)
	content, err := io.ReadAll(file)
	require.NoError(t, err)
	require.NoError(t, file.Close())
	assert.Equal(t, testUpscalePNG, content)
}

func TestExtractGeneratedImages(t *testing.T) {
	t.Run("b64 entries keep order", func(t *testing.T) {
		c := newHookTestContext(t)
		first := base64.StdEncoding.EncodeToString(testUpscalePNG)
		second := base64.StdEncoding.EncodeToString([]byte("second-image"))
		body := fmt.Sprintf(`{"created":1,"data":[{"b64_json":"%s","revised_prompt":"p1"},{"b64_json":"%s"}]}`, first, second)

		images, err := extractGeneratedImages(c, []byte(body))
		require.NoError(t, err)
		require.Len(t, images, 2)
		assert.Equal(t, testUpscalePNG, images[0].data)
		assert.Equal(t, []byte("second-image"), images[1].data)
		assert.Equal(t, "image.png", images[0].filename)
	})

	t.Run("url entries are downloaded", func(t *testing.T) {
		initTestDownloadPath(t)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(testUpscalePNG)
		}))
		defer server.Close()
		c := newHookTestContext(t)
		body := fmt.Sprintf(`{"data":[{"url":%q}]}`, server.URL+"/img.png")

		images, err := extractGeneratedImages(c, []byte(body))
		require.NoError(t, err)
		require.Len(t, images, 1)
		assert.Equal(t, testUpscalePNG, images[0].data)
	})

	t.Run("rejects url with unexpected status", func(t *testing.T) {
		initTestDownloadPath(t)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusNotFound)
		}))
		defer server.Close()
		c := newHookTestContext(t)
		body := fmt.Sprintf(`{"data":[{"url":%q}]}`, server.URL)

		_, err := extractGeneratedImages(c, []byte(body))
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unexpected status 404")
	})

	t.Run("entry without image fields", func(t *testing.T) {
		c := newHookTestContext(t)
		_, err := extractGeneratedImages(c, []byte(`{"data":[{"revised_prompt":"p"}]}`))
		require.Error(t, err)
	})

	t.Run("data is not an array", func(t *testing.T) {
		c := newHookTestContext(t)
		_, err := extractGeneratedImages(c, []byte(`{"data":{}}`))
		require.Error(t, err)
	})
}

func TestParseUpscaleEditResponse(t *testing.T) {
	t.Run("b64_json", func(t *testing.T) {
		c := newHookTestContext(t)
		encoded := base64.StdEncoding.EncodeToString(testUpscalePNG)
		entry, apiErr := parseUpscaleEditResponse(c, []byte(fmt.Sprintf(`{"data":[{"b64_json":"%s"}]}`, encoded)))
		require.Nil(t, apiErr)
		assert.Equal(t, encoded, entry.base64Data)
	})

	t.Run("url", func(t *testing.T) {
		initTestDownloadPath(t)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(testUpscalePNG)
		}))
		defer server.Close()
		c := newHookTestContext(t)
		entry, apiErr := parseUpscaleEditResponse(c, []byte(fmt.Sprintf(`{"data":[{"url":%q}]}`, server.URL)))
		require.Nil(t, apiErr)
		assert.Equal(t, base64.StdEncoding.EncodeToString(testUpscalePNG), entry.base64Data)
	})

	t.Run("missing data", func(t *testing.T) {
		c := newHookTestContext(t)
		_, apiErr := parseUpscaleEditResponse(c, []byte(`{"created":1}`))
		require.NotNil(t, apiErr)
		assert.Contains(t, apiErr.Error(), "no image data")
	})
}

func TestRebuildImageResponse(t *testing.T) {
	original := `{"created":1700000000,"usage":{"input_tokens":10,"output_tokens":20,"total_tokens":30},` +
		`"data":[{"b64_json":"old","revised_prompt":"a cat in space"},{"b64_json":"old2"}]}`
	upscaled := []upscaledImageEntry{{base64Data: "new1"}, {base64Data: "new2"}}

	rebuilt, err := rebuildImageResponse([]byte(original), upscaled)
	require.NoError(t, err)

	assert.True(t, strings.Contains(string(rebuilt), `"created":1700000000`))
	assert.True(t, strings.Contains(string(rebuilt), `"revised_prompt":"a cat in space"`))
	assert.True(t, strings.Contains(string(rebuilt), `"input_tokens":10`))
	assert.False(t, strings.Contains(string(rebuilt), `"old"`))

	// created defaults to a timestamp when the original has none
	rebuilt, err = rebuildImageResponse([]byte(`{"data":[]}`), nil)
	require.NoError(t, err)
	assert.True(t, strings.Contains(string(rebuilt), `"created":1`))
}

func newArmTestInfo(other dto.ChannelOtherSettings, isStream bool, isChannelTest bool) *relaycommon.RelayInfo {
	info := &relaycommon.RelayInfo{IsStream: isStream, IsChannelTest: isChannelTest}
	info.ChannelMeta = &relaycommon.ChannelMeta{ChannelOtherSettings: other}
	return info
}

func TestArmImageUpscaleHook(t *testing.T) {
	enabled := dto.ChannelOtherSettings{ImageUpscale: &dto.ImageUpscaleConfig{Enabled: true, TargetChannelID: 166, TargetModel: "upscale-nomos-2x"}}
	disabled := dto.ChannelOtherSettings{ImageUpscale: &dto.ImageUpscaleConfig{Enabled: false}}

	c := newHookTestContext(t)
	assert.Nil(t, armImageUpscaleHook(c, newArmTestInfo(disabled, false, false)))
	assert.Nil(t, armImageUpscaleHook(c, newArmTestInfo(dto.ChannelOtherSettings{}, false, false)))

	hook := armImageUpscaleHook(c, newArmTestInfo(enabled, false, false))
	require.NotNil(t, hook)
	assert.NotNil(t, hook.writer(c.Writer))

	// Stream requests arm the hook too; the SSE replay happens after capture.
	streamInfo := newArmTestInfo(enabled, true, false)
	assert.NotNil(t, armImageUpscaleHook(c, streamInfo))

	channelTestInfo := newArmTestInfo(enabled, false, true)
	assert.Nil(t, armImageUpscaleHook(c, channelTestInfo))

	internal := newHookTestContext(t)
	internal.Set(imageUpscaleInternalFlag, true)
	assert.Nil(t, armImageUpscaleHook(internal, newArmTestInfo(enabled, false, false)))
}

func TestImageUpscaleProcessFallbackOnExtractFailure(t *testing.T) {
	original := `{"created":7,"data":[{"b64_json":"not-valid-base64!!!"}]}`
	capture := &imageUpscaleCapture{limit: maxImageUpscaleBodyBytes}
	_, err := capture.body.WriteString(original)
	require.NoError(t, err)
	capture.status = http.StatusOK

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/images/generations", nil)

	hook := &imageUpscaleHook{
		config:  &dto.ImageUpscaleConfig{Enabled: true, TargetChannelID: 166, TargetModel: "upscale-nomos-2x"},
		capture: capture,
	}
	info := newArmTestInfo(dto.ChannelOtherSettings{}, false, false)
	apiErr := hook.process(c, info, &dto.ImageRequest{Prompt: "a cat"})
	require.Nil(t, apiErr)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "fallback", recorder.Header().Get(imageUpscaleHeader))
	assert.Equal(t, original, recorder.Body.String())
	assert.Equal(t, fmt.Sprintf("%d", len(original)), recorder.Header().Get("Content-Length"))
}

func TestImageUpscaleProcessFailsWhenPolicyIsFail(t *testing.T) {
	original := `{"created":7,"data":[{"b64_json":"not-valid-base64!!!"}]}`
	capture := &imageUpscaleCapture{limit: maxImageUpscaleBodyBytes}
	_, err := capture.body.WriteString(original)
	require.NoError(t, err)
	capture.status = http.StatusOK

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/images/generations", nil)

	hook := &imageUpscaleHook{
		config: &dto.ImageUpscaleConfig{
			Enabled:         true,
			TargetChannelID: 166,
			TargetModel:     "upscale-nomos-2x",
			OnError:         dto.ImageUpscaleOnErrorFail,
		},
		capture: capture,
	}
	info := newArmTestInfo(dto.ChannelOtherSettings{}, false, false)
	apiErr := hook.process(c, info, &dto.ImageRequest{Prompt: "a cat"})
	require.NotNil(t, apiErr)
	assert.Contains(t, apiErr.Error(), "image upscale failed")
	// The original generation is never leaked to the client on the fail policy.
	assert.Empty(t, recorder.Body.String())
}

// guard against accidental truncation of a normal payload
func TestImageUpscaleCaptureAcceptsNormalPayload(t *testing.T) {
	capture := &imageUpscaleCapture{limit: maxImageUpscaleBodyBytes}
	payload := bytes.Repeat([]byte("a"), 1<<20)
	n, err := capture.write(payload)
	require.NoError(t, err)
	assert.Equal(t, len(payload), n)
	assert.False(t, capture.truncated)
}

func TestSSEPayloadHelpers(t *testing.T) {
	assert.True(t, isSSEPayload([]byte("event: image_generation.completed\ndata: {}\n\n")))
	assert.True(t, isSSEPayload([]byte("data: {}\n\n")))
	assert.False(t, isSSEPayload([]byte(`{"created":1}`)))
	assert.False(t, isSSEPayload(nil))

	_, ok := sseDataPayload("event: x\ndata: [DONE]")
	assert.False(t, ok)
	_, ok = sseDataPayload("event: x\ndata:")
	assert.False(t, ok)
	payload, ok := sseDataPayload("event: image_generation.completed\ndata: {\"type\":\"image_generation.completed\"}")
	require.True(t, ok)
	assert.Equal(t, `{"type":"image_generation.completed"}`, string(payload))

	assert.True(t, isCompletedImagePayload([]byte(`{"type":"image_generation.completed","b64_json":"abc"}`)))
	assert.True(t, isCompletedImagePayload([]byte(`{"type":"image_edit.completed","url":"https://x/y.png"}`)))
	assert.False(t, isCompletedImagePayload([]byte(`{"type":"image_generation.partial_image","b64_json":"abc"}`)))
	assert.False(t, isCompletedImagePayload([]byte(`{"type":"image_generation.completed"}`)))

	rewritten := rewriteSSEDataLine("event: image_generation.completed\ndata: {\"old\":true}", []byte(`{"new":true}`))
	assert.Equal(t, "event: image_generation.completed\ndata: {\"new\":true}", rewritten)
}

func TestImageUpscaleProcessStreamFallsBackWithoutCompletedImage(t *testing.T) {
	original := "event: image_generation.partial_image\ndata: {\"type\":\"image_generation.partial_image\",\"b64_json\":\"abc\"}\n\n" +
		"data: [DONE]\n\n"
	capture := &imageUpscaleCapture{limit: maxImageUpscaleBodyBytes}
	_, err := capture.body.WriteString(original)
	require.NoError(t, err)
	capture.status = http.StatusOK

	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/v1/images/generations", nil)

	hook := &imageUpscaleHook{
		config:  &dto.ImageUpscaleConfig{Enabled: true, TargetChannelID: 166, TargetModel: "upscale-nomos-2x"},
		capture: capture,
	}
	info := newArmTestInfo(dto.ChannelOtherSettings{}, false, false)
	apiErr := hook.process(c, info, &dto.ImageRequest{Prompt: "a cat"})
	require.Nil(t, apiErr)

	assert.Equal(t, http.StatusOK, recorder.Code)
	assert.Equal(t, "fallback", recorder.Header().Get(imageUpscaleHeader))
	assert.Equal(t, original, recorder.Body.String())
	assert.Empty(t, recorder.Header().Get("Content-Length"), "SSE replay must not carry a Content-Length")
}
