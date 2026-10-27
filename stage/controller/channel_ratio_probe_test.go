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

package controller

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func ratioProbeFloat(value float64) *float64 {
	return &value
}

func TestParseUpstreamGroupRatios(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		want    map[string]float64
		wantErr string
	}{
		{
			name: "management envelope",
			body: `{"success":true,"message":"","data":{"model_ratio":{"gpt-4":15},"group_ratio":{"default":1,"vip":0.8}}}`,
			want: map[string]float64{"default": 1, "vip": 0.8},
		},
		{
			name: "bare document",
			body: `{"group_ratio":{"default":2}}`,
			want: map[string]float64{"default": 2},
		},
		{
			name: "non numeric and negative entries are dropped",
			body: `{"group_ratio":{"default":1,"broken":"1.0","negative":-1}}`,
			want: map[string]float64{"default": 1},
		},
		{
			name:    "upstream failure",
			body:    `{"success":false,"message":"倍率配置接口未启用"}`,
			wantErr: "倍率配置接口未启用",
		},
		{
			name:    "upstream failure without message",
			body:    `{"success":false}`,
			wantErr: "upstream reported failure",
		},
		{
			name:    "group ratio missing",
			body:    `{"success":true,"data":{"model_ratio":{"gpt-4":15}}}`,
			wantErr: "does not expose group_ratio",
		},
		{
			name:    "group ratio has no usable entry",
			body:    `{"success":true,"data":{"group_ratio":{"default":"free"}}}`,
			wantErr: "no usable entries",
		},
		{
			name:    "invalid JSON",
			body:    `not json`,
			wantErr: "invalid ratio config response",
		},
		{
			name:    "pricing list payload",
			body:    `{"success":true,"data":[{"model_name":"gpt-4"}]}`,
			wantErr: "does not expose group_ratio",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ratios, err := parseUpstreamGroupRatios([]byte(tt.body))
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, ratios)
		})
	}
}

func TestBuildChannelRatioProbeURL(t *testing.T) {
	customBaseURL := "https://relay.example"
	tests := []struct {
		name    string
		channel *model.Channel
		config  *dto.RatioProbeConfig
		want    string
		wantErr string
	}{
		{
			name:    "follow api uses the channel base URL",
			channel: &model.Channel{BaseURL: &customBaseURL},
			config:  &dto.RatioProbeConfig{Enabled: true, MaxGroupRatio: ratioProbeFloat(1)},
			want:    "https://relay.example/api/ratio_config",
		},
		{
			name:    "custom source ignores the channel base URL",
			channel: &model.Channel{BaseURL: &customBaseURL},
			config: &dto.RatioProbeConfig{
				Enabled: true,
				Source:  dto.RatioProbeSourceCustom,
				BaseURL: "https://probe.example/",
				Path:    "/api/pricing",
			},
			want: "https://probe.example/api/pricing",
		},
		{
			name:    "follow api without a base URL",
			channel: &model.Channel{},
			config:  &dto.RatioProbeConfig{Enabled: true},
			wantErr: "base URL is empty",
		},
		{
			name:    "follow api with an unusable base URL",
			channel: &model.Channel{BaseURL: ratioProbeStringPointer("relay.example")},
			config:  &dto.RatioProbeConfig{Enabled: true},
			wantErr: "absolute HTTP or HTTPS URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestURL, err := buildChannelRatioProbeURL(tt.channel, tt.config)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tt.want, requestURL)
		})
	}
}

func TestBuildChannelRatioProbeTestResults(t *testing.T) {
	channel := &model.Channel{
		Key: "sk-a\nsk-b",
		ChannelInfo: model.ChannelInfo{
			IsMultiKey: true,
		},
	}
	config := &dto.RatioProbeConfig{
		Enabled:       true,
		MaxGroupRatio: ratioProbeFloat(1),
	}

	results := buildChannelRatioProbeTestResults(channel, config, []ratioProbeDecision{
		{key: "sk-a", compliant: true, ratio: 0.8},
		{key: "sk-b", ratio: 1.2, message: "group default ratio 1.2 exceeds max 1"},
		{key: "sk-c", failed: true, message: "status code: 502"},
	})

	require.Len(t, results, 3)
	assert.Equal(t, dto.RatioProbeStatusCompliant, results[0].Status)
	require.NotNil(t, results[0].KeyIndex)
	assert.Equal(t, 1, *results[0].KeyIndex)
	require.NotNil(t, results[0].Ratio)
	assert.Equal(t, 0.8, *results[0].Ratio)

	assert.Equal(t, dto.RatioProbeStatusRejected, results[1].Status)
	require.NotNil(t, results[1].KeyIndex)
	assert.Equal(t, 2, *results[1].KeyIndex)
	assert.Equal(t, "group default ratio 1.2 exceeds max 1", results[1].Message)

	assert.Equal(t, dto.RatioProbeStatusError, results[2].Status)
	assert.Nil(t, results[2].Ratio)
	assert.Nil(t, results[2].KeyIndex)
}

func TestBuildChannelRatioProbeTestResultsMarksDisabledProbeUnconfigured(t *testing.T) {
	channel := &model.Channel{Key: "sk-a"}
	config := &dto.RatioProbeConfig{}

	results := buildChannelRatioProbeTestResults(channel, config, []ratioProbeDecision{
		{key: "sk-a", compliant: true, ratio: 1},
	})

	require.Len(t, results, 1)
	assert.Equal(t, dto.RatioProbeStatusUnconfigured, results[0].Status)
	require.NotNil(t, results[0].Ratio)
	assert.Equal(t, 1.0, *results[0].Ratio)
}

func TestChannelRatioProbeConfiguredAuthorization(t *testing.T) {
	receivedAuthorization := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		receivedAuthorization <- request.Header.Get("Authorization")
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"group_ratio":{"default":1}}`))
	}))
	defer server.Close()

	useAPIKey := true
	skipAPIKey := false
	tests := []struct {
		name          string
		useAPIKey     *bool
		authorization string
		wantHeader    string
	}{
		{
			name:       "default sends the probed key as the bearer token",
			wantHeader: "Bearer channel-key",
		},
		{
			name:          "the channel key wins over a configured header",
			useAPIKey:     &useAPIKey,
			authorization: "Basic configured-token",
			wantHeader:    "Bearer channel-key",
		},
		{
			name:          "the configured header replaces the channel key",
			useAPIKey:     &skipAPIKey,
			authorization: "  Basic configured-token  ",
			wantHeader:    "Basic configured-token",
		},
		{
			name:      "no header is sent without a configured value",
			useAPIKey: &skipAPIKey,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := &dto.RatioProbeConfig{
				Enabled:       true,
				MaxGroupRatio: ratioProbeFloat(1),
				UseAPIKey:     tt.useAPIKey,
				Authorization: tt.authorization,
			}
			runner := newChannelRatioProbeRunner(context.Background())
			decision := runner.probeKey(config, server.URL, "", "channel-key")

			require.False(t, decision.failed, decision.message)
			assert.Equal(t, tt.wantHeader, <-receivedAuthorization)
		})
	}
}

func ratioProbeStringPointer(value string) *string {
	return &value
}

func TestApplySingleKeyRatioProbeDecision(t *testing.T) {
	probeDisabled := &model.Channel{Status: common.ChannelStatusAutoDisabled, Key: "sk-a"}
	setChannelRatioProbeStatusReason(probeDisabled, "group default ratio 2 exceeds max 1")

	relayDisabled := &model.Channel{Status: common.ChannelStatusAutoDisabled, Key: "sk-a"}
	relayDisabled.SetOtherInfo(map[string]interface{}{"status_reason": "invalid api key"})

	tests := []struct {
		name       string
		channel    *model.Channel
		decision   ratioProbeDecision
		wantStatus int
		wantChange bool
	}{
		{
			name:       "non compliant disables an enabled channel",
			channel:    &model.Channel{Status: common.ChannelStatusEnabled, Key: "sk-a"},
			decision:   ratioProbeDecision{key: "sk-a", message: "group default ratio 2 exceeds max 1"},
			wantStatus: common.ChannelStatusAutoDisabled,
			wantChange: true,
		},
		{
			name:       "compliant restores a probe disabled channel",
			channel:    probeDisabled,
			decision:   ratioProbeDecision{key: "sk-a", compliant: true, ratio: 1},
			wantStatus: common.ChannelStatusEnabled,
			wantChange: true,
		},
		{
			name:       "compliant leaves a relay disabled channel alone",
			channel:    relayDisabled,
			decision:   ratioProbeDecision{key: "sk-a", compliant: true, ratio: 1},
			wantStatus: common.ChannelStatusAutoDisabled,
		},
		{
			name:       "probe failure changes nothing",
			channel:    &model.Channel{Status: common.ChannelStatusEnabled, Key: "sk-a"},
			decision:   ratioProbeDecision{key: "sk-a", failed: true, message: "status code: 502"},
			wantStatus: common.ChannelStatusEnabled,
		},
		{
			name:       "a rotated key leaves the channel untouched",
			channel:    &model.Channel{Status: common.ChannelStatusEnabled, Key: "sk-new"},
			decision:   ratioProbeDecision{key: "sk-a", message: "group default ratio 2 exceeds max 1"},
			wantStatus: common.ChannelStatusEnabled,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := channelRatioProbeResult{}
			byKey := map[string]ratioProbeDecision{tt.decision.key: tt.decision}
			applySingleKeyRatioProbeDecision(tt.channel, byKey, &result)
			assert.Equal(t, tt.wantStatus, tt.channel.Status)
			assert.Equal(t, tt.wantChange, result.statusChanged)
		})
	}
}

func TestSummarizeRatioProbeDecisions(t *testing.T) {
	tests := []struct {
		name        string
		decisions   []ratioProbeDecision
		wantStatus  string
		wantMessage string
		wantRatio   *float64
	}{
		{
			name:       "all compliant reports the highest ratio",
			decisions:  []ratioProbeDecision{{key: "a", compliant: true, ratio: 0.5}, {key: "b", compliant: true, ratio: 0.9}},
			wantStatus: dto.RatioProbeStatusCompliant,
			wantRatio:  ratioProbeFloat(0.9),
		},
		{
			name: "one rejection wins over compliant keys",
			decisions: []ratioProbeDecision{
				{key: "a", compliant: true, ratio: 0.5},
				{key: "b", ratio: 2, message: "group default ratio 2 exceeds max 1"},
			},
			wantStatus:  dto.RatioProbeStatusRejected,
			wantMessage: "group default ratio 2 exceeds max 1",
			wantRatio:   ratioProbeFloat(2),
		},
		{
			name: "errors are reported only when nothing succeeded",
			decisions: []ratioProbeDecision{
				{key: "a", failed: true, message: "status code: 502"},
				{key: "b", compliant: true, ratio: 1},
			},
			wantStatus: dto.RatioProbeStatusCompliant,
			wantRatio:  ratioProbeFloat(1),
		},
		{
			name:        "all failed",
			decisions:   []ratioProbeDecision{{key: "a", failed: true, message: "status code: 502"}},
			wantStatus:  dto.RatioProbeStatusError,
			wantMessage: "status code: 502",
		},
		{
			name:        "no decisions",
			wantStatus:  dto.RatioProbeStatusError,
			wantMessage: "probe produced no result",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			status, message, ratio := summarizeRatioProbeDecisions(tt.decisions)
			assert.Equal(t, tt.wantStatus, status)
			assert.Equal(t, tt.wantMessage, message)
			if tt.wantRatio == nil {
				assert.Nil(t, ratio)
				return
			}
			require.NotNil(t, ratio)
			assert.InDelta(t, *tt.wantRatio, *ratio, 1e-9)
		})
	}
}

func TestApplyMultiKeyRatioProbeDecisions(t *testing.T) {
	channel := &model.Channel{
		Status: common.ChannelStatusEnabled,
		Key:    "sk-a\nsk-b\nsk-c",
		ChannelInfo: model.ChannelInfo{
			IsMultiKey:   true,
			MultiKeySize: 3,
			MultiKeyStatusList: map[int]int{
				2: common.ChannelStatusManuallyDisabled,
			},
		},
	}

	result := channelRatioProbeResult{}
	applyMultiKeyRatioProbeDecisions(channel, map[string]ratioProbeDecision{
		"sk-a": {key: "sk-a", compliant: true, ratio: 1},
		"sk-b": {key: "sk-b", ratio: 3, message: "group default ratio 3 exceeds max 1"},
		"sk-c": {key: "sk-c", compliant: true, ratio: 1},
	}, &result)

	assert.Equal(t, 1, result.disabledKeys)
	assert.Equal(t, 0, result.enabledKeys)
	assert.False(t, result.statusChanged)
	assert.Equal(t, common.ChannelStatusEnabled, channel.Status)
	assert.Equal(t, map[int]int{
		1: common.ChannelStatusAutoDisabled,
		2: common.ChannelStatusManuallyDisabled,
	}, channel.ChannelInfo.MultiKeyStatusList, "a manually disabled key stays manually disabled")
	assert.Contains(t, channel.ChannelInfo.MultiKeyDisabledReason[1], "exceeds max 1")
	assert.NotZero(t, channel.ChannelInfo.MultiKeyDisabledTime[1])

	// The compliant key turns non-compliant too, which leaves no usable key and
	// must take the channel down.
	result = channelRatioProbeResult{}
	applyMultiKeyRatioProbeDecisions(channel, map[string]ratioProbeDecision{
		"sk-a": {key: "sk-a", ratio: 3, message: "group default ratio 3 exceeds max 1"},
	}, &result)

	assert.Equal(t, 1, result.disabledKeys)
	assert.True(t, result.statusChanged)
	assert.True(t, result.disabled)
	assert.Equal(t, common.ChannelStatusAutoDisabled, channel.Status)

	// A later compliant probe restores the keys this probe disabled and the
	// channel with them.
	result = channelRatioProbeResult{}
	applyMultiKeyRatioProbeDecisions(channel, map[string]ratioProbeDecision{
		"sk-a": {key: "sk-a", compliant: true, ratio: 1},
		"sk-b": {key: "sk-b", compliant: true, ratio: 1},
		"sk-c": {key: "sk-c", compliant: true, ratio: 1},
	}, &result)

	assert.Equal(t, 2, result.enabledKeys)
	assert.True(t, result.statusChanged)
	assert.True(t, result.enabled)
	assert.Equal(t, common.ChannelStatusEnabled, channel.Status)
	assert.Equal(t, map[int]int{2: common.ChannelStatusManuallyDisabled}, channel.ChannelInfo.MultiKeyStatusList)
	assert.Empty(t, channel.ChannelInfo.MultiKeyDisabledReason)
	assert.Empty(t, channel.ChannelInfo.MultiKeyDisabledTime)
}

func TestApplyMultiKeyRatioProbeDecisionsKeepsRelayDisabledKeys(t *testing.T) {
	channel := &model.Channel{
		Status: common.ChannelStatusAutoDisabled,
		Key:    "sk-a",
		ChannelInfo: model.ChannelInfo{
			IsMultiKey:             true,
			MultiKeySize:           1,
			MultiKeyStatusList:     map[int]int{0: common.ChannelStatusAutoDisabled},
			MultiKeyDisabledReason: map[int]string{0: "invalid api key"},
		},
	}

	result := channelRatioProbeResult{}
	applyMultiKeyRatioProbeDecisions(channel, map[string]ratioProbeDecision{
		"sk-a": {key: "sk-a", compliant: true, ratio: 1},
	}, &result)

	assert.Equal(t, 0, result.enabledKeys)
	assert.False(t, result.statusChanged)
	assert.Equal(t, common.ChannelStatusAutoDisabled, channel.Status)
	assert.Equal(t, map[int]int{0: common.ChannelStatusAutoDisabled}, channel.ChannelInfo.MultiKeyStatusList)
}

func TestApplyMultiKeyRatioProbeDecisionsIgnoresFailedProbes(t *testing.T) {
	channel := &model.Channel{
		Status:      common.ChannelStatusEnabled,
		Key:         "sk-a\nsk-b",
		ChannelInfo: model.ChannelInfo{IsMultiKey: true, MultiKeySize: 2},
	}

	result := channelRatioProbeResult{}
	applyMultiKeyRatioProbeDecisions(channel, map[string]ratioProbeDecision{
		"sk-a": {key: "sk-a", failed: true, message: "status code: 502"},
		"sk-b": {key: "sk-b", failed: true, message: "status code: 502"},
	}, &result)

	assert.Equal(t, 0, result.disabledKeys)
	assert.False(t, result.statusChanged)
	assert.Equal(t, common.ChannelStatusEnabled, channel.Status)
	assert.Empty(t, channel.ChannelInfo.MultiKeyStatusList)
}
