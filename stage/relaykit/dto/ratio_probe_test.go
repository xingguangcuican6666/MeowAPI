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

package dto

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func float64Pointer(value float64) *float64 {
	return &value
}

func TestRatioProbeConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *RatioProbeConfig
		message string
	}{
		{
			name:   "disabled config is not validated",
			config: &RatioProbeConfig{Source: "nonsense", BaseURL: "not a url"},
		},
		{
			name:   "follow api with max bound",
			config: &RatioProbeConfig{Enabled: true, MaxGroupRatio: float64Pointer(1)},
		},
		{
			name: "custom source with base URL",
			config: &RatioProbeConfig{
				Enabled:       true,
				Source:        RatioProbeSourceCustom,
				BaseURL:       "https://upstream.example/",
				MinGroupRatio: float64Pointer(0),
				MaxGroupRatio: float64Pointer(2),
			},
		},
		{
			name:    "unknown source",
			config:  &RatioProbeConfig{Enabled: true, Source: "guess", MaxGroupRatio: float64Pointer(1)},
			message: "invalid ratio probe source",
		},
		{
			name:    "custom source without base URL",
			config:  &RatioProbeConfig{Enabled: true, Source: RatioProbeSourceCustom, MaxGroupRatio: float64Pointer(1)},
			message: "absolute HTTP or HTTPS URL",
		},
		{
			name: "custom source with credentials",
			config: &RatioProbeConfig{
				Enabled:       true,
				Source:        RatioProbeSourceCustom,
				BaseURL:       "https://user:pass@upstream.example",
				MaxGroupRatio: float64Pointer(1),
			},
			message: "credentials",
		},
		{
			name:    "relative path",
			config:  &RatioProbeConfig{Enabled: true, Path: "api/ratio_config", MaxGroupRatio: float64Pointer(1)},
			message: "absolute path",
		},
		{
			name:    "path with query",
			config:  &RatioProbeConfig{Enabled: true, Path: "/api/ratio_config?a=1", MaxGroupRatio: float64Pointer(1)},
			message: "query parameters or fragments",
		},
		{
			name:    "no bounds",
			config:  &RatioProbeConfig{Enabled: true},
			message: "requires a max or min group ratio",
		},
		{
			name:    "negative bound",
			config:  &RatioProbeConfig{Enabled: true, MaxGroupRatio: float64Pointer(-1)},
			message: "must be between 0 and",
		},
		{
			name:    "bound above limit",
			config:  &RatioProbeConfig{Enabled: true, MaxGroupRatio: float64Pointer(MaxRatioProbeRatio + 1)},
			message: "must be between 0 and",
		},
		{
			name: "min above max",
			config: &RatioProbeConfig{
				Enabled:       true,
				MinGroupRatio: float64Pointer(2),
				MaxGroupRatio: float64Pointer(1),
			},
			message: "must not exceed max group ratio",
		},
		{
			name: "authorization header value",
			config: &RatioProbeConfig{
				Enabled:       true,
				MaxGroupRatio: float64Pointer(1),
				Authorization: "Basic dXNlcjpwYXNz",
			},
		},
		{
			name: "authorization with a line break",
			config: &RatioProbeConfig{
				Enabled:       true,
				MaxGroupRatio: float64Pointer(1),
				Authorization: "Bearer token\r\nX-Injected: 1",
			},
			message: "printable ASCII",
		},
		{
			name: "authorization above the length limit",
			config: &RatioProbeConfig{
				Enabled:       true,
				MaxGroupRatio: float64Pointer(1),
				Authorization: strings.Repeat("a", MaxRatioProbeAuthorizationLength+1),
			},
			message: "must not exceed",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if tt.message == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.message)
		})
	}
}

func TestRatioProbeConfigNilIsInert(t *testing.T) {
	var config *RatioProbeConfig
	require.NoError(t, config.Validate())
	assert.False(t, config.IsEnabled())
	assert.True(t, config.UsesAPIKey())
	assert.True(t, config.Accepts(1000))
	assert.Equal(t, RatioProbeSourceFollowAPI, config.NormalizedSource())
	assert.Equal(t, RatioProbeDefaultPath, config.NormalizedPath())
	assert.Equal(t, RatioProbeDefaultGroup, config.NormalizedGroup())
	assert.Equal(t, "", config.NormalizedAuthorization())
}

func TestRatioProbeConfigNormalization(t *testing.T) {
	config := &RatioProbeConfig{
		Source:        " CUSTOM ",
		BaseURL:       "  https://upstream.example//  ",
		Path:          " /api/pricing ",
		Group:         "  vip  ",
		Authorization: "  Bearer probe-token  ",
	}
	assert.Equal(t, RatioProbeSourceCustom, config.NormalizedSource())
	assert.Equal(t, "https://upstream.example", config.NormalizedBaseURL())
	assert.Equal(t, "/api/pricing", config.NormalizedPath())
	assert.Equal(t, "vip", config.NormalizedGroup())
	assert.Equal(t, "Bearer probe-token", config.NormalizedAuthorization())

	useAPIKey := false
	config.UseAPIKey = &useAPIKey
	assert.False(t, config.UsesAPIKey())
}

func TestRatioProbeConfigAccepts(t *testing.T) {
	tests := []struct {
		name   string
		config RatioProbeConfig
		ratio  float64
		accept bool
	}{
		{
			name:   "at max bound",
			config: RatioProbeConfig{MaxGroupRatio: float64Pointer(1)},
			ratio:  1,
			accept: true,
		},
		{
			name:   "float round-trip at max bound",
			config: RatioProbeConfig{MaxGroupRatio: float64Pointer(1)},
			ratio:  1.0000000000000002,
			accept: true,
		},
		{
			name:   "above max bound",
			config: RatioProbeConfig{MaxGroupRatio: float64Pointer(1)},
			ratio:  1.5,
			accept: false,
		},
		{
			name:   "below min bound",
			config: RatioProbeConfig{MinGroupRatio: float64Pointer(0.5)},
			ratio:  0.2,
			accept: false,
		},
		{
			name:   "inside both bounds",
			config: RatioProbeConfig{MinGroupRatio: float64Pointer(0.5), MaxGroupRatio: float64Pointer(1)},
			ratio:  0.75,
			accept: true,
		},
		{
			name:   "zero max bound rejects a priced group",
			config: RatioProbeConfig{MaxGroupRatio: float64Pointer(0)},
			ratio:  1,
			accept: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.accept, tt.config.Accepts(tt.ratio))
		})
	}
}
