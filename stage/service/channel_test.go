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

package service

import (
	"errors"
	"net/http"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/QuantumNous/new-api/relaykit/types"
	"github.com/QuantumNous/new-api/setting/operation_setting"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestShouldRuntimeDisableChannelUsesChannelOverrideAsCompleteReplacement(t *testing.T) {
	originalEnabled := common.RuntimeAutomaticDisableChannelEnabled
	originalRanges := operation_setting.RuntimeAutomaticDisableStatusCodeRanges
	originalKeywords := operation_setting.RuntimeAutomaticDisableKeywords
	t.Cleanup(func() {
		common.RuntimeAutomaticDisableChannelEnabled = originalEnabled
		operation_setting.RuntimeAutomaticDisableStatusCodeRanges = originalRanges
		operation_setting.RuntimeAutomaticDisableKeywords = originalKeywords
	})

	common.RuntimeAutomaticDisableChannelEnabled = true
	operation_setting.RuntimeAutomaticDisableStatusCodeRanges = []operation_setting.StatusCodeRange{{Start: 401, End: 403}}
	operation_setting.RuntimeAutomaticDisableKeywords = []string{"global balance error"}
	override := dto.ChannelOtherSettings{
		RuntimeAutomaticDisableOverrideEnabled: true,
		RuntimeAutomaticDisableStatusCodes:     "429",
		RuntimeAutomaticDisableKeywords:        "channel balance error",
	}

	require.False(t, ShouldRuntimeDisableChannel(types.NewOpenAIError(errors.New("global balance error"), types.ErrorCodeBadResponseStatusCode, http.StatusForbidden), &override))
	require.False(t, ShouldRuntimeDisableChannel(types.NewOpenAIError(errors.New("CHANNEL BALANCE ERROR"), types.ErrorCodeBadResponseStatusCode, http.StatusBadRequest), &override))
	require.False(t, ShouldRuntimeDisableChannel(types.NewOpenAIError(errors.New("rate limited"), types.ErrorCodeBadResponseStatusCode, http.StatusTooManyRequests), &override))
	require.True(t, ShouldRuntimeDisableChannel(types.NewOpenAIError(errors.New("CHANNEL BALANCE ERROR"), types.ErrorCodeBadResponseStatusCode, http.StatusTooManyRequests), &override))
}

func TestShouldDisableChannelUsesChannelOverrideAsCompleteReplacement(t *testing.T) {
	originalEnabled := common.AutomaticDisableChannelEnabled
	originalRanges := operation_setting.AutomaticDisableStatusCodeRanges
	originalKeywords := operation_setting.AutomaticDisableKeywords
	t.Cleanup(func() {
		common.AutomaticDisableChannelEnabled = originalEnabled
		operation_setting.AutomaticDisableStatusCodeRanges = originalRanges
		operation_setting.AutomaticDisableKeywords = originalKeywords
	})

	common.AutomaticDisableChannelEnabled = true
	operation_setting.AutomaticDisableStatusCodeRanges = []operation_setting.StatusCodeRange{{Start: 401, End: 403}}
	operation_setting.AutomaticDisableKeywords = []string{"global balance error"}
	override := dto.ChannelOtherSettings{
		AutomaticDisableOverrideEnabled: true,
		AutomaticDisableStatusCodes:     "429",
		AutomaticDisableKeywords:        "channel balance error",
	}

	require.False(t, ShouldDisableChannel(types.NewOpenAIError(errors.New("global balance error"), types.ErrorCodeBadResponseStatusCode, http.StatusForbidden), &override))
	require.False(t, ShouldDisableChannel(types.NewOpenAIError(errors.New("CHANNEL BALANCE ERROR"), types.ErrorCodeBadResponseStatusCode, http.StatusBadRequest), &override))
	require.False(t, ShouldDisableChannel(types.NewOpenAIError(errors.New("rate limited"), types.ErrorCodeBadResponseStatusCode, http.StatusTooManyRequests), &override))
	require.True(t, ShouldDisableChannel(types.NewOpenAIError(errors.New("CHANNEL BALANCE ERROR"), types.ErrorCodeBadResponseStatusCode, http.StatusTooManyRequests), &override))
}

func TestShouldDisableChannelHonorsRuntimeOverrideFields(t *testing.T) {
	originalEnabled := common.AutomaticDisableChannelEnabled
	originalRanges := operation_setting.AutomaticDisableStatusCodeRanges
	originalKeywords := operation_setting.AutomaticDisableKeywords
	t.Cleanup(func() {
		common.AutomaticDisableChannelEnabled = originalEnabled
		operation_setting.AutomaticDisableStatusCodeRanges = originalRanges
		operation_setting.AutomaticDisableKeywords = originalKeywords
	})

	common.AutomaticDisableChannelEnabled = true
	operation_setting.AutomaticDisableStatusCodeRanges = []operation_setting.StatusCodeRange{{Start: 401, End: 403}}
	operation_setting.AutomaticDisableKeywords = []string{"global balance error"}
	override := dto.ChannelOtherSettings{
		RuntimeAutomaticDisableOverrideEnabled: true,
		RuntimeAutomaticDisableStatusCodes:     "429",
		RuntimeAutomaticDisableKeywords:        "channel balance error",
	}

	require.False(t, ShouldDisableChannel(types.NewOpenAIError(errors.New("global balance error"), types.ErrorCodeBadResponseStatusCode, http.StatusForbidden), &override))
	require.True(t, ShouldDisableChannel(types.NewOpenAIError(errors.New("CHANNEL BALANCE ERROR"), types.ErrorCodeBadResponseStatusCode, http.StatusTooManyRequests), &override))
}

func TestShouldDisableChannelDefaultsIncludeForbidden(t *testing.T) {
	originalEnabled := common.AutomaticDisableChannelEnabled
	originalRanges := operation_setting.AutomaticDisableStatusCodeRanges
	t.Cleanup(func() {
		common.AutomaticDisableChannelEnabled = originalEnabled
		operation_setting.AutomaticDisableStatusCodeRanges = originalRanges
	})
	common.AutomaticDisableChannelEnabled = true
	operation_setting.AutomaticDisableStatusCodeRanges = []operation_setting.StatusCodeRange{{Start: 401, End: 401}}

	err := types.NewOpenAIError(errors.New("forbidden"), types.ErrorCodeBadResponseStatusCode, http.StatusForbidden)
	assert.False(t, ShouldDisableChannel(err, nil))
}

func TestShouldRuntimeDisableChannelOverrideOnlyDisablesMatchingRuntimeErrors(t *testing.T) {
	originalEnabled := common.RuntimeAutomaticDisableChannelEnabled
	t.Cleanup(func() { common.RuntimeAutomaticDisableChannelEnabled = originalEnabled })
	common.RuntimeAutomaticDisableChannelEnabled = true

	override := dto.ChannelOtherSettings{
		RuntimeAutomaticDisableOverrideEnabled: true,
		RuntimeAutomaticDisableStatusCodes:     "403",
		RuntimeAutomaticDisableKeywords:        "account suspended",
	}

	unmatchedChannelError := types.NewErrorWithStatusCode(
		errors.New("invalid local channel configuration"),
		types.ErrorCodeChannelInvalidKey,
		http.StatusBadRequest,
	)
	matchedStatus := types.NewErrorWithStatusCode(
		errors.New("forbidden"),
		types.ErrorCodeChannelInvalidKey,
		http.StatusForbidden,
	)
	matchedKeyword := types.NewOpenAIError(
		errors.New("ACCOUNT SUSPENDED by provider"),
		types.ErrorCodeBadResponseStatusCode,
		http.StatusBadRequest,
	)

	assert.False(t, ShouldRuntimeDisableChannel(unmatchedChannelError, &override))
	assert.False(t, ShouldRuntimeDisableChannel(matchedStatus, &override))
	assert.False(t, ShouldRuntimeDisableChannel(matchedKeyword, &override))
	matchedBoth := types.NewOpenAIError(
		errors.New("ACCOUNT SUSPENDED by provider"),
		types.ErrorCodeBadResponseStatusCode,
		http.StatusForbidden,
	)
	assert.True(t, ShouldRuntimeDisableChannel(matchedBoth, &override))
}

func TestShouldRuntimeDisableChannelGlobalRulesDoNotDisableUnmatchedChannelErrors(t *testing.T) {
	originalEnabled := common.RuntimeAutomaticDisableChannelEnabled
	originalRanges := operation_setting.RuntimeAutomaticDisableStatusCodeRanges
	originalKeywords := operation_setting.RuntimeAutomaticDisableKeywords
	t.Cleanup(func() {
		common.RuntimeAutomaticDisableChannelEnabled = originalEnabled
		operation_setting.RuntimeAutomaticDisableStatusCodeRanges = originalRanges
		operation_setting.RuntimeAutomaticDisableKeywords = originalKeywords
	})
	common.RuntimeAutomaticDisableChannelEnabled = true
	operation_setting.RuntimeAutomaticDisableStatusCodeRanges = []operation_setting.StatusCodeRange{{Start: 401, End: 401}}
	operation_setting.RuntimeAutomaticDisableKeywords = []string{"account suspended"}

	unmatched := types.NewErrorWithStatusCode(
		errors.New("invalid local channel configuration"),
		types.ErrorCodeChannelInvalidKey,
		http.StatusBadRequest,
	)

	assert.False(t, ShouldRuntimeDisableChannel(unmatched, nil))
}

// The forced retry rule is the operator's own escape hatch: it must be able to
// retry an upstream reply that arrives as 200 but carries an error in the body,
// which is what the distributor's "no available upstream" replies look like.
func TestShouldRetryChannelErrorForcedRetryRules(t *testing.T) {
	enabled := dto.ChannelOtherSettings{
		AutomaticRetryOverrideEnabled: true,
		AutomaticRetryStatusCodes:     "200",
		AutomaticRetryKeywords:        "no available upstream",
	}
	disabled := dto.ChannelOtherSettings{
		AutomaticRetryStatusCodes: "200",
		AutomaticRetryKeywords:    "no available upstream",
	}

	tests := []struct {
		name     string
		settings *dto.ChannelOtherSettings
		err      *types.NewAPIError
		want     bool
	}{
		{
			name:     "matching code and keyword retries",
			settings: &enabled,
			err:      types.NewOpenAIError(errors.New(`{"error":{"message":"no available upstream"}}`), types.ErrorCodeBadResponseStatusCode, http.StatusOK),
			want:     true,
		},
		{
			name:     "keyword is matched case-insensitively",
			settings: &enabled,
			err:      types.NewOpenAIError(errors.New("No Available Upstream for model"), types.ErrorCodeBadResponseStatusCode, http.StatusOK),
			want:     true,
		},
		{
			name:     "matching code without the keyword does not retry",
			settings: &enabled,
			err:      types.NewOpenAIError(errors.New("rate limited"), types.ErrorCodeBadResponseStatusCode, http.StatusOK),
			want:     false,
		},
		{
			name:     "matching keyword on another status does not retry",
			settings: &enabled,
			err:      types.NewOpenAIError(errors.New("no available upstream"), types.ErrorCodeBadResponseStatusCode, http.StatusServiceUnavailable),
			want:     false,
		},
		{
			name:     "override switch off keeps the rule inert",
			settings: &disabled,
			err:      types.NewOpenAIError(errors.New("no available upstream"), types.ErrorCodeBadResponseStatusCode, http.StatusOK),
			want:     false,
		},
		{
			name:     "no settings never retries",
			settings: nil,
			err:      types.NewOpenAIError(errors.New("no available upstream"), types.ErrorCodeBadResponseStatusCode, http.StatusOK),
			want:     false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, ShouldRetryChannelError(test.err, test.settings))
		})
	}
}
