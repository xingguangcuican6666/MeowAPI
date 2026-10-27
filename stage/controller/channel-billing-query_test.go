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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/constant"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBuildBillingQueryRequestAuthModes(t *testing.T) {
	channel := &model.Channel{Key: " channel-api-key "}
	baseURL := "https://billing.example/base///"

	useAPIKey := true
	doNotUseAPIKey := false
	tests := []struct {
		name       string
		config     *dto.BillingQueryConfig
		wantHeader string
		wantUserID string
	}{
		{
			name: "omitted switch uses channel key",
			config: &dto.BillingQueryConfig{
				Type:    dto.BillingQueryTypeNewAPI,
				BaseURL: baseURL,
				UserID:  "1001",
			},
			wantHeader: "Bearer channel-api-key",
			wantUserID: "1001",
		},
		{
			name: "enabled switch uses channel key",
			config: &dto.BillingQueryConfig{
				Type:        dto.BillingQueryTypeNewAPI,
				BaseURL:     baseURL,
				BearerToken: "custom-token-is-ignored",
				UseAPIKey:   &useAPIKey,
			},
			wantHeader: "Bearer channel-api-key",
		},
		{
			name: "disabled switch uses custom token",
			config: &dto.BillingQueryConfig{
				Type:        dto.BillingQueryTypeNewAPI,
				BaseURL:     baseURL,
				BearerToken: " custom-token ",
				UseAPIKey:   &doNotUseAPIKey,
			},
			wantHeader: "Bearer custom-token",
		},
		{
			name: "disabled switch with empty token sends no auth",
			config: &dto.BillingQueryConfig{
				Type:      dto.BillingQueryTypeNewAPI,
				BaseURL:   baseURL,
				UseAPIKey: &doNotUseAPIKey,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			requestURL, headers, err := buildBillingQueryRequest(channel, tt.config)
			require.NoError(t, err)
			assert.Equal(t, "https://billing.example/base/api/user/self", requestURL)
			assert.Equal(t, tt.wantHeader, headers.Get("Authorization"))
			assert.Equal(t, "application/json", headers.Get("Accept"))
			assert.Equal(t, "application/json", headers.Get("Content-Type"))
			assert.Equal(t, "cc-switch/1.0", headers.Get("User-Agent"))
			assert.Equal(t, tt.wantUserID, headers.Get("New-Api-User"))
		})
	}
}

func TestUpdateChannelBalanceUsesConfiguredQueryAndPersistsRawAmount(t *testing.T) {
	db := setupModelListControllerTestDB(t)

	requestPath := make(chan string, 1)
	authorization := make(chan string, 1)
	userID := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestPath <- request.URL.Path
		authorization <- request.Header.Get("Authorization")
		userID <- request.Header.Get("New-Api-User")
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"success":true,"message":"","data":{"group":"default","quota":1250000,"used_quota":250000}}`))
	}))
	defer server.Close()

	baseURL := "https://relay.example.invalid"
	channel := &model.Channel{
		Type:    constant.ChannelTypeOpenAI,
		Key:     "channel-api-key",
		Name:    "configured billing channel",
		BaseURL: &baseURL,
		Balance: 99,
	}
	channel.SetOtherSettings(dto.ChannelOtherSettings{
		BillingQuery: &dto.BillingQueryConfig{
			Type:      dto.BillingQueryTypeNewAPI,
			BaseURL:   server.URL + "/billing///",
			UserID:    "1001",
			UseAPIKey: boolPointer(true),
		},
	})
	require.NoError(t, db.Create(channel).Error)

	result, err := updateChannelBalance(channel)
	require.NoError(t, err)
	assert.Equal(t, 2.5, result.Balance)
	assert.Empty(t, result.RawResponse)
	assert.Equal(t, "/billing/api/user/self", <-requestPath)
	assert.Equal(t, "Bearer channel-api-key", <-authorization)
	assert.Equal(t, "1001", <-userID)

	var stored model.Channel
	require.NoError(t, db.First(&stored, channel.Id).Error)
	assert.Equal(t, 2.5, stored.Balance)
}

func TestUpdateChannelBalanceKeepsAdvancedCustomFallbackWithoutBillingQuery(t *testing.T) {
	db := setupModelListControllerTestDB(t)
	requestPath := make(chan string, 1)
	authorization := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requestPath <- request.URL.Path
		authorization <- request.Header.Get("Authorization")
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"balance":4.5}`))
	}))
	defer server.Close()

	baseURL := server.URL
	channel := &model.Channel{
		Type:    constant.ChannelTypeAdvancedCustom,
		Key:     "advanced-custom-key",
		Name:    "advanced custom fallback",
		BaseURL: &baseURL,
		Balance: 8,
	}
	channel.SetOtherSettings(dto.ChannelOtherSettings{
		AdvancedCustom: &dto.AdvancedCustomConfig{
			Routes: []dto.AdvancedCustomRoute{
				{
					IncomingPath: dto.AdvancedCustomBalancePath,
					UpstreamPath: "/provider/balance",
					Converter:    "none",
				},
			},
		},
	})
	require.NoError(t, db.Create(channel).Error)

	result, err := updateChannelBalance(channel)
	require.NoError(t, err)
	assert.Equal(t, "/provider/balance", <-requestPath)
	assert.Equal(t, "Bearer advanced-custom-key", <-authorization)
	assert.Equal(t, "{\n  \"balance\": 4.5\n}", result.RawResponse)

	var stored model.Channel
	require.NoError(t, db.First(&stored, channel.Id).Error)
	assert.Equal(t, 8.0, stored.Balance)
}

func TestFetchBillingQueryBalanceDoesNotUpdateForInvalidResponses(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		body       string
	}{
		{
			name:       "non-200 response",
			statusCode: http.StatusUnauthorized,
			body:       `{"success":true,"data":{"quota":1250000}}`,
		},
		{
			name:       "invalid JSON",
			statusCode: http.StatusOK,
			body:       "not-json",
		},
		{
			name:       "oversized response",
			statusCode: http.StatusOK,
			body:       strings.Repeat("x", maxChannelBalanceResponseBytes+1),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db := setupModelListControllerTestDB(t)
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(tt.statusCode)
				_, _ = writer.Write([]byte(tt.body))
			}))
			defer server.Close()

			baseURL := "https://relay.example.invalid"
			channel := &model.Channel{
				Type:    constant.ChannelTypeOpenAI,
				Key:     "channel-api-key",
				Name:    "invalid billing response",
				BaseURL: &baseURL,
				Balance: 7,
			}
			require.NoError(t, db.Create(channel).Error)

			config := &dto.BillingQueryConfig{
				Type:      dto.BillingQueryTypeNewAPI,
				BaseURL:   server.URL,
				UseAPIKey: boolPointer(false),
			}
			_, err := fetchBillingQueryBalance(channel, config)
			require.Error(t, err)

			var stored model.Channel
			require.NoError(t, db.First(&stored, channel.Id).Error)
			assert.Equal(t, 7.0, stored.Balance)
		})
	}
}

func TestFetchBillingQueryBalancePreservesNegativeRemaining(t *testing.T) {
	db := setupModelListControllerTestDB(t)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		_, _ = writer.Write([]byte(`{"success":true,"data":{"quota":-500000,"used_quota":0}}`))
	}))
	defer server.Close()

	baseURL := "https://relay.example.invalid"
	channel := &model.Channel{
		Type:    constant.ChannelTypeOpenAI,
		Key:     "channel-api-key",
		Name:    "negative billing response",
		BaseURL: &baseURL,
		Balance: 7,
	}
	require.NoError(t, db.Create(channel).Error)

	config := &dto.BillingQueryConfig{
		Type:      dto.BillingQueryTypeNewAPI,
		BaseURL:   server.URL,
		UseAPIKey: boolPointer(false),
	}
	result, err := fetchBillingQueryBalance(channel, config)
	require.NoError(t, err)
	assert.Equal(t, -1.0, result.Balance)

	var stored model.Channel
	require.NoError(t, db.First(&stored, channel.Id).Error)
	assert.Equal(t, -1.0, stored.Balance)
}

func TestSanitizeBillingQueryErrorRemovesCredentials(t *testing.T) {
	secret := "query-secret"
	err := sanitizeBillingQueryError(errors.New("request failed for "+secret), secret)
	require.Error(t, err)
	assert.NotContains(t, err.Error(), secret)
	assert.Contains(t, err.Error(), "[REDACTED]")
}

func boolPointer(value bool) *bool {
	return &value
}
