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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/relaykit/dto"
	"github.com/QuantumNous/new-api/service"
)

const newAPIUserQuotaPerUSD = 500000.0

func buildBillingQueryRequest(channel *model.Channel, config *dto.BillingQueryConfig) (string, http.Header, error) {
	if channel == nil {
		return "", nil, errors.New("channel is nil")
	}
	if config == nil {
		return "", nil, errors.New("billing query config is nil")
	}
	if err := config.Validate(); err != nil {
		return "", nil, err
	}

	requestURL := config.NormalizedBaseURL() + dto.BillingQueryNewAPIUserSelfPath
	headers := http.Header{}
	headers.Set("Accept", "application/json")
	headers.Set("Content-Type", "application/json")
	headers.Set("User-Agent", "cc-switch/1.0")
	if userID := strings.TrimSpace(config.UserID); userID != "" {
		headers.Set("New-Api-User", userID)
	}
	if config.UsesAPIKey() {
		if key := strings.TrimSpace(channel.Key); key != "" {
			headers.Set("Authorization", "Bearer "+key)
		}
	} else if token := strings.TrimSpace(config.BearerToken); token != "" {
		headers.Set("Authorization", "Bearer "+token)
	}
	return requestURL, headers, nil
}

func fetchBillingQueryBalance(channel *model.Channel, config *dto.BillingQueryConfig) (channelBalanceResult, error) {
	secrets := make([]string, 0, 4)
	if channel != nil {
		secrets = append(secrets, channel.Key)
	}
	if config != nil {
		secrets = append(secrets, config.BearerToken, config.BaseURL, config.NormalizedBaseURL())
	}

	requestURL, headers, err := buildBillingQueryRequest(channel, config)
	if err != nil {
		return channelBalanceResult{}, sanitizeBillingQueryError(err, secrets...)
	}

	body, err := getBillingQueryResponseBody(http.MethodGet, requestURL, channel, headers)
	if err != nil {
		return channelBalanceResult{}, sanitizeBillingQueryError(err, secrets...)
	}
	balance, err := parseNewAPIUserSelfBalance(body)
	if err != nil {
		return channelBalanceResult{}, err
	}

	channel.UpdateBalance(balance)
	return channelBalanceResult{Balance: balance}, nil
}

func getBillingQueryResponseBody(method string, requestURL string, channel *model.Channel, headers http.Header) ([]byte, error) {
	if channel == nil {
		return nil, errors.New("channel is nil")
	}
	request, err := http.NewRequest(method, requestURL, nil)
	if err != nil {
		return nil, err
	}
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}

	client, err := service.GetHttpClientWithProxy(channel.GetSetting().Proxy)
	if err != nil {
		return nil, err
	}
	response, err := client.Do(request)
	if err != nil {
		return nil, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status code: %d", response.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(response.Body, maxChannelBalanceResponseBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > maxChannelBalanceResponseBytes {
		return nil, fmt.Errorf("balance response exceeds %d bytes", maxChannelBalanceResponseBytes)
	}
	return body, nil
}

func parseNewAPIUserSelfBalance(body []byte) (float64, error) {
	var validated json.RawMessage
	if err := common.Unmarshal(body, &validated); err != nil {
		return 0, fmt.Errorf("invalid balance JSON response: %w", err)
	}
	if common.GetJsonType(validated) != "object" {
		return 0, errors.New("invalid balance JSON response: expected an object")
	}

	var response struct {
		Success bool `json:"success"`
		Data    *struct {
			Quota json.RawMessage `json:"quota"`
		} `json:"data"`
	}
	if err := common.Unmarshal(body, &response); err != nil {
		return 0, fmt.Errorf("invalid balance JSON response: %w", err)
	}
	if !response.Success {
		return 0, errors.New("invalid balance response: success must be true")
	}
	if response.Data == nil {
		return 0, errors.New("invalid balance response: data is required")
	}
	if len(response.Data.Quota) == 0 || strings.EqualFold(string(response.Data.Quota), "null") {
		return 0, errors.New("invalid balance response: quota is required")
	}
	if common.GetJsonType(response.Data.Quota) != "number" {
		return 0, errors.New("invalid balance response: quota must be a number")
	}

	var quota float64
	if err := common.Unmarshal(response.Data.Quota, &quota); err != nil {
		return 0, fmt.Errorf("invalid balance response: quota: %w", err)
	}
	// JSON cannot normally represent NaN or infinity, but keep the check here
	// because the value is converted to float64 before it is persisted.
	if math.IsNaN(quota) || math.IsInf(quota, 0) {
		return 0, errors.New("invalid balance response: quota must be finite")
	}
	return quota / newAPIUserQuotaPerUSD, nil
}

func sanitizeBillingQueryError(err error, secrets ...string) error {
	if err == nil {
		return nil
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Err != nil {
		err = urlErr.Err
	}
	message := err.Error()
	for _, secret := range secrets {
		secret = strings.TrimSpace(secret)
		if secret == "" {
			continue
		}
		message = strings.ReplaceAll(message, secret, "[REDACTED]")
		message = strings.ReplaceAll(message, url.QueryEscape(secret), "[REDACTED]")
		message = strings.ReplaceAll(message, url.PathEscape(secret), "[REDACTED]")
	}
	return errors.New(message)
}
