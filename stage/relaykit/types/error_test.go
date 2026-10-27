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

package types

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsModelMissingError(t *testing.T) {
	tests := []struct {
		name     string
		err      *NewAPIError
		expected bool
	}{
		{
			name: "nil error",
		},
		{
			name:     "upstream model_not_found code",
			err:      WithOpenAIError(OpenAIError{Message: "The model `gpt-x` does not exist", Code: "model_not_found"}, http.StatusNotFound),
			expected: true,
		},
		{
			name:     "404 mentioning model",
			err:      NewErrorWithStatusCode(errors.New("model claude-x not found"), ErrorCodeBadResponse, http.StatusNotFound),
			expected: true,
		},
		{
			name:     "404 no endpoints",
			err:      NewErrorWithStatusCode(errors.New("No endpoints found for this model"), ErrorCodeBadResponse, http.StatusNotFound),
			expected: true,
		},
		{
			name: "404 without model mention",
			err:  NewErrorWithStatusCode(errors.New("resource not found"), ErrorCodeBadResponse, http.StatusNotFound),
		},
		{
			name: "500 mentioning model",
			err:  NewErrorWithStatusCode(errors.New("model overloaded"), ErrorCodeBadResponse, http.StatusInternalServerError),
		},
		{
			name:     "gateway routing abort",
			err:      NewError(errors.New("no available channel"), ErrorCodeModelNotFound),
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.expected, IsModelMissingError(test.err))
		})
	}
}

func TestIsStreamStallError(t *testing.T) {
	assert.False(t, IsStreamStallError(nil))
	assert.False(t, IsStreamStallError(NewError(errors.New("boom"), ErrorCodeBadResponse)))
	assert.True(t, IsStreamStallError(NewErrorWithStatusCode(
		errors.New("upstream stream stalled before first byte"),
		ErrorCodeChannelStreamTimeout, http.StatusBadGateway)))
}

func TestClientMessageOverridesClientProjectionsOnly(t *testing.T) {
	err := WithOpenAIError(OpenAIError{
		Message: "upstream acct-secret balance exhausted",
		Type:    "insufficient_quota",
		Code:    "insufficient_quota",
	}, http.StatusPaymentRequired)

	// Without a client message the projections carry the verbatim error.
	assert.Contains(t, err.ToOpenAIError().Message, "acct-secret")
	assert.Contains(t, err.ToClaudeError().Message, "acct-secret")

	err.SetClientMessage("upstream request failed")
	assert.Equal(t, "upstream request failed", err.ToOpenAIError().Message)
	assert.Equal(t, "upstream request failed", err.ToClaudeError().Message)
	// Internal consumers keep reading the verbatim error.
	assert.Contains(t, err.Error(), "acct-secret")
	assert.Contains(t, err.Err.Error(), "acct-secret")

	// Deep-preserved NewAPIError keeps its pinned client message.
	wrapped := NewError(err, ErrorCodeBadResponse)
	assert.Equal(t, "upstream request failed", wrapped.ToOpenAIError().Message)
}

func TestToOpenAIError_SanitizesMetadata(t *testing.T) {
	// Simulate an upstream error with sensitive metadata (e.g., OpenRouter's provider_name/raw)
	upstreamErr := OpenAIError{
		Message:  "Rate limit exceeded",
		Type:     "rate_limit_error",
		Code:     "rate_limit",
		Metadata: json.RawMessage(`{"provider_name":"openai","raw":"upstream detail"}`),
		Param:    "requests",
	}

	apiErr := &NewAPIError{
		RelayError:    upstreamErr,
		errorType:     ErrorTypeOpenAIError,
		StatusCode:    429,
		Err:           errors.New("Rate limit exceeded"),
		clientMessage: "You have exceeded the rate limit. Please try again later.",
	}

	clientError := apiErr.ToOpenAIError()

	// Client should see the sanitized message, preserved Type/Code, but NO Metadata/Param
	assert.Equal(t, "You have exceeded the rate limit. Please try again later.", clientError.Message)
	assert.Equal(t, "rate_limit_error", clientError.Type)
	assert.Equal(t, "rate_limit", clientError.Code)
	assert.Nil(t, clientError.Metadata, "Metadata must be cleared for client")
	assert.Empty(t, clientError.Param, "Param must be cleared for client")
}

func TestToClaudeError_SanitizesMessage(t *testing.T) {
	upstreamErr := ClaudeError{
		Type:    "overloaded_error",
		Message: "Our systems are currently overloaded. Provider: anthropic-us-east.",
	}

	apiErr := &NewAPIError{
		RelayError:    upstreamErr,
		errorType:     ErrorTypeClaudeError,
		StatusCode:    529,
		Err:           errors.New(upstreamErr.Message),
		clientMessage: "The service is temporarily unavailable. Please retry.",
	}

	clientError := apiErr.ToClaudeError()

	assert.Equal(t, "The service is temporarily unavailable. Please retry.", clientError.Message)
	assert.Equal(t, "overloaded_error", clientError.Type)
}

// TestWithOpenAIError_DoesNotConcatenateMetadataIntoErr verifies that upstream
// Metadata never reaches Err.Error(). The verbatim error text is served to
// administrators and written to logs, and when SANITIZE_UPSTREAM_ERROR is off
// (the default) it also reaches ordinary clients, so metadata must stay out of
// it regardless of the sanitizer setting.
func TestWithOpenAIError_DoesNotConcatenateMetadataIntoErr(t *testing.T) {
	apiErr := WithOpenAIError(OpenAIError{
		Message:  "Rate limit exceeded",
		Type:     "rate_limit_error",
		Code:     "rate_limit",
		Metadata: json.RawMessage(`{"provider_name":"anthropic","raw":"account xyz-1234 over quota"}`),
		Param:    "requests",
	}, http.StatusTooManyRequests)

	assert.NotContains(t, apiErr.Error(), "provider_name")
	assert.NotContains(t, apiErr.Error(), "xyz-1234")
	// Metadata is still retained for internal debugging.
	assert.JSONEq(t, `{"provider_name":"anthropic","raw":"account xyz-1234 over quota"}`, string(apiErr.Metadata))
}
