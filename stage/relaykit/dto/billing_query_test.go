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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestBillingQueryConfigValidate(t *testing.T) {
	valid := &BillingQueryConfig{
		Type:    BillingQueryTypeNewAPI,
		BaseURL: "https://billing.example/api///",
	}
	require.NoError(t, valid.Validate())
	assert.Equal(t, "https://billing.example/api", valid.NormalizedBaseURL())

	tests := []struct {
		name    string
		config  BillingQueryConfig
		message string
	}{
		{
			name:    "missing type",
			config:  BillingQueryConfig{BaseURL: "https://billing.example"},
			message: "billing query type is required",
		},
		{
			name:    "unsupported type",
			config:  BillingQueryConfig{Type: "openai", BaseURL: "https://billing.example"},
			message: "unsupported billing query type",
		},
		{
			name:    "relative URL",
			config:  BillingQueryConfig{Type: BillingQueryTypeNewAPI, BaseURL: "/billing"},
			message: "absolute HTTP or HTTPS URL",
		},
		{
			name:    "unsupported scheme",
			config:  BillingQueryConfig{Type: BillingQueryTypeNewAPI, BaseURL: "ftp://billing.example"},
			message: "HTTP or HTTPS",
		},
		{
			name:    "credentials",
			config:  BillingQueryConfig{Type: BillingQueryTypeNewAPI, BaseURL: "https://user:pass@billing.example"},
			message: "credentials",
		},
		{
			name:    "query string",
			config:  BillingQueryConfig{Type: BillingQueryTypeNewAPI, BaseURL: "https://billing.example?tenant=one"},
			message: "query parameters",
		},
		{
			name:    "fragment",
			config:  BillingQueryConfig{Type: BillingQueryTypeNewAPI, BaseURL: "https://billing.example#billing"},
			message: "absolute HTTP or HTTPS URL",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			require.Error(t, err)
			assert.Contains(t, err.Error(), tt.message)
		})
	}
}

func TestBillingQueryConfigUsesAPIKeyCompatibilityDefault(t *testing.T) {
	config := &BillingQueryConfig{}
	assert.True(t, config.UsesAPIKey())

	useAPIKey := true
	config.UseAPIKey = &useAPIKey
	assert.True(t, config.UsesAPIKey())

	useAPIKey = false
	assert.False(t, config.UsesAPIKey())
}
