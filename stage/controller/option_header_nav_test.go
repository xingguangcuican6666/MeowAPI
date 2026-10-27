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
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const headerNavModulesKey = "HeaderNavModules"

type headerNavUpdateResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

func headerNavItem(id, title, href, openMode string) map[string]any {
	return map[string]any{"id": id, "title": title, "href": href, "openMode": openMode, "requireAuth": false}
}

// headerNavItems returns count valid items with distinct ids.
func headerNavItems(count int) []map[string]any {
	items := make([]map[string]any, 0, count)
	for i := range count {
		items = append(items, headerNavItem(fmt.Sprintf("item-%d", i), fmt.Sprintf("Item %d", i), fmt.Sprintf("/item-%d", i), "internal"))
	}
	return items
}

// headerNavConfig marshals items so special characters in hrefs are escaped the
// way the admin page would send them.
func headerNavConfig(t *testing.T, items []map[string]any) string {
	t.Helper()
	encoded, err := common.Marshal(map[string]any{"home": true, "customItems": items})
	require.NoError(t, err)
	return string(encoded)
}

func updateHeaderNavModules(t *testing.T, value string) headerNavUpdateResponse {
	t.Helper()
	var response headerNavUpdateResponse
	recorder := modelManagementRequest(t, UpdateOption, http.MethodPut, "/api/option/",
		OptionUpdateRequest{Key: headerNavModulesKey, Value: value}, &response)
	require.Equal(t, http.StatusOK, recorder.Code)
	return response
}

// storedHeaderNavModules returns the persisted rows and the in-memory value that
// /api/status publishes to every visitor.
func storedHeaderNavModules(t *testing.T) (rows []model.Option, published string, hasPublished bool) {
	t.Helper()
	require.NoError(t, model.DB.Where(&model.Option{Key: headerNavModulesKey}).Find(&rows).Error)
	common.OptionMapRWMutex.RLock()
	defer common.OptionMapRWMutex.RUnlock()
	published, hasPublished = common.OptionMap[headerNavModulesKey]
	return rows, published, hasPublished
}

func TestUpdateOptionStoresValidHeaderNavModules(t *testing.T) {
	modelManagementDB(t, "sqlite", "")

	limitItems := headerNavItems(20)
	limitItems[0]["title"] = strings.Repeat("t", 50)
	limitItems[1] = headerNavItem("long-link", "Long", "https://example.com/"+strings.Repeat("a", 2048-len("https://example.com/")), "external")
	tests := []struct {
		name  string
		value string
	}{
		{"empty value means defaults", ""},
		{"legacy config without customItems", `{"home":true,"console":true,"pricing":{"enabled":true,"requireAuth":false},"rankings":false,"docs":true,"about":true}`},
		{"empty customItems", `{"customItems":[]}`},
		{"every open mode with unknown keys", `{"home":true,"futureModule":{"beta":1},"customItems":[` +
			`{"id":"status-page","title":"Status","href":"https://status.example.com/","openMode":"external","requireAuth":false,"icon":"globe"},` +
			`{"id":"grafana_1","title":"Dashboard","href":"http://grafana.example.com:3000/d/abc?orgId=1#top","openMode":"iframe","requireAuth":true},` +
			`{"id":"pricing","title":"Pricing","href":"/pricing?tab=1","openMode":"internal"},` +
			`{"id":"docs-site","title":"Docs","href":"https://docs.example.com","openMode":"internal","requireAuth":false}]}`},
		{"limits are inclusive", headerNavConfig(t, limitItems)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := updateHeaderNavModules(t, tt.value)

			assert.True(t, response.Success, response.Message)
			rows, published, hasPublished := storedHeaderNavModules(t)
			require.Len(t, rows, 1)
			assert.Equal(t, tt.value, rows[0].Value)
			assert.True(t, hasPublished)
			assert.Equal(t, tt.value, published)
		})
	}
}

func TestUpdateOptionRejectsUnsafeHeaderNavModules(t *testing.T) {
	modelManagementDB(t, "sqlite", "")

	one := func(href, openMode string) string {
		return headerNavConfig(t, []map[string]any{headerNavItem("a", "A", href, openMode)})
	}
	withTitle := func(title string) string {
		return headerNavConfig(t, []map[string]any{headerNavItem("a", title, "/a", "internal")})
	}
	const (
		absoluteURLOnly = "href must be an absolute http(s) URL"
		singleSlash     = `href must be an app path starting with a single "/"`
		titleRange      = "title must be 1 to 50 characters"
	)
	tests := []struct {
		name        string
		value       string
		wantMessage string
	}{
		{"javascript URL", one("javascript:alert(document.domain)", "external"), absoluteURLOnly},
		{"javascript URL in internal mode", one("javascript:alert(1)", "internal"), `href must be an app path starting with "/" or an absolute http(s) URL`},
		{"data URL in an iframe", one("data:text/html,<script>alert(1)</script>", "iframe"), absoluteURLOnly},
		{"protocol-relative URL", one("//evil.example", "external"), absoluteURLOnly},
		{"protocol-relative app path", one("//evil.example", "internal"), singleSlash},
		{"backslash protocol-relative app path", one(`/\evil.example`, "internal"), singleSlash},
		{"tab hidden in an app path", one("/\t/evil.example", "internal"), "href must not contain whitespace or control characters"},
		{"app path outside internal mode", one("/console", "iframe"), absoluteURLOnly},
		{"URL with userinfo", one("https://trusted.example.com@evil.example/", "external"), "href must not contain credentials"},
		{"URL without authority", one("http:evil.example", "external"), absoluteURLOnly},
		{"blank href", one("   ", "internal"), "href must not be empty"},
		{"overlong href", one("https://example.com/"+strings.Repeat("a", 2049), "external"), "href must be at most 2048 characters"},
		{"unknown openMode", one("https://example.com", "popup"), "openMode must be one of"},
		{"duplicate id", headerNavConfig(t, []map[string]any{
			headerNavItem("same", "One", "/one", "internal"),
			headerNavItem("same", "Two", "/two", "internal"),
		}), `custom navigation item 2: duplicate id "same"`},
		{"non-boolean requireAuth", headerNavConfig(t, []map[string]any{{"id": "a", "title": "A", "href": "/a", "openMode": "internal", "requireAuth": "yes"}}), "requireAuth must be true or false"},
		{"unsafe id", headerNavConfig(t, []map[string]any{headerNavItem("bad id!", "A", "/a", "internal")}), "id must be 1 to 64"},
		{"blank title", withTitle("  "), titleRange},
		{"overlong title", withTitle(strings.Repeat("t", 51)), titleRange},
		{"title over 50 UTF-16 units", withTitle(strings.Repeat("\U0001F600", 26)), titleRange},
		{"more than 20 items", headerNavConfig(t, headerNavItems(21)), "customItems must contain at most 20 items"},
		{"customItems is not an array", `{"customItems":{"id":"a"}}`, "customItems must be an array"},
		{"item is not an object", `{"customItems":["/a"]}`, "custom navigation item 1: must be an object"},
		{"config is not an object", `["customItems"]`, "must be a JSON object"},
		{"config is not JSON", `{"customItems":`, "valid JSON object"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			response := updateHeaderNavModules(t, tt.value)

			assert.False(t, response.Success)
			assert.Contains(t, response.Message, tt.wantMessage)
			rows, _, hasPublished := storedHeaderNavModules(t)
			assert.Empty(t, rows)
			assert.False(t, hasPublished)
		})
	}
}
