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

package oauthscope

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service/oauthserver"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// setupOAuthScopeTestDB gives the resolver an isolated in-memory database holding
// the users, clients and tokens tables, restoring the process DB on cleanup.
func setupOAuthScopeTestDB(t *testing.T) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	common.RedisEnabled = false

	previousDB := model.DB
	dsn := "file:" + strings.ReplaceAll(t.Name(), "/", "_") + "?mode=memory&cache=shared"
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{})
	require.NoError(t, err)
	sqlDB, err := db.DB()
	require.NoError(t, err)
	sqlDB.SetMaxOpenConns(1)
	require.NoError(t, db.AutoMigrate(&model.User{}, &model.OAuthClient{}, &model.OAuthToken{}))
	model.DB = db
	t.Cleanup(func() {
		model.DB = previousDB
		_ = sqlDB.Close()
	})
}

func seedScopeUser(t *testing.T, id, status int) {
	t.Helper()
	require.NoError(t, model.DB.Create(&model.User{
		Id:       id,
		Username: "owner",
		AffCode:  "owner",
		Group:    "default",
		Status:   status,
		Role:     common.RoleCommonUser,
		Quota:    500,
	}).Error)
}

func seedScopeClient(t *testing.T, clientId string, trusted bool) {
	t.Helper()
	require.NoError(t, model.DB.Create(&model.OAuthClient{
		ClientId:    clientId,
		Name:        "Test App",
		Scopes:      "openid profile",
		Status:      model.OAuthClientStatusEnabled,
		OwnerUserId: 1,
		Trusted:     trusted,
	}).Error)
}

func seedScopeToken(t *testing.T, plain, clientId string, userId int, scopes string, expiresAt int64, revoked bool) {
	t.Helper()
	rec := &model.OAuthToken{
		GrantId:          "grant-" + plain,
		ClientId:         clientId,
		UserId:           userId,
		Scopes:           scopes,
		AccessExpiresAt:  expiresAt,
		RefreshExpiresAt: expiresAt,
		Revoked:          revoked,
	}
	rec.SetAccessToken(plain)
	require.NoError(t, rec.Insert())
}

func TestIsAccessToken(t *testing.T) {
	assert.True(t, IsAccessToken("at_abc123"))
	assert.False(t, IsAccessToken("sk-abc123"))
	assert.False(t, IsAccessToken(""))
	// The caller strips any "Bearer " wrapping before calling.
	assert.False(t, IsAccessToken("Bearer at_x"))
}

func TestBearerAccessToken(t *testing.T) {
	gin.SetMode(gin.TestMode)
	newCtx := func(req *http.Request) *gin.Context {
		c, _ := gin.CreateTestContext(httptest.NewRecorder())
		c.Request = req
		return c
	}

	// RFC 6750 §2.1 Authorization: Bearer header (scheme matched case-insensitively).
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer at_header")
	assert.Equal(t, "at_header", BearerAccessToken(newCtx(req)))

	req = httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "bEaReR   at_case  ")
	assert.Equal(t, "at_case", BearerAccessToken(newCtx(req)))

	// RFC 6750 §2.2 access_token form field.
	form := url.Values{"access_token": {"at_form"}}
	req = httptest.NewRequest(http.MethodPost, "/", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	assert.Equal(t, "at_form", BearerAccessToken(newCtx(req)))

	// RFC 6750 §2.3 URI query is NOT accepted.
	req = httptest.NewRequest(http.MethodGet, "/?access_token=at_query", nil)
	assert.Equal(t, "", BearerAccessToken(newCtx(req)))
}

func TestResolve(t *testing.T) {
	setupOAuthScopeTestDB(t)
	seedScopeUser(t, 1, common.UserStatusEnabled)
	future := time.Now().Add(time.Hour).Unix()
	past := time.Now().Add(-time.Hour).Unix()
	seedScopeToken(t, "at_ok", "cli_a", 1, "openid wallet.read", future, false)
	seedScopeToken(t, "at_revoked", "cli_a", 1, "openid", future, true)
	seedScopeToken(t, "at_expired", "cli_a", 1, "openid", past, false)

	grant, err := Resolve("at_ok")
	require.NoError(t, err)
	assert.Equal(t, 1, grant.UserId)
	assert.Equal(t, "cli_a", grant.ClientId)
	assert.Equal(t, []string{"openid", "wallet.read"}, grant.Scopes)

	// Empty/whitespace tokens never touch the database.
	_, err = Resolve("")
	assert.ErrorIs(t, err, ErrNoToken)
	_, err = Resolve("   ")
	assert.ErrorIs(t, err, ErrNoToken)

	// Unknown, revoked and expired tokens are all indistinguishable "invalid".
	_, err = Resolve("at_unknown")
	assert.ErrorIs(t, err, ErrInvalidToken)
	_, err = Resolve("at_revoked")
	assert.ErrorIs(t, err, ErrInvalidToken)
	_, err = Resolve("at_expired")
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestRequireScope(t *testing.T) {
	setupOAuthScopeTestDB(t)
	seedScopeClient(t, "cli_trusted", true)
	seedScopeClient(t, "cli_untrusted", false)

	// A nil grant is treated as an invalid token, never a silent pass.
	assert.ErrorIs(t, RequireScope(nil, oauthserver.ScopeWalletRead), ErrInvalidToken)

	// Non-sensitive scope: present → allowed, absent → insufficient_scope. The
	// client's trust is irrelevant when the scope is not sensitive.
	readGrant := &Grant{UserId: 1, ClientId: "cli_untrusted", Scopes: []string{"openid", oauthserver.ScopeWalletRead}}
	assert.NoError(t, RequireScope(readGrant, oauthserver.ScopeWalletRead))
	assert.ErrorIs(t, RequireScope(readGrant, oauthserver.ScopeModelsRead), ErrInsufficientScope)

	// Sensitive scope requires the issuing client be Trusted, re-checked here at
	// request time (defense in depth, not relying on the config-time gate alone).
	sensitive := []string{oauthserver.ScopeAPIKeysManage}
	assert.NoError(t, RequireScope(&Grant{UserId: 1, ClientId: "cli_trusted", Scopes: sensitive}, oauthserver.ScopeAPIKeysManage))
	assert.ErrorIs(t, RequireScope(&Grant{UserId: 1, ClientId: "cli_untrusted", Scopes: sensitive}, oauthserver.ScopeAPIKeysManage), ErrClientNotTrusted)

	// A sensitive grant whose client has since been deleted is denied, not errored.
	assert.ErrorIs(t, RequireScope(&Grant{UserId: 1, ClientId: "cli_gone", Scopes: sensitive}, oauthserver.ScopeAPIKeysManage), ErrClientNotTrusted)

	// Missing the scope short-circuits before the trust check.
	assert.ErrorIs(t, RequireScope(&Grant{UserId: 1, ClientId: "cli_trusted", Scopes: sensitive}, oauthserver.ScopeWalletTopUp), ErrInsufficientScope)
}

func TestAuthorizeRelay(t *testing.T) {
	setupOAuthScopeTestDB(t)
	seedScopeUser(t, 1, common.UserStatusEnabled)
	future := time.Now().Add(time.Hour).Unix()
	seedScopeToken(t, "at_invoke", "cli_a", 1, "openid models.invoke", future, false)
	seedScopeToken(t, "at_readonly", "cli_a", 1, "openid models.read", future, false)

	grant, err := AuthorizeRelay("at_invoke")
	require.NoError(t, err)
	assert.Equal(t, 1, grant.UserId)

	// The dedicated relay scope is mandatory; models.read alone is not enough.
	_, err = AuthorizeRelay("at_readonly")
	assert.ErrorIs(t, err, ErrInsufficientScope)

	_, err = AuthorizeRelay("at_unknown")
	assert.ErrorIs(t, err, ErrInvalidToken)
}

func TestDashboardScopeAuth(t *testing.T) {
	setupOAuthScopeTestDB(t)
	seedScopeUser(t, 1, common.UserStatusEnabled)
	seedScopeClient(t, "cli_trusted", true)
	seedScopeClient(t, "cli_untrusted", false)
	future := time.Now().Add(time.Hour).Unix()
	seedScopeToken(t, "at_read", "cli_untrusted", 1, "openid wallet.read", future, false)
	seedScopeToken(t, "at_sensitive_ok", "cli_trusted", 1, "apikeys.manage", future, false)
	seedScopeToken(t, "at_sensitive_bad", "cli_untrusted", 1, "apikeys.manage", future, false)

	// The terminal handler echoes the identity the middleware established, so a
	// 200 proves the token resolved to its owner and the context keys were set.
	router := func(scope string) *gin.Engine {
		r := gin.New()
		r.GET("/probe", DashboardScopeAuth(scope), func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{"id": c.GetInt("id"), "group": c.GetString("user_group")})
		})
		return r
	}
	do := func(scope, token string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodGet, "/probe", nil)
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		rec := httptest.NewRecorder()
		router(scope).ServeHTTP(rec, req)
		return rec
	}

	t.Run("valid token with scope resolves to owner", func(t *testing.T) {
		rec := do(oauthserver.ScopeWalletRead, "at_read")
		require.Equal(t, http.StatusOK, rec.Code)
		assert.Contains(t, rec.Body.String(), `"id":1`)
		assert.Contains(t, rec.Body.String(), `"group":"default"`)
	})
	t.Run("missing token is 401 invalid_token", func(t *testing.T) {
		rec := do(oauthserver.ScopeWalletRead, "")
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
	})
	t.Run("unknown token is 401 invalid_token", func(t *testing.T) {
		rec := do(oauthserver.ScopeWalletRead, "at_nope")
		assert.Equal(t, http.StatusUnauthorized, rec.Code)
		assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
	})
	t.Run("token without scope is 403 insufficient_scope naming the scope", func(t *testing.T) {
		rec := do(oauthserver.ScopeModelsRead, "at_read")
		assert.Equal(t, http.StatusForbidden, rec.Code)
		challenge := rec.Header().Get("WWW-Authenticate")
		assert.Contains(t, challenge, `error="insufficient_scope"`)
		assert.Contains(t, challenge, `scope="`+oauthserver.ScopeModelsRead+`"`)
	})
	t.Run("sensitive scope from a Trusted client is allowed", func(t *testing.T) {
		assert.Equal(t, http.StatusOK, do(oauthserver.ScopeAPIKeysManage, "at_sensitive_ok").Code)
	})
	t.Run("sensitive scope from a non-Trusted client is 403", func(t *testing.T) {
		rec := do(oauthserver.ScopeAPIKeysManage, "at_sensitive_bad")
		assert.Equal(t, http.StatusForbidden, rec.Code)
		assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `error="insufficient_scope"`)
	})
}

func TestDashboardScopeAuthRejectsDisabledUser(t *testing.T) {
	setupOAuthScopeTestDB(t)
	seedScopeUser(t, 1, common.UserStatusDisabled)
	future := time.Now().Add(time.Hour).Unix()
	// wallet.read is non-sensitive, so the disabled-account check is the only gate
	// left after the scope passes.
	seedScopeToken(t, "at_read", "cli_a", 1, "wallet.read", future, false)

	r := gin.New()
	r.GET("/probe", DashboardScopeAuth(oauthserver.ScopeWalletRead), func(c *gin.Context) {
		c.Status(http.StatusOK)
	})
	req := httptest.NewRequest(http.MethodGet, "/probe", nil)
	req.Header.Set("Authorization", "Bearer at_read")
	rec := httptest.NewRecorder()
	r.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusForbidden, rec.Code)
	assert.Contains(t, rec.Header().Get("WWW-Authenticate"), `error="invalid_token"`)
	assert.Contains(t, rec.Body.String(), "disabled")
}
