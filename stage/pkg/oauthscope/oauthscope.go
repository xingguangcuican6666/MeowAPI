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

// Package oauthscope turns an OAuth 2.0 access token (at_...) into a first-class
// credential for new-api's own business endpoints, without going through a relay
// API key. It resolves a bearer token to its resource owner and granted scopes,
// enforces the scope required by an endpoint (and, for sensitive scopes, that the
// issuing client has been admin-marked Trusted), and exposes a Gin middleware for
// the dashboard-shaped OAuth API route group.
//
// Layering: this package imports model and service/oauthserver but never
// middleware or controller, so both the relay path (middleware/auth.go, which
// renders the OpenAI error envelope itself) and the dashboard API group can build
// on the pure decisions here. Scope name constants live in service/oauthserver
// (the single source of truth); this package does not redefine them.
package oauthscope

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service/oauthserver"

	"github.com/gin-gonic/gin"
)

// accessTokenPrefix is the opaque access-token prefix minted by the OAuth server
// (service/oauthserver.IssueForAuthorizationCode / RefreshGrant).
const accessTokenPrefix = "at_"

// Sentinel errors returned by Resolve/RequireScope/AuthorizeRelay so callers can
// map each to the right RFC 6750 response without string matching. A backend
// (database) failure is wrapped, not one of these, so callers can tell a
// deny-by-policy apart from a transient error and answer 500 rather than 401/403.
var (
	// ErrNoToken means no bearer access token was presented.
	ErrNoToken = errors.New("oauthscope: no bearer access token")
	// ErrInvalidToken means the access token is unknown, revoked or expired.
	ErrInvalidToken = errors.New("oauthscope: access token is invalid or has expired")
	// ErrInsufficientScope means the token is valid but lacks a required scope.
	ErrInsufficientScope = errors.New("oauthscope: access token is missing a required scope")
	// ErrClientNotTrusted means a sensitive scope was requested by a client the
	// administrator has not marked Trusted.
	ErrClientNotTrusted = errors.New("oauthscope: client is not trusted for the requested sensitive scope")
)

// Grant is the resolved authorization behind an access token: the resource owner
// the request acts as, the client that holds the token, and the granted scopes.
type Grant struct {
	UserId   int
	ClientId string
	Scopes   []string
}

// IsAccessToken reports whether a raw credential is an OAuth access token (as
// opposed to a relay sk- key), so a shared route can branch on the prefix. The
// caller passes the credential with any "Bearer "/"sk-" wrapping already removed.
func IsAccessToken(credential string) bool {
	return strings.HasPrefix(credential, accessTokenPrefix)
}

// Resolve validates a bearer access token and returns its grant. A revoked,
// expired or unknown token yields ErrInvalidToken; a database failure is wrapped
// so the caller can distinguish it and answer 500 instead of 401.
func Resolve(accessToken string) (*Grant, error) {
	if strings.TrimSpace(accessToken) == "" {
		return nil, ErrNoToken
	}
	record, err := model.FindActiveOAuthTokenByAccessToken(accessToken)
	if err != nil {
		if errors.Is(err, model.ErrOAuthTokenNotFound) {
			return nil, ErrInvalidToken
		}
		return nil, fmt.Errorf("oauthscope: resolve access token: %w", err)
	}
	return &Grant{
		UserId:   record.UserId,
		ClientId: record.ClientId,
		Scopes:   record.GetScopes(),
	}, nil
}

// RequireScope asserts the grant carries scope. For a sensitive scope it also
// re-checks, at request time, that the issuing client is still Trusted — never
// relying on the config-time gate alone (defense in depth, OWASP ASVS V4). A
// backend failure while loading the client is wrapped, not turned into a deny.
func RequireScope(grant *Grant, scope string) error {
	if grant == nil {
		return ErrInvalidToken
	}
	if !oauthserver.ContainsScope(grant.Scopes, scope) {
		return ErrInsufficientScope
	}
	if isSensitiveScope(scope) {
		return requireTrustedClient(grant.ClientId)
	}
	return nil
}

// AuthorizeRelay resolves an access token and asserts the dedicated
// models.invoke scope, for the /v1/* relay path. It returns the grant so the
// caller (middleware/auth.go) can set up the request context and render its own
// OpenAI-shaped errors.
func AuthorizeRelay(accessToken string) (*Grant, error) {
	grant, err := Resolve(accessToken)
	if err != nil {
		return nil, err
	}
	if err := RequireScope(grant, oauthserver.ScopeModelsInvoke); err != nil {
		return nil, err
	}
	return grant, nil
}

func isSensitiveScope(scope string) bool {
	if s, ok := oauthserver.LookupScope(scope); ok {
		return s.Sensitive
	}
	return false
}

func requireTrustedClient(clientId string) error {
	client, err := model.GetOAuthClientByClientId(clientId)
	if err != nil {
		if errors.Is(err, model.ErrOAuthClientNotFound) {
			return ErrClientNotTrusted
		}
		return fmt.Errorf("oauthscope: load client for trust check: %w", err)
	}
	if !client.Trusted {
		return ErrClientNotTrusted
	}
	return nil
}

// BearerAccessToken extracts an OAuth access token from the Authorization: Bearer
// header (RFC 6750 §2.1, scheme matched case-insensitively) or an access_token
// form field (§2.2). URI query tokens are not accepted (§2.3).
func BearerAccessToken(c *gin.Context) string {
	header := c.GetHeader("Authorization")
	if len(header) >= 7 && strings.EqualFold(header[:7], "Bearer ") {
		return strings.TrimSpace(header[7:])
	}
	return strings.TrimSpace(c.PostForm("access_token"))
}

// DashboardScopeAuth is the Gin middleware guarding the OAuth-scoped API route
// group. It authenticates the bearer access token, enforces the endpoint's
// required scope (and Trusted for sensitive scopes), loads the resource owner and
// writes the same request-context keys a dashboard session would (id, role,
// group, and the user_* cache keys), so the existing dashboard handlers run
// unchanged as the token's owner. Failures carry an RFC 6750 WWW-Authenticate
// challenge alongside the dashboard JSON envelope the handlers use.
func DashboardScopeAuth(scope string) gin.HandlerFunc {
	return func(c *gin.Context) {
		accessToken := BearerAccessToken(c)
		grant, err := Resolve(accessToken)
		if err != nil {
			switch {
			case errors.Is(err, ErrNoToken):
				writeChallenge(c, http.StatusUnauthorized, "invalid_token", "", "a bearer access token is required")
			case errors.Is(err, ErrInvalidToken):
				writeChallenge(c, http.StatusUnauthorized, "invalid_token", "", "the access token is invalid or has expired")
			default:
				common.SysError("oauthscope resolve error: " + err.Error())
				abortServerError(c)
			}
			return
		}
		if err := RequireScope(grant, scope); err != nil {
			switch {
			case errors.Is(err, ErrInsufficientScope):
				writeChallenge(c, http.StatusForbidden, "insufficient_scope", scope, "the "+scope+" scope is required")
			case errors.Is(err, ErrClientNotTrusted):
				writeChallenge(c, http.StatusForbidden, "insufficient_scope", scope, "this application is not permitted to use the "+scope+" scope")
			default:
				common.SysError("oauthscope scope check error: " + err.Error())
				abortServerError(c)
			}
			return
		}
		userCache, err := model.GetUserCache(grant.UserId)
		if err != nil {
			common.SysError(fmt.Sprintf("oauthscope get user cache error for user %d: %v", grant.UserId, err))
			abortServerError(c)
			return
		}
		if userCache.Status != common.UserStatusEnabled {
			writeChallenge(c, http.StatusForbidden, "invalid_token", "", "the account is disabled")
			return
		}
		c.Set("id", grant.UserId)
		c.Set("role", userCache.Role)
		c.Set("username", userCache.Username)
		c.Set("group", userCache.Group)
		c.Set("user_group", userCache.Group)
		userCache.WriteContext(c)
		c.Next()
	}
}

// writeChallenge renders an RFC 6750 §3 WWW-Authenticate challenge and aborts with
// the dashboard JSON envelope (matching the handlers this group fronts).
func writeChallenge(c *gin.Context, status int, errCode, scope, message string) {
	challenge := `Bearer error="` + errCode + `"`
	if errCode == "insufficient_scope" && scope != "" {
		challenge += `, scope="` + scope + `"`
	}
	c.Header("WWW-Authenticate", challenge)
	c.AbortWithStatusJSON(status, gin.H{"success": false, "message": message})
}

func abortServerError(c *gin.Context) {
	c.AbortWithStatusJSON(http.StatusInternalServerError, gin.H{"success": false, "message": "internal server error"})
}
