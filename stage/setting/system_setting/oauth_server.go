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

package system_setting

import (
	"strings"

	"github.com/QuantumNous/new-api/setting/config"
)

// OAuthServerSettings configures new-api's built-in OAuth 2.0 / OpenID Connect
// authorization server (new-api acting as an identity provider for third-party
// applications). This is distinct from the OAuth *client* login providers
// (GitHub / OIDC / custom) that let users sign in to new-api.
type OAuthServerSettings struct {
	Enabled bool `json:"enabled"`
	// Issuer overrides the OIDC issuer identifier. Empty means derive it from
	// system_setting.ServerAddress.
	Issuer string `json:"issuer"`
	// SigningKey holds the PEM-encoded RSA private key used to sign ID tokens.
	// It is generated automatically on first use and persisted here. Ends in
	// "Key" so controller.GetOptions never returns it to the frontend.
	SigningKey string `json:"signing_key"`
	// SigningKeyId is the stable JWKS "kid" advertised for SigningKey.
	SigningKeyId string `json:"signing_key_id"`
	// Token lifetimes in seconds. Zero falls back to the defaults below.
	AccessTokenTTL       int `json:"access_token_ttl"`
	RefreshTokenTTL      int `json:"refresh_token_ttl"`
	AuthorizationCodeTTL int `json:"authorization_code_ttl"`
	// AllowUserRegistration lets non-admin users register their own OAuth
	// client applications. Disabled by default: clients are admin-managed.
	AllowUserRegistration bool `json:"allow_user_registration"`
}

const (
	DefaultOAuthAccessTokenTTL       = 3600       // 1 hour
	DefaultOAuthRefreshTokenTTL      = 30 * 86400 // 30 days
	DefaultOAuthAuthorizationCodeTTL = 600        // 10 minutes
)

var defaultOAuthServerSettings = OAuthServerSettings{
	AccessTokenTTL:       DefaultOAuthAccessTokenTTL,
	RefreshTokenTTL:      DefaultOAuthRefreshTokenTTL,
	AuthorizationCodeTTL: DefaultOAuthAuthorizationCodeTTL,
}

func init() {
	config.GlobalConfig.Register("oauth_server", &defaultOAuthServerSettings)
}

func GetOAuthServerSettings() *OAuthServerSettings {
	return &defaultOAuthServerSettings
}

// GetIssuer returns the effective OIDC issuer identifier, trimming any trailing
// slash so downstream URL concatenation stays canonical.
func (s *OAuthServerSettings) GetIssuer() string {
	issuer := strings.TrimSpace(s.Issuer)
	if issuer == "" {
		issuer = strings.TrimSpace(ServerAddress)
	}
	return strings.TrimRight(issuer, "/")
}

func (s *OAuthServerSettings) GetAccessTokenTTL() int {
	if s.AccessTokenTTL <= 0 {
		return DefaultOAuthAccessTokenTTL
	}
	return s.AccessTokenTTL
}

func (s *OAuthServerSettings) GetRefreshTokenTTL() int {
	if s.RefreshTokenTTL <= 0 {
		return DefaultOAuthRefreshTokenTTL
	}
	return s.RefreshTokenTTL
}

func (s *OAuthServerSettings) GetAuthorizationCodeTTL() int {
	if s.AuthorizationCodeTTL <= 0 {
		return DefaultOAuthAuthorizationCodeTTL
	}
	return s.AuthorizationCodeTTL
}
