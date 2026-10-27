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

package oauthserver

import (
	"fmt"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/system_setting"

	"github.com/golang-jwt/jwt/v5"
)

// TokenType is the only token type new-api issues at the token endpoint.
const TokenType = "Bearer"

// IssuedTokens is the result of a successful grant, shaped for the RFC 6749
// token endpoint JSON response.
type IssuedTokens struct {
	AccessToken  string
	RefreshToken string
	IDToken      string
	TokenType    string
	ExpiresIn    int
	Scope        string
}

// GrantContext is the validated authorization a code or refresh exchange draws
// on to mint tokens.
type GrantContext struct {
	Client   *model.OAuthClient
	UserId   int
	Scopes   []string
	Nonce    string
	AuthTime int64
}

func newRandomToken(prefix string) (string, error) {
	body, err := common.GenerateRandomCharsKey(48)
	if err != nil {
		return "", err
	}
	return prefix + body, nil
}

// IssueForAuthorizationCode mints a fresh access/refresh (and, for openid, ID)
// token set for a newly consumed authorization code.
func IssueForAuthorizationCode(g GrantContext) (*IssuedTokens, error) {
	settings := system_setting.GetOAuthServerSettings()
	now := time.Now()
	accessPlain, err := newRandomToken("at_")
	if err != nil {
		return nil, err
	}
	refreshPlain, err := newRandomToken("rt_")
	if err != nil {
		return nil, err
	}
	accessExpiresAt := now.Add(time.Duration(settings.GetAccessTokenTTL()) * time.Second).Unix()
	refreshExpiresAt := now.Add(time.Duration(settings.GetRefreshTokenTTL()) * time.Second).Unix()

	record := &model.OAuthToken{
		GrantId:          common.GetUUID(),
		ClientId:         g.Client.ClientId,
		UserId:           g.UserId,
		Scopes:           JoinScopes(g.Scopes),
		Nonce:            g.Nonce,
		AuthTime:         g.AuthTime,
		AccessExpiresAt:  accessExpiresAt,
		RefreshExpiresAt: refreshExpiresAt,
	}
	record.SetAccessToken(accessPlain)
	record.SetRefreshToken(refreshPlain)
	if err := record.Insert(); err != nil {
		return nil, err
	}

	return assembleTokens(g.Client, g.UserId, g.Scopes, g.Nonce, g.AuthTime, accessPlain, refreshPlain, settings.GetAccessTokenTTL())
}

// RefreshGrant rotates a refresh token, returning a new token set. The client is
// re-checked so a token issued to one client cannot be refreshed by another.
func RefreshGrant(client *model.OAuthClient, refreshToken string) (*IssuedTokens, error) {
	settings := system_setting.GetOAuthServerSettings()
	now := time.Now()
	accessPlain, err := newRandomToken("at_")
	if err != nil {
		return nil, err
	}
	refreshPlain, err := newRandomToken("rt_")
	if err != nil {
		return nil, err
	}
	rotation := model.OAuthTokenRotation{
		AccessTokenPlain:  accessPlain,
		RefreshTokenPlain: refreshPlain,
		AccessExpiresAt:   now.Add(time.Duration(settings.GetAccessTokenTTL()) * time.Second).Unix(),
		RefreshExpiresAt:  now.Add(time.Duration(settings.GetRefreshTokenTTL()) * time.Second).Unix(),
	}
	issued, err := model.RotateOAuthRefreshToken(refreshToken, rotation)
	if err != nil {
		return nil, err
	}
	if issued.ClientId != client.ClientId {
		return nil, model.ErrOAuthTokenNotFound
	}
	scopes := issued.GetScopes()
	return assembleTokens(client, issued.UserId, scopes, issued.Nonce, issued.AuthTime, accessPlain, refreshPlain, settings.GetAccessTokenTTL())
}

func assembleTokens(client *model.OAuthClient, userId int, scopes []string, nonce string, authTime int64, accessPlain, refreshPlain string, expiresIn int) (*IssuedTokens, error) {
	out := &IssuedTokens{
		AccessToken:  accessPlain,
		RefreshToken: refreshPlain,
		TokenType:    TokenType,
		ExpiresIn:    expiresIn,
		Scope:        JoinScopes(scopes),
	}
	if ContainsScope(scopes, ScopeOpenID) {
		idToken, err := IssueIDToken(client, userId, scopes, nonce, authTime)
		if err != nil {
			return nil, err
		}
		out.IDToken = idToken
	}
	return out, nil
}

// IssueIDToken builds and signs an OpenID Connect ID token (RS256) carrying the
// claims granted by scopes, with aud bound to the requesting client.
func IssueIDToken(client *model.OAuthClient, userId int, scopes []string, nonce string, authTime int64) (string, error) {
	key, kid, err := EnsureSigningKey()
	if err != nil {
		return "", err
	}
	user, err := model.GetUserById(userId, false)
	if err != nil {
		return "", err
	}
	settings := system_setting.GetOAuthServerSettings()
	now := time.Now()
	claims := jwt.MapClaims{
		"iss":       settings.GetIssuer(),
		"sub":       fmt.Sprintf("%d", userId),
		"aud":       client.ClientId,
		"iat":       now.Unix(),
		"exp":       now.Add(time.Duration(settings.GetAccessTokenTTL()) * time.Second).Unix(),
		"auth_time": authTime,
	}
	if nonce != "" {
		claims["nonce"] = nonce
	}
	// ID tokens carry the same identity claims the userinfo endpoint would return
	// for the granted scopes, so simple clients can avoid a second round-trip.
	for k, v := range ClaimsForScopes(user, scopes) {
		claims[k] = v
	}
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = kid
	return token.SignedString(key)
}

// UserInfo resolves an access token to its owner and returns the claim set the
// token's scopes permit. The "sub" claim is always present.
func UserInfo(accessToken string) (map[string]any, error) {
	record, err := model.FindActiveOAuthTokenByAccessToken(accessToken)
	if err != nil {
		return nil, err
	}
	user, err := model.GetUserById(record.UserId, false)
	if err != nil {
		return nil, err
	}
	claims := ClaimsForScopes(user, record.GetScopes())
	claims["sub"] = fmt.Sprintf("%d", record.UserId)
	return claims, nil
}
