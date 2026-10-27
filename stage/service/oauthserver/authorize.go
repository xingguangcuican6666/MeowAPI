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
	"errors"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

// AuthFlow purposes for the authorization-server flow. Kept local to this
// package so the shared auth_flow model stays unaware of OIDC-provider details.
const (
	authFlowPurposeAuthorize = "oauth_srv_authorize"
	authFlowPurposeCode      = "oauth_srv_code"
)

// ErrAuthorizeRequestInvalid is returned when a pending authorization request or
// authorization code cannot be found, has expired, or was already used. Callers
// map it to the OAuth "invalid_grant" / "invalid_request" errors.
var ErrAuthorizeRequestInvalid = errors.New("oauth authorization request is invalid or expired")

// PendingAuthorize is the validated state of an /authorize request, parked while
// the resource owner reviews the consent screen. The user is not yet known when
// it is created (the browser hitting /authorize carries no dashboard session),
// so it is bound to a user only when consent is granted.
type PendingAuthorize struct {
	ResponseType        string   `json:"response_type"`
	ClientId            string   `json:"client_id"`
	RedirectUri         string   `json:"redirect_uri"`
	Scopes              []string `json:"scopes"`
	State               string   `json:"state"`
	Nonce               string   `json:"nonce"`
	CodeChallenge       string   `json:"code_challenge"`
	CodeChallengeMethod string   `json:"code_challenge_method"`
}

// AuthorizationCode is the state bound to an issued authorization code, consumed
// exactly once at the token endpoint.
type AuthorizationCode struct {
	ClientId            string   `json:"client_id"`
	RedirectUri         string   `json:"redirect_uri"`
	Scopes              []string `json:"scopes"`
	Nonce               string   `json:"nonce"`
	CodeChallenge       string   `json:"code_challenge"`
	CodeChallengeMethod string   `json:"code_challenge_method"`
	UserId              int      `json:"user_id"`
	AuthTime            int64    `json:"auth_time"`
}

// StorePendingAuthorize parks a validated authorize request and returns an
// opaque request token to hand to the consent page.
func StorePendingAuthorize(p PendingAuthorize, ttlSeconds int) (string, error) {
	payload, err := common.Marshal(p)
	if err != nil {
		return "", err
	}
	token, _, err := model.CreateAuthFlow(model.AuthFlowCreate{
		Purpose:   authFlowPurposeAuthorize,
		Payload:   string(payload),
		ExpiresAt: time.Now().Add(time.Duration(ttlSeconds) * time.Second),
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

// LoadPendingAuthorize validates a request token without consuming it, so the
// consent page can render the request details. Consent submission consumes it.
func LoadPendingAuthorize(requestToken string) (*PendingAuthorize, error) {
	flow, err := model.GetAuthFlow(requestToken, model.AuthFlowMatch{Purpose: authFlowPurposeAuthorize})
	if err != nil {
		return nil, ErrAuthorizeRequestInvalid
	}
	var p PendingAuthorize
	if err := common.UnmarshalJsonStr(flow.Payload, &p); err != nil {
		return nil, ErrAuthorizeRequestInvalid
	}
	return &p, nil
}

// ConsumePendingAuthorize atomically consumes a parked authorize request. It is
// called on both approve and deny so a request token can never be replayed.
func ConsumePendingAuthorize(requestToken string) (*PendingAuthorize, error) {
	flow, err := model.ConsumeAuthFlow(requestToken, model.AuthFlowMatch{Purpose: authFlowPurposeAuthorize})
	if err != nil {
		return nil, ErrAuthorizeRequestInvalid
	}
	var p PendingAuthorize
	if err := common.UnmarshalJsonStr(flow.Payload, &p); err != nil {
		return nil, ErrAuthorizeRequestInvalid
	}
	return &p, nil
}

// IssueAuthorizationCode mints a single-use authorization code bound to the
// consenting user and returns the opaque code string.
func IssueAuthorizationCode(code AuthorizationCode, ttlSeconds int) (string, error) {
	payload, err := common.Marshal(code)
	if err != nil {
		return "", err
	}
	token, _, err := model.CreateAuthFlow(model.AuthFlowCreate{
		Purpose:   authFlowPurposeCode,
		UserId:    code.UserId,
		Payload:   string(payload),
		ExpiresAt: time.Now().Add(time.Duration(ttlSeconds) * time.Second),
	})
	if err != nil {
		return "", err
	}
	return token, nil
}

// ConsumeAuthorizationCode atomically consumes an authorization code, returning
// its bound state. A second use of the same code fails.
func ConsumeAuthorizationCode(codeStr string) (*AuthorizationCode, error) {
	flow, err := model.ConsumeAuthFlow(codeStr, model.AuthFlowMatch{Purpose: authFlowPurposeCode})
	if err != nil {
		return nil, ErrAuthorizeRequestInvalid
	}
	var code AuthorizationCode
	if err := common.UnmarshalJsonStr(flow.Payload, &code); err != nil {
		return nil, ErrAuthorizeRequestInvalid
	}
	return &code, nil
}
