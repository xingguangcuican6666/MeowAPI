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
	"sort"
	"strings"

	"github.com/QuantumNous/new-api/model"
)

// Scope is a single OAuth scope the authorization server understands. Title and
// Description are English fallbacks (used in discovery metadata and for clients
// that do not localize); the frontend consent screen localizes by Name.
type Scope struct {
	Name        string `json:"name"`
	Title       string `json:"title"`
	Description string `json:"description"`
	// OIDC marks scopes that map to OpenID Connect standard claims.
	OIDC bool `json:"oidc"`
	// Sensitive marks scopes that grant an action beyond reading identity claims
	// (for example, minting API keys). The consent screen highlights these so the
	// user notices the elevated request before approving.
	Sensitive bool `json:"sensitive"`
}

// The identity scopes map to OpenID Connect standard claims (see
// ClaimsForScopes). ScopeOpenID is required for any OIDC flow (issues an ID
// token).
const (
	ScopeOpenID  = "openid"
	ScopeProfile = "profile"
	ScopeEmail   = "email"
	ScopeGroups  = "groups"
)

// The business scopes each authorize one action domain against the resource
// owner's account, driven directly by the access token (no relay API key in
// between). They are named "<domain>.<action>". The sensitive ones (topping up
// the wallet, managing API keys) grant a privileged action, so a client may
// only request or hold them once an admin marks it Trusted.
const (
	// ScopeWalletRead grants read-only access to the owner's quota balance and
	// the configured top-up options.
	ScopeWalletRead = "wallet.read"
	// ScopeWalletTopUp authorizes creating top-up orders / payment links and
	// redeeming gift codes on the owner's behalf. Sensitive.
	ScopeWalletTopUp = "wallet.topup"
	// ScopeAPIKeysManage authorizes full CRUD over the owner's relay API keys.
	// Sensitive.
	ScopeAPIKeysManage = "apikeys.manage"
	// ScopeModelsRead grants read-only access to the groups, models and pricing
	// available to the owner.
	ScopeModelsRead = "models.read"
	// ScopeModelsInvoke authorizes calling the model relay API (/v1/*) on the
	// owner's behalf, spending the owner's own quota. It is a dedicated relay
	// scope, not an identity claim, and implies no ClaimsForScopes entry.
	ScopeModelsInvoke = "models.invoke"
)

// supportedScopes is the authorization server's scope catalog. Adding a scope
// here makes it available for clients to allow and for users to grant; wire any
// new claims it implies into ClaimsForScopes, and mark it Sensitive when it
// grants a privileged action rather than exposing an identity claim.
var supportedScopes = []Scope{
	{Name: ScopeOpenID, Title: "Sign you in", Description: "Verify your identity and sign you in", OIDC: true},
	{Name: ScopeProfile, Title: "Basic profile", Description: "Your username and display name", OIDC: true},
	{Name: ScopeEmail, Title: "Email address", Description: "Your email address", OIDC: true},
	{Name: ScopeGroups, Title: "Groups and role", Description: "Your account groups and role", OIDC: false},
	{Name: ScopeWalletRead, Title: "Read your wallet", Description: "View your quota balance and the available top-up options", OIDC: false},
	{Name: ScopeWalletTopUp, Title: "Top up your wallet", Description: "Create top-up orders and payment links and redeem gift codes on your behalf", OIDC: false, Sensitive: true},
	{Name: ScopeAPIKeysManage, Title: "Manage your API keys", Description: "Create, view, update and delete API keys on your account", OIDC: false, Sensitive: true},
	{Name: ScopeModelsRead, Title: "View available models", Description: "List the groups, models and pricing available to you", OIDC: false},
	{Name: ScopeModelsInvoke, Title: "Call models on your behalf", Description: "Send requests to the model API and spend your quota", OIDC: false},
}

// SensitiveScopeNames returns the scopes that grant a privileged action and so
// require the requesting client to be admin-marked Trusted.
func SensitiveScopeNames() []string {
	var out []string
	for _, s := range supportedScopes {
		if s.Sensitive {
			out = append(out, s.Name)
		}
	}
	return out
}

// ContainsSensitiveScope reports whether any scope in the set is sensitive.
func ContainsSensitiveScope(scopes []string) bool {
	for _, name := range scopes {
		if s, ok := scopeIndex[name]; ok && s.Sensitive {
			return true
		}
	}
	return false
}

var scopeIndex = func() map[string]Scope {
	m := make(map[string]Scope, len(supportedScopes))
	for _, s := range supportedScopes {
		m[s.Name] = s
	}
	return m
}()

// SupportedScopes returns the catalog in a stable order.
func SupportedScopes() []Scope {
	out := make([]Scope, len(supportedScopes))
	copy(out, supportedScopes)
	return out
}

// SupportedScopeNames returns just the scope identifiers, for discovery metadata.
func SupportedScopeNames() []string {
	names := make([]string, len(supportedScopes))
	for i, s := range supportedScopes {
		names[i] = s.Name
	}
	return names
}

// IsSupportedScope reports whether a scope is in the catalog.
func IsSupportedScope(name string) bool {
	_, ok := scopeIndex[name]
	return ok
}

// LookupScope returns the catalog entry for a scope name.
func LookupScope(name string) (Scope, bool) {
	s, ok := scopeIndex[name]
	return s, ok
}

// ParseScopes splits a space-delimited scope string into a de-duplicated,
// order-preserving slice. Empty and whitespace-only tokens are dropped.
func ParseScopes(raw string) []string {
	seen := make(map[string]struct{})
	var out []string
	for _, tok := range strings.Fields(raw) {
		if _, dup := seen[tok]; dup {
			continue
		}
		seen[tok] = struct{}{}
		out = append(out, tok)
	}
	return out
}

// JoinScopes renders a scope slice back to the space-delimited wire format.
func JoinScopes(scopes []string) string {
	return strings.Join(scopes, " ")
}

// NormalizeScopeString parses and rejoins so stored scope strings are canonical.
func NormalizeScopeString(raw string) string {
	return JoinScopes(ParseScopes(raw))
}

// FilterSupported keeps only scopes present in the catalog, preserving order.
func FilterSupported(scopes []string) []string {
	var out []string
	for _, s := range scopes {
		if IsSupportedScope(s) {
			out = append(out, s)
		}
	}
	return out
}

// ScopesSubset reports whether every scope in want is present in allow.
func ScopesSubset(want, allow []string) bool {
	allowed := make(map[string]struct{}, len(allow))
	for _, s := range allow {
		allowed[s] = struct{}{}
	}
	for _, s := range want {
		if _, ok := allowed[s]; !ok {
			return false
		}
	}
	return true
}

// ContainsScope reports whether scopes includes name.
func ContainsScope(scopes []string, name string) bool {
	for _, s := range scopes {
		if s == name {
			return true
		}
	}
	return false
}

// ClaimsForScopes builds the userinfo / ID-token claim set granted by scopes for
// a given user. The "sub" claim is always included when any claims are produced;
// callers requiring OIDC must ensure ScopeOpenID was granted. Group and role
// data is only exposed when the "groups" scope is present, matching consent.
func ClaimsForScopes(user *model.User, scopes []string) map[string]any {
	claims := make(map[string]any)
	for _, scope := range scopes {
		switch scope {
		case ScopeProfile:
			claims["preferred_username"] = user.Username
			if user.DisplayName != "" {
				claims["name"] = user.DisplayName
			} else {
				claims["name"] = user.Username
			}
		case ScopeEmail:
			if user.Email != "" {
				claims["email"] = user.Email
				// new-api verifies email addresses at bind time; a stored,
				// non-empty address is treated as verified.
				claims["email_verified"] = true
			}
		case ScopeGroups:
			groups := []string{user.Group}
			groups = append(groups, user.GetExtraGroups()...)
			claims["groups"] = dedupeNonEmpty(groups)
			claims["role"] = user.Role
		}
	}
	return claims
}

func dedupeNonEmpty(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	var out []string
	for _, v := range values {
		if v == "" {
			continue
		}
		if _, dup := seen[v]; dup {
			continue
		}
		seen[v] = struct{}{}
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
