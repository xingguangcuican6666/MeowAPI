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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
)

// PKCEMethodS256 is the only code challenge method new-api accepts. The plain
// method is intentionally unsupported (OAuth 2.1 / RFC 7636 §7.2 discourage it).
const PKCEMethodS256 = "S256"

// ValidChallengeMethod reports whether method is a code challenge method the
// server supports. An empty method is not valid here; callers decide whether
// PKCE is optional for a given client.
func ValidChallengeMethod(method string) bool {
	return method == PKCEMethodS256
}

// VerifyCodeChallenge checks a PKCE code_verifier against the stored challenge
// using S256 (RFC 7636 §4.6): BASE64URL(SHA256(verifier)) must equal challenge.
// The comparison is constant time to avoid leaking the challenge.
func VerifyCodeChallenge(verifier, challenge string) bool {
	if verifier == "" || challenge == "" {
		return false
	}
	sum := sha256.Sum256([]byte(verifier))
	computed := base64.RawURLEncoding.EncodeToString(sum[:])
	return subtle.ConstantTimeCompare([]byte(computed), []byte(challenge)) == 1
}
