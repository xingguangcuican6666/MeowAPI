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
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/setting/system_setting"
)

// signingKeyMu guards lazy generation so concurrent first-use requests do not
// each generate and persist a different key.
var signingKeyMu sync.Mutex

// SigningKeyBits is the RSA modulus size for ID-token signing keys.
const SigningKeyBits = 2048

// EnsureSigningKey returns the active RSA private key and its JWKS key id,
// generating and persisting one on first use.
func EnsureSigningKey() (*rsa.PrivateKey, string, error) {
	settings := system_setting.GetOAuthServerSettings()
	if key, kid, err := parseSigningKey(settings); err == nil {
		return key, kid, nil
	}

	signingKeyMu.Lock()
	defer signingKeyMu.Unlock()

	// Re-check after acquiring the lock: another goroutine may have generated it.
	settings = system_setting.GetOAuthServerSettings()
	if key, kid, err := parseSigningKey(settings); err == nil {
		return key, kid, nil
	}

	key, err := rsa.GenerateKey(rand.Reader, SigningKeyBits)
	if err != nil {
		return nil, "", fmt.Errorf("generate oauth signing key: %w", err)
	}
	der := x509.MarshalPKCS1PrivateKey(key)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: der})
	kid := common.GetUUID()

	// Persist through the option layer so the value is stored in the DB and
	// synced to the in-memory config struct on every node.
	if err := model.UpdateOption("oauth_server.signing_key", string(pemBytes)); err != nil {
		return nil, "", fmt.Errorf("persist oauth signing key: %w", err)
	}
	if err := model.UpdateOption("oauth_server.signing_key_id", kid); err != nil {
		return nil, "", fmt.Errorf("persist oauth signing key id: %w", err)
	}
	return key, kid, nil
}

func parseSigningKey(settings *system_setting.OAuthServerSettings) (*rsa.PrivateKey, string, error) {
	if settings.SigningKey == "" || settings.SigningKeyId == "" {
		return nil, "", errors.New("oauth signing key not configured")
	}
	block, _ := pem.Decode([]byte(settings.SigningKey))
	if block == nil {
		return nil, "", errors.New("oauth signing key is not valid PEM")
	}
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, "", fmt.Errorf("parse oauth signing key: %w", err)
	}
	return key, settings.SigningKeyId, nil
}

// JWKS builds the JSON Web Key Set exposing the current signing key's public
// half, so relying parties can verify ID token signatures.
func JWKS() (map[string]any, error) {
	key, kid, err := EnsureSigningKey()
	if err != nil {
		return nil, err
	}
	pub := key.Public().(*rsa.PublicKey)
	n := base64.RawURLEncoding.EncodeToString(pub.N.Bytes())
	e := base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes())
	return map[string]any{
		"keys": []map[string]any{
			{
				"kty": "RSA",
				"use": "sig",
				"alg": "RS256",
				"kid": kid,
				"n":   n,
				"e":   e,
			},
		},
	}, nil
}
