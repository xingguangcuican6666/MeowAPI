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

package model

import (
	"errors"
	"net/url"
	"strings"

	"github.com/QuantumNous/new-api/common"

	"gorm.io/gorm"
)

const (
	OAuthClientStatusEnabled  = 1
	OAuthClientStatusDisabled = 2

	// DefaultOAuthClientScopes is the scope set granted to a new client when the
	// admin does not narrow it.
	DefaultOAuthClientScopes = "openid profile email"
)

var (
	ErrOAuthClientNotFound = errors.New("oauth client not found")
	ErrOAuthClientDisabled = errors.New("oauth client is disabled")
)

// OAuthClient is a third-party application registered to use new-api as an
// OAuth 2.0 / OpenID Connect identity provider.
type OAuthClient struct {
	Id          int    `json:"id" gorm:"primaryKey"`
	ClientId    string `json:"client_id" gorm:"type:varchar(64);uniqueIndex;not null"`
	SecretHash  string `json:"-" gorm:"type:varchar(128)"` // HMAC of the client secret; never exposed
	Name        string `json:"name" gorm:"type:varchar(128);not null"`
	Description string `json:"description" gorm:"type:varchar(512);default:''"`
	Logo        string `json:"logo" gorm:"type:varchar(512);default:''"`
	Homepage    string `json:"homepage" gorm:"type:varchar(512);default:''"`
	// RedirectUris is a JSON array of exact-match allowed redirect URIs.
	RedirectUris string `json:"redirect_uris" gorm:"type:text"`
	// Scopes is a space-delimited list of scopes this client may request.
	Scopes string `json:"scopes" gorm:"type:varchar(512);default:'openid profile email'"`
	// IsPublic marks a public (non-confidential) client that authenticates with
	// PKCE instead of a client secret.
	IsPublic bool `json:"is_public" gorm:"default:false"`
	// Trusted marks a client an administrator has vetted to hold sensitive
	// scopes (wallet.topup, apikeys.manage). Only an admin may set it, and a
	// client may request or hold a sensitive scope only while it is true. The
	// zero value (false) is deliberately the safe default, so no gorm default
	// tag is set (a bool default:true/false tag causes AutoMigrate churn).
	Trusted     bool  `json:"trusted"`
	Status      int   `json:"status" gorm:"default:1"`
	OwnerUserId int   `json:"owner_user_id" gorm:"index;default:0"`
	CreatedAt   int64 `json:"created_at" gorm:"autoCreateTime"`
	UpdatedAt   int64 `json:"updated_at" gorm:"autoUpdateTime"`
}

func (OAuthClient) TableName() string {
	return "oauth_clients"
}

// hashOAuthSecret domain-separates each secret kind so a value from one context
// can never validate in another, keying off the process SessionSecret.
func hashOAuthSecret(kind, secret string) string {
	return common.GenerateHMACWithKey([]byte("oauth-"+kind+"-v1:"+common.SessionSecret), secret)
}

func (c *OAuthClient) IsEnabled() bool {
	return c.Status == OAuthClientStatusEnabled
}

// SetSecret hashes and stores a freshly generated client secret.
func (c *OAuthClient) SetSecret(secret string) {
	c.SecretHash = hashOAuthSecret("client-secret", secret)
}

// ValidateSecret checks a presented client secret in constant time via HMAC.
func (c *OAuthClient) ValidateSecret(secret string) bool {
	if c.SecretHash == "" || secret == "" {
		return false
	}
	return hashOAuthSecret("client-secret", secret) == c.SecretHash
}

// GetRedirectUris decodes the stored JSON array of registered redirect URIs.
func (c *OAuthClient) GetRedirectUris() []string {
	if strings.TrimSpace(c.RedirectUris) == "" {
		return nil
	}
	var uris []string
	if err := common.Unmarshal([]byte(c.RedirectUris), &uris); err != nil {
		return nil
	}
	return uris
}

// RedirectUriRegistered reports whether uri exactly matches a registered
// redirect URI. Exact matching (no substring/prefix logic) is required by
// RFC 6749 §3.1.2 to prevent open-redirect abuse.
func (c *OAuthClient) RedirectUriRegistered(uri string) bool {
	for _, registered := range c.GetRedirectUris() {
		if registered == uri {
			return true
		}
	}
	return false
}

// GetScopes returns the client's allowed scopes as a slice.
func (c *OAuthClient) GetScopes() []string {
	return strings.Fields(c.Scopes)
}

// GetAllOAuthClients returns every registered client, newest first.
func GetAllOAuthClients() ([]*OAuthClient, error) {
	var clients []*OAuthClient
	err := DB.Order("id desc").Find(&clients).Error
	return clients, err
}

// GetOAuthClientsByOwner returns clients owned by a specific user.
func GetOAuthClientsByOwner(ownerId int) ([]*OAuthClient, error) {
	var clients []*OAuthClient
	err := DB.Where("owner_user_id = ?", ownerId).Order("id desc").Find(&clients).Error
	return clients, err
}

func GetOAuthClientById(id int) (*OAuthClient, error) {
	var client OAuthClient
	if err := DB.First(&client, id).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrOAuthClientNotFound
		}
		return nil, err
	}
	return &client, nil
}

// GetOAuthClientByClientId looks a client up by its public client_id.
func GetOAuthClientByClientId(clientId string) (*OAuthClient, error) {
	if strings.TrimSpace(clientId) == "" {
		return nil, ErrOAuthClientNotFound
	}
	var client OAuthClient
	if err := DB.Where("client_id = ?", clientId).First(&client).Error; err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrOAuthClientNotFound
		}
		return nil, err
	}
	return &client, nil
}

func (c *OAuthClient) Insert() error {
	if err := c.validate(); err != nil {
		return err
	}
	return DB.Create(c).Error
}

func (c *OAuthClient) Update() error {
	if err := c.validate(); err != nil {
		return err
	}
	// Persist all columns except the primary key so clearing a field (e.g. logo)
	// takes effect, while never overwriting the secret hash with a blank value.
	return DB.Model(c).Omit("id", "created_at", "owner_user_id").Save(c).Error
}

// DeleteOAuthClient removes a client together with all OAuth tokens, consent
// grants, AND relay API keys minted for it (across every user), so deleting an
// application leaves no usable credential behind.
func DeleteOAuthClient(id int) error {
	return DB.Transaction(func(tx *gorm.DB) error {
		client, err := GetOAuthClientById(id)
		if err != nil {
			return err
		}
		if err := tx.Where("client_id = ?", client.ClientId).Delete(&OAuthToken{}).Error; err != nil {
			return err
		}
		if err := tx.Where("client_id = ?", client.ClientId).Delete(&OAuthUserGrant{}).Error; err != nil {
			return err
		}
		if _, err := deleteTokensByOAuthClientTx(tx, client.ClientId, nil); err != nil {
			return err
		}
		return tx.Delete(&OAuthClient{}, id).Error
	})
}

func (c *OAuthClient) validate() error {
	c.Name = strings.TrimSpace(c.Name)
	if c.Name == "" {
		return errors.New("application name is required")
	}
	c.Scopes = normalizeScopeField(c.Scopes)
	if c.Scopes == "" {
		c.Scopes = DefaultOAuthClientScopes
	}
	uris := c.GetRedirectUris()
	if len(uris) == 0 {
		return errors.New("at least one redirect URI is required")
	}
	cleaned := make([]string, 0, len(uris))
	for _, raw := range uris {
		uri := strings.TrimSpace(raw)
		if uri == "" {
			continue
		}
		if err := validateRedirectUri(uri); err != nil {
			return err
		}
		cleaned = append(cleaned, uri)
	}
	if len(cleaned) == 0 {
		return errors.New("at least one redirect URI is required")
	}
	encoded, err := common.Marshal(cleaned)
	if err != nil {
		return err
	}
	c.RedirectUris = string(encoded)
	if c.Status != OAuthClientStatusEnabled && c.Status != OAuthClientStatusDisabled {
		c.Status = OAuthClientStatusEnabled
	}
	return nil
}

// validateRedirectUri enforces the OAuth security baseline: an absolute URI, no
// fragment, and https unless it targets loopback for native/dev clients.
func validateRedirectUri(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return errors.New("redirect URI is not a valid URL: " + raw)
	}
	if !parsed.IsAbs() || parsed.Host == "" {
		return errors.New("redirect URI must be an absolute URL: " + raw)
	}
	if parsed.Fragment != "" {
		return errors.New("redirect URI must not contain a fragment: " + raw)
	}
	scheme := strings.ToLower(parsed.Scheme)
	host := strings.ToLower(parsed.Hostname())
	isLoopback := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if scheme == "http" && !isLoopback {
		return errors.New("redirect URI must use https (except for loopback): " + raw)
	}
	return nil
}

func normalizeScopeField(raw string) string {
	seen := make(map[string]struct{})
	var out []string
	for _, tok := range strings.Fields(raw) {
		if _, dup := seen[tok]; dup {
			continue
		}
		seen[tok] = struct{}{}
		out = append(out, tok)
	}
	return strings.Join(out, " ")
}

// GenerateOAuthClientId returns a new random public client identifier.
func GenerateOAuthClientId() string {
	return "cli_" + common.GetUUID()
}

// GenerateOAuthClientSecret returns a new random client secret in plaintext; the
// caller stores only its hash via OAuthClient.SetSecret and shows it once.
func GenerateOAuthClientSecret() (string, error) {
	return common.GenerateRandomKey(48)
}
