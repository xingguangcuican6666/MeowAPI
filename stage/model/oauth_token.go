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
	"strings"
	"time"

	"gorm.io/gorm"
)

var (
	ErrOAuthTokenNotFound     = errors.New("oauth token not found")
	ErrOAuthRefreshReused     = errors.New("oauth refresh token reuse detected")
	ErrOAuthRefreshExpired    = errors.New("oauth refresh token expired")
	ErrOAuthRefreshNotCurrent = errors.New("oauth refresh token is no longer current")
)

// OAuthToken is one issued access/refresh token pair for a third-party client.
// Rotating a refresh token supersedes its row (Revoked=true) and inserts a new
// row sharing GrantId, so a replayed old refresh token can be detected and used
// to revoke the whole family (RFC 6819 §5.2.2.3 refresh token rotation).
type OAuthToken struct {
	Id               int64  `json:"id" gorm:"primaryKey"`
	GrantId          string `json:"grant_id" gorm:"type:varchar(64);index;not null"`
	ClientId         string `json:"client_id" gorm:"type:varchar(64);index;not null"`
	UserId           int    `json:"user_id" gorm:"index;not null"`
	AccessTokenHash  string `json:"-" gorm:"type:varchar(128);uniqueIndex"`
	RefreshTokenHash string `json:"-" gorm:"type:varchar(128);index"`
	Scopes           string `json:"scopes" gorm:"type:varchar(512)"`
	Nonce            string `json:"-" gorm:"type:varchar(128)"`
	AuthTime         int64  `json:"auth_time"`
	AccessExpiresAt  int64  `json:"access_expires_at"`
	RefreshExpiresAt int64  `json:"refresh_expires_at"`
	Revoked          bool   `json:"revoked" gorm:"index;default:false"`
	CreatedAt        int64  `json:"created_at" gorm:"autoCreateTime"`
}

func (OAuthToken) TableName() string {
	return "oauth_tokens"
}

func (t *OAuthToken) SetAccessToken(plaintext string) {
	t.AccessTokenHash = hashOAuthSecret("access-token", plaintext)
}

func (t *OAuthToken) SetRefreshToken(plaintext string) {
	if plaintext == "" {
		t.RefreshTokenHash = ""
		return
	}
	t.RefreshTokenHash = hashOAuthSecret("refresh-token", plaintext)
}

func (t *OAuthToken) Insert() error {
	return DB.Create(t).Error
}

func (t *OAuthToken) GetScopes() []string {
	return strings.Fields(t.Scopes)
}

// FindActiveOAuthTokenByAccessToken resolves a bearer access token to its row,
// rejecting revoked or expired tokens. Used by the userinfo endpoint.
func FindActiveOAuthTokenByAccessToken(accessToken string) (*OAuthToken, error) {
	if accessToken == "" {
		return nil, ErrOAuthTokenNotFound
	}
	var token OAuthToken
	err := DB.Where("access_token_hash = ?", hashOAuthSecret("access-token", accessToken)).First(&token).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrOAuthTokenNotFound
		}
		return nil, err
	}
	if token.Revoked {
		return nil, ErrOAuthTokenNotFound
	}
	if token.AccessExpiresAt <= time.Now().Unix() {
		return nil, ErrOAuthTokenNotFound
	}
	return &token, nil
}

// OAuthTokenRotation carries the freshly generated successor token material into
// a refresh-token rotation.
type OAuthTokenRotation struct {
	AccessTokenPlain  string
	RefreshTokenPlain string
	AccessExpiresAt   int64
	RefreshExpiresAt  int64
}

// RotateOAuthRefreshToken atomically validates a presented refresh token and,
// on success, supersedes it with a new token pair in the same grant family.
// A refresh token that was already rotated (revoked row) triggers family-wide
// revocation and ErrOAuthRefreshReused.
func RotateOAuthRefreshToken(refreshToken string, next OAuthTokenRotation) (*OAuthToken, error) {
	if refreshToken == "" {
		return nil, ErrOAuthTokenNotFound
	}
	refreshHash := hashOAuthSecret("refresh-token", refreshToken)
	var issued *OAuthToken
	err := DB.Transaction(func(tx *gorm.DB) error {
		var current OAuthToken
		if err := lockForUpdate(tx).Where("refresh_token_hash = ?", refreshHash).First(&current).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				return ErrOAuthTokenNotFound
			}
			return err
		}
		if current.Revoked {
			// The presented refresh token was already rotated: this is a replay.
			// Revoke every token in the family to contain a possible theft.
			if err := tx.Model(&OAuthToken{}).Where("grant_id = ?", current.GrantId).
				Update("revoked", true).Error; err != nil {
				return err
			}
			return ErrOAuthRefreshReused
		}
		if current.RefreshExpiresAt <= time.Now().Unix() {
			return ErrOAuthRefreshExpired
		}
		if err := tx.Model(&OAuthToken{}).Where("id = ?", current.Id).
			Update("revoked", true).Error; err != nil {
			return err
		}
		successor := &OAuthToken{
			GrantId:          current.GrantId,
			ClientId:         current.ClientId,
			UserId:           current.UserId,
			Scopes:           current.Scopes,
			Nonce:            current.Nonce,
			AuthTime:         current.AuthTime,
			AccessExpiresAt:  next.AccessExpiresAt,
			RefreshExpiresAt: next.RefreshExpiresAt,
		}
		successor.SetAccessToken(next.AccessTokenPlain)
		successor.SetRefreshToken(next.RefreshTokenPlain)
		if err := tx.Create(successor).Error; err != nil {
			return err
		}
		issued = successor
		return nil
	})
	if err != nil {
		return nil, err
	}
	return issued, nil
}

// RevokeOAuthTokenForClient revokes the token presented at the RFC 7009
// revocation endpoint, matching it as either an access or a refresh token, but
// only when it belongs to the authenticated client. The whole grant family is
// revoked so neither half of a leaked pair remains usable. An unknown token is a
// no-op, because RFC 7009 §2.2 requires the endpoint to succeed regardless.
func RevokeOAuthTokenForClient(clientId, presented string) error {
	if presented == "" || clientId == "" {
		return nil
	}
	accessHash := hashOAuthSecret("access-token", presented)
	refreshHash := hashOAuthSecret("refresh-token", presented)
	var token OAuthToken
	err := DB.Where("client_id = ? AND (access_token_hash = ? OR refresh_token_hash = ?)",
		clientId, accessHash, refreshHash).First(&token).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		return err
	}
	return DB.Model(&OAuthToken{}).Where("grant_id = ?", token.GrantId).Update("revoked", true).Error
}

func DeleteExpiredOAuthTokens(now time.Time) error {
	cutoff := now.Add(-24 * time.Hour).Unix()
	return DB.Where("refresh_expires_at < ? AND access_expires_at < ?", cutoff, cutoff).
		Delete(&OAuthToken{}).Error
}
