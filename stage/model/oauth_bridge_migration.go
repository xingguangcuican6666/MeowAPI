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
	"github.com/QuantumNous/new-api/common"
)

// revokeOAuthBridgeTokens is a one-time, idempotent startup migration that
// revokes every relay API key minted through the removed POST /oauth2/keys
// bridge — that is, every Token whose oauth_client_id is non-empty. OAuth access
// tokens now drive the business endpoints directly through their own scopes, so
// these bridge-minted keys are no longer issued and any surviving ones must be
// invalidated to force integrations onto the access-token path.
//
// Idempotency and safety:
//   - The filter matches only rows whose oauth_client_id is a non-empty string.
//     Keys a user created directly carry an empty string, and legacy rows carry
//     SQL NULL (for which the inequality is unknown, never true), so no non-OAuth
//     key is ever touched.
//   - Token uses gorm soft delete, so a second run matches nothing (already
//     soft-deleted rows carry deleted_at) and reports zero — safe to run on every
//     startup across SQLite, MySQL and PostgreSQL.
//
// This runs inside InitDB, before InitRedisClient connects the cache, so the
// Redis client is normally nil here and the guarded invalidation is skipped.
// That is safe: a freshly started process has no local cache, and any entry
// left in an external shared cache expires within its short TTL. When a client
// is already connected the cache is invalidated first so a revoked key stops
// authenticating immediately; a cache error is logged but never aborts the
// migration (the next lookup re-hydrates from the database and finds the row gone).
func revokeOAuthBridgeTokens() (int64, error) {
	var tokens []Token
	if err := DB.Select("id", commonKeyCol).
		Where("oauth_client_id <> ''").
		Find(&tokens).Error; err != nil {
		return 0, err
	}
	if len(tokens) == 0 {
		return 0, nil
	}
	// Guard on an initialized client, not just RedisEnabled: RedisEnabled
	// defaults to true and is only corrected in InitRedisClient, which has not
	// run yet, so RDB is nil at migration time and calling it would panic.
	if common.RedisEnabled && common.RDB != nil {
		if err := invalidateTokensCache(tokens); err != nil {
			common.SysLog("revokeOAuthBridgeTokens: failed to invalidate token cache before revocation: " + err.Error())
		}
	}
	result := DB.Where("oauth_client_id <> ''").Delete(&Token{})
	if result.Error != nil {
		return 0, result.Error
	}
	return result.RowsAffected, nil
}
