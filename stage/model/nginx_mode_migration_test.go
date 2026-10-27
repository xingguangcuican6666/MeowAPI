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
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMigrateRenamedIPRateLimitOptionCarriesEnabledToggleForward(t *testing.T) {
	db := useFrontendOptionMigrationDB(t)
	require.NoError(t, db.Create(&Option{
		Key:   deprecatedIPRateLimitOptionKey,
		Value: "true",
	}).Error)

	require.NoError(t, MigrateRenamedIPRateLimitOption())

	assert.Equal(t, "true", requireOptionValue(t, db, "NginxMode"))
	requireOptionMissing(t, db, deprecatedIPRateLimitOptionKey)

	// Startup migrations run on every boot; a second pass must not resurrect
	// the legacy row or disturb the migrated one.
	require.NoError(t, MigrateRenamedIPRateLimitOption())
	assert.Equal(t, "true", requireOptionValue(t, db, "NginxMode"))
	requireOptionMissing(t, db, deprecatedIPRateLimitOptionKey)
}

func TestMigrateRenamedIPRateLimitOptionPrefersStoredNginxMode(t *testing.T) {
	db := useFrontendOptionMigrationDB(t)
	require.NoError(t, db.Create(&[]Option{
		{Key: deprecatedIPRateLimitOptionKey, Value: "true"},
		{Key: "NginxMode", Value: "false"},
	}).Error)

	require.NoError(t, MigrateRenamedIPRateLimitOption())

	assert.Equal(t, "false", requireOptionValue(t, db, "NginxMode"))
	requireOptionMissing(t, db, deprecatedIPRateLimitOptionKey)
}

func TestMigrateRenamedIPRateLimitOptionDiscardsInertValues(t *testing.T) {
	db := useFrontendOptionMigrationDB(t)
	require.NoError(t, db.Create(&[]Option{
		{Key: deprecatedIPRateLimitOptionKey, Value: "false"},
		{Key: "CheckSensitiveEnabled", Value: "true"},
	}).Error)

	require.NoError(t, MigrateRenamedIPRateLimitOption())

	// A disabled toggle matches the default anyway; either way the legacy row
	// must not switch anything on.
	requireOptionMissing(t, db, "NginxMode")
	requireOptionMissing(t, db, deprecatedIPRateLimitOptionKey)
	assert.Equal(t, "true", requireOptionValue(t, db, "CheckSensitiveEnabled"))
}

func TestMigrateRenamedIPRateLimitOptionWithoutLegacyRow(t *testing.T) {
	useFrontendOptionMigrationDB(t)
	require.NoError(t, MigrateRenamedIPRateLimitOption())
}

func TestNginxModeOptionReachesEnforcementState(t *testing.T) {
	originalMode := common.NginxMode
	originalMap := common.OptionMap
	common.OptionMap = map[string]string{}
	t.Cleanup(func() {
		common.NginxMode = originalMode
		common.OptionMap = originalMap
	})

	require.NoError(t, updateOptionMap("NginxMode", "true"))
	assert.True(t, common.NginxMode, "nginx mode must reach the enforcement variable")
	assert.Equal(t, "true", common.OptionMap["NginxMode"])

	require.NoError(t, updateOptionMap("NginxMode", "false"))
	assert.False(t, common.NginxMode)
	assert.Equal(t, "false", common.OptionMap["NginxMode"])

	// Anything but an explicit true keeps IP limiting active, so a malformed
	// stored value fails closed rather than open.
	require.NoError(t, updateOptionMap("NginxMode", "true"))
	require.NoError(t, updateOptionMap("NginxMode", "garbage"))
	assert.False(t, common.NginxMode)
}
