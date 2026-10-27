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
	"os"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/setting"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// setupRegistrationGroupTestDatabase repoints the package database globals at
// a real server when TEST_REGISTRATION_GROUP_DIALECT selects mysql or
// postgres, so the scenarios below run against every supported database
// instead of only the TestMain in-memory SQLite.
func setupRegistrationGroupTestDatabase(t *testing.T) {
	t.Helper()
	dialect := strings.TrimSpace(os.Getenv("TEST_REGISTRATION_GROUP_DIALECT"))
	if dialect == "" || dialect == "sqlite" {
		return
	}
	dsnEnv := "TEST_" + strings.ToUpper(dialect) + "_DSN"
	dsn := strings.TrimSpace(os.Getenv(dsnEnv))
	if dsn == "" {
		t.Skipf("%s is not configured", dsnEnv)
	}
	db, dbType, err := chooseDB(dsnEnv, false)
	require.NoError(t, err)
	previousDB, previousLogDB := DB, LOG_DB
	previousMain, previousLog := common.MainDatabaseType(), common.LogDatabaseType()
	DB, LOG_DB = db, db
	common.SetDatabaseTypes(dbType, dbType)
	initCol()
	sqlDB, err := db.DB()
	require.NoError(t, err)
	t.Cleanup(func() {
		_ = db.Exec("DELETE FROM options").Error
		_ = db.Exec("DELETE FROM users").Error
		DB, LOG_DB = previousDB, previousLogDB
		common.SetDatabaseTypes(previousMain, previousLog)
		initCol()
		_ = sqlDB.Close()
	})
	require.NoError(t, db.AutoMigrate(&User{}, &Option{}))
	var version string
	versionQuery := "SELECT version()"
	if dbType == common.DatabaseTypeSQLite {
		versionQuery = "SELECT sqlite_version()"
	}
	require.NoError(t, db.Raw(versionQuery).Scan(&version).Error)
	t.Logf("registration group test database: %s %s", dialect, version)
}

func setupRegistrationGroupTest(t *testing.T) {
	t.Helper()
	setupRegistrationGroupTestDatabase(t)
	truncateTables(t)
	require.NoError(t, DB.AutoMigrate(&Option{}))
	require.NoError(t, DB.Exec("DELETE FROM options").Error)
	originalRatios := ratio_setting.GroupRatio2JSONString()
	originalDefault, _, originalErr := setting.RegistrationGroupConfiguration()
	originalOptionMap := common.OptionMap
	common.OptionMapRWMutex.Lock()
	common.OptionMap = make(map[string]string)
	common.OptionMapRWMutex.Unlock()
	require.NoError(t, ratio_setting.UpdateGroupRatioByJSONString(`{"default":1,"free":0,"vip":2}`))
	require.NoError(t, setting.ApplyRegistrationGroupConfiguration("default", ratio_setting.GetGroupRatioCopy()))
	t.Cleanup(func() {
		require.NoError(t, ratio_setting.UpdateGroupRatioByJSONString(originalRatios))
		if originalErr != nil {
			setting.ApplyInvalidRegistrationGroupConfiguration(originalDefault, ratio_setting.GetGroupRatioCopy(), originalErr)
		} else {
			require.NoError(t, setting.ApplyRegistrationGroupConfiguration(originalDefault, ratio_setting.GetGroupRatioCopy()))
		}
		common.OptionMapRWMutex.Lock()
		common.OptionMap = originalOptionMap
		common.OptionMapRWMutex.Unlock()
	})
}

func TestRegistrationInsertUsesConfiguredGroupOnly(t *testing.T) {
	setupRegistrationGroupTest(t)
	require.NoError(t, setting.ApplyRegistrationGroupConfiguration("free", ratio_setting.GetGroupRatioCopy()))

	registered := User{Username: "registered", Password: "registered-password", Group: ""}
	require.NoError(t, registered.InsertForRegistration(0))
	assert.Equal(t, "free", registered.Group)

	explicit := User{Username: "explicit", Password: "explicit-password", Group: "vip"}
	require.NoError(t, explicit.InsertForRegistration(0))
	assert.Equal(t, "vip", explicit.Group)

	managed := User{Username: "managed", Password: "managed-password"}
	require.NoError(t, managed.Insert(0))
	assert.Equal(t, "default", managed.Group)
}

func TestRegistrationGroupValidation(t *testing.T) {
	groups := map[string]float64{"default": 1, "free": 0}
	for _, test := range []struct {
		name  string
		valid bool
	}{
		{name: "default", valid: true},
		{name: "free", valid: true},
		{name: ""},
		{name: " free"},
		{name: "free "},
		{name: "auto"},
		{name: "unknown"},
		{name: strings.Repeat("界", 22)},
		{name: strings.Repeat("x", 65)},
		{name: string([]byte{0xff})},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := setting.ValidateRegistrationGroup(test.name, groups)
			if test.valid {
				require.NoError(t, err)
			} else {
				require.ErrorIs(t, err, setting.ErrRegistrationGroupUnavailable)
			}
		})
	}
}

func currentRegistrationGroup(t *testing.T) string {
	t.Helper()
	configured, _, err := setting.RegistrationGroupConfiguration()
	require.NoError(t, err)
	return configured
}

func TestRegistrationGroupOptionUpdatesAreAtomic(t *testing.T) {
	setupRegistrationGroupTest(t)
	require.NoError(t, UpdateOption("GroupRatio", `{"default":1,"free":0,"vip":2}`))
	require.NoError(t, UpdateOption(setting.DefaultRegistrationGroupOptionKey, "free"))

	err := UpdateOption("GroupRatio", `{"default":1,"vip":2}`)
	require.ErrorIs(t, err, setting.ErrRegistrationGroupUnavailable)
	assert.True(t, ratio_setting.ContainsGroupRatio("free"))
	assert.Equal(t, "free", currentRegistrationGroup(t))
	var persisted Option
	require.NoError(t, DB.First(&persisted, commonKeyCol+" = ?", "GroupRatio").Error)
	assert.Contains(t, persisted.Value, `"free":0`)

	require.NoError(t, UpdateOptionsBulk(map[string]string{
		"GroupRatio": `{"default":1,"vip":2}`,
		setting.DefaultRegistrationGroupOptionKey: "vip",
	}))
	assert.False(t, ratio_setting.ContainsGroupRatio("free"))
	assert.Equal(t, "vip", currentRegistrationGroup(t))
}

func TestInvalidPersistedRegistrationGroupFailsClosedAndCanBeRepaired(t *testing.T) {
	setupRegistrationGroupTest(t)
	require.NoError(t, DB.Create(&Option{Key: "GroupRatio", Value: `{"default":1}`}).Error)
	require.NoError(t, DB.Create(&Option{Key: setting.DefaultRegistrationGroupOptionKey, Value: "missing"}).Error)
	loadRegistrationGroupOptions([]*Option{
		{Key: "GroupRatio", Value: `{"default":1}`},
		{Key: setting.DefaultRegistrationGroupOptionKey, Value: "missing"},
	})

	user := User{Username: "blocked-registration", Password: "blocked-password"}
	err := user.InsertForRegistration(0)
	require.ErrorIs(t, err, setting.ErrRegistrationGroupUnavailable)
	var count int64
	require.NoError(t, DB.Model(&User{}).Where("username = ?", user.Username).Count(&count).Error)
	assert.Zero(t, count)

	require.NoError(t, UpdateOption(setting.DefaultRegistrationGroupOptionKey, "default"))
	require.NoError(t, user.InsertForRegistration(0))
	assert.Equal(t, "default", user.Group)
}

func TestRegistrationInsertWithTxRollsBackUnavailableGroup(t *testing.T) {
	setupRegistrationGroupTest(t)
	setting.ApplyInvalidRegistrationGroupConfiguration("missing", map[string]float64{"default": 1}, errors.New("test corruption"))

	err := DB.Transaction(func(tx *gorm.DB) error {
		user := User{Username: "transactional", Password: "transaction-password"}
		return user.InsertForRegistrationWithTx(tx, 0)
	})
	require.ErrorIs(t, err, setting.ErrRegistrationGroupUnavailable)
}
