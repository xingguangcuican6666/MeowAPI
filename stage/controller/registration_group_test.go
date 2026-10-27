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

package controller

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/i18n"
	"github.com/QuantumNous/new-api/model"
	"github.com/QuantumNous/new-api/service/authz"
	"github.com/QuantumNous/new-api/setting"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupRegistrationGroupControllerTest provides a real (SQLite by default)
// database and the option tables the registration path reads from.
func setupRegistrationGroupControllerTest(t *testing.T) {
	t.Helper()
	db := setupManageUserTestDB(t)
	require.NoError(t, i18n.Init())
	require.NoError(t, db.AutoMigrate(&model.Option{}))
	require.NoError(t, db.Exec("DELETE FROM options").Error)
	require.NoError(t, authz.Init(db))

	originalRatios := ratio_setting.GroupRatio2JSONString()
	originalConfigured, _, originalErr := setting.RegistrationGroupConfiguration()
	require.NoError(t, ratio_setting.UpdateGroupRatioByJSONString(`{"default":1,"free":0,"vip":2}`))
	require.NoError(t, setting.ApplyRegistrationGroupConfiguration("default", ratio_setting.GetGroupRatioCopy()))
	t.Cleanup(func() {
		require.NoError(t, ratio_setting.UpdateGroupRatioByJSONString(originalRatios))
		if originalErr != nil {
			setting.ApplyInvalidRegistrationGroupConfiguration(originalConfigured, ratio_setting.GetGroupRatioCopy(), originalErr)
		} else {
			require.NoError(t, setting.ApplyRegistrationGroupConfiguration(originalConfigured, ratio_setting.GetGroupRatioCopy()))
		}
	})

	previousRegister, previousPasswordRegister := common.RegisterEnabled, common.PasswordRegisterEnabled
	previousInviteCode := common.InviteCodeRegisterEnabled
	common.RegisterEnabled = true
	common.PasswordRegisterEnabled = true
	common.InviteCodeRegisterEnabled = true
	t.Cleanup(func() {
		common.RegisterEnabled, common.PasswordRegisterEnabled = previousRegister, previousPasswordRegister
		common.InviteCodeRegisterEnabled = previousInviteCode
	})
}

func performRegisterRequest(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/register", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	Register(c)
	return recorder
}

func performCreateUserRequest(t *testing.T, body string) *httptest.ResponseRecorder {
	t.Helper()
	gin.SetMode(gin.TestMode)
	recorder := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(recorder)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/user/", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Set("id", 9999)
	c.Set("role", common.RoleRootUser)
	c.Set("username", "root-operator")
	c.Set(common.RequestIdKey, "registration-group-test")
	CreateUser(c)
	return recorder
}

func TestRegisterUsesConfiguredGroupAndIgnoresClientGroup(t *testing.T) {
	setupRegistrationGroupControllerTest(t)
	require.NoError(t, setting.ApplyRegistrationGroupConfiguration("free", ratio_setting.GetGroupRatioCopy()))
	createRegistrationInviter(t, "group-inviter", "group-valid-invite")

	recorder := performRegisterRequest(t, `{"username":"selfservice","password":"password-1234","aff_code":"group-valid-invite","group":"vip"}`)
	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Contains(t, recorder.Body.String(), `"success":true`)

	var created model.User
	require.NoError(t, model.DB.First(&created, "username = ?", "selfservice").Error)
	assert.Equal(t, "free", created.Group, "the server-configured group must win over the ignored client field")
}

func createRegistrationInviter(t *testing.T, username, affCode string) model.User {
	t.Helper()
	inviter := model.User{
		Username: username, Password: "password-1234", Role: common.RoleCommonUser,
		Status: common.UserStatusEnabled, Group: "default", AuthVersion: 1, AffCode: affCode,
	}
	require.NoError(t, model.DB.Create(&inviter).Error)
	return inviter
}

func TestRegisterRequiresInvitationCode(t *testing.T) {
	setupRegistrationGroupControllerTest(t)

	tests := []struct {
		name    string
		body    string
		message string
	}{
		{
			name:    "missing",
			body:    `{"username":"missing-invite","password":"password-1234"}`,
			message: i18n.T(nil, i18n.MsgUserAffCodeEmpty),
		},
		{
			name:    "blank",
			body:    `{"username":"blank-invite","password":"password-1234","aff_code":"   "}`,
			message: i18n.T(nil, i18n.MsgUserAffCodeEmpty),
		},
		{
			name:    "invalid",
			body:    `{"username":"invalid-invite","password":"password-1234","aff_code":"not-found"}`,
			message: i18n.T(nil, i18n.MsgUserAffCodeInvalid),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := performRegisterRequest(t, test.body)
			require.Equal(t, http.StatusOK, recorder.Code)
			assert.Contains(t, recorder.Body.String(), `"success":false`)
			assert.Contains(t, recorder.Body.String(), test.message)
		})
	}

	var count int64
	require.NoError(t, model.DB.Model(&model.User{}).Count(&count).Error)
	assert.Zero(t, count)
}

func TestRegisterAcceptsValidTrimmedInvitationCode(t *testing.T) {
	setupRegistrationGroupControllerTest(t)
	require.NoError(t, setting.ApplyRegistrationGroupConfiguration("free", ratio_setting.GetGroupRatioCopy()))
	inviter := createRegistrationInviter(t, "inviter", "valid-invite")

	recorder := performRegisterRequest(t, `{"username":"invited-user","password":"password-1234","aff_code":"  valid-invite  ","group":"vip"}`)
	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Contains(t, recorder.Body.String(), `"success":true`)

	var created model.User
	require.NoError(t, model.DB.First(&created, "username = ?", "invited-user").Error)
	assert.Equal(t, inviter.Id, created.InviterId)
	assert.Equal(t, "free", created.Group)
}

func TestRegisterInviteCodeOptionalWhenDisabled(t *testing.T) {
	setupRegistrationGroupControllerTest(t)
	require.NoError(t, setting.ApplyRegistrationGroupConfiguration("free", ratio_setting.GetGroupRatioCopy()))
	inviter := createRegistrationInviter(t, "optional-inviter", "optional-invite")
	common.InviteCodeRegisterEnabled = false

	// Without the toggle, registration succeeds with no inviter attached.
	recorder := performRegisterRequest(t, `{"username":"no-invite","password":"password-1234"}`)
	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Contains(t, recorder.Body.String(), `"success":true`)
	var noInvite model.User
	require.NoError(t, model.DB.Where("username = ?", "no-invite").First(&noInvite).Error)
	assert.Zero(t, noInvite.InviterId)

	// An invalid code does not block registration and attributes nobody.
	recorder = performRegisterRequest(t, `{"username":"bad-invite","password":"password-1234","aff_code":"not-found"}`)
	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Contains(t, recorder.Body.String(), `"success":true`)
	var badInvite model.User
	require.NoError(t, model.DB.Where("username = ?", "bad-invite").First(&badInvite).Error)
	assert.Zero(t, badInvite.InviterId)

	// A valid code still attributes the inviter.
	recorder = performRegisterRequest(t, `{"username":"linked-invite","password":"password-1234","aff_code":"optional-invite"}`)
	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Contains(t, recorder.Body.String(), `"success":true`)
	var linked model.User
	require.NoError(t, model.DB.Where("username = ?", "linked-invite").First(&linked).Error)
	assert.Equal(t, inviter.Id, linked.InviterId)
}

func TestCreateUserKeepsDefaultGroup(t *testing.T) {
	setupRegistrationGroupControllerTest(t)
	require.NoError(t, setting.ApplyRegistrationGroupConfiguration("free", ratio_setting.GetGroupRatioCopy()))

	recorder := performCreateUserRequest(t, `{"username":"admin-created","password":"password-1234","role":1}`)
	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Contains(t, recorder.Body.String(), `"success":true`)

	var created model.User
	require.NoError(t, model.DB.First(&created, "username = ?", "admin-created").Error)
	assert.Equal(t, "default", created.Group, "admin-created accounts must not use the self-registration group")
}

func TestExistingUserGroupIsNotMigratedWhenConfigurationChanges(t *testing.T) {
	setupRegistrationGroupControllerTest(t)
	existing := model.User{
		Username: "existing-member", Password: "password-1234", Role: common.RoleCommonUser,
		Status: common.UserStatusEnabled, Group: "default", AuthVersion: 1, AffCode: "existing-aff",
	}
	require.NoError(t, model.DB.Create(&existing).Error)

	require.NoError(t, setting.ApplyRegistrationGroupConfiguration("free", ratio_setting.GetGroupRatioCopy()))

	var reloaded model.User
	require.NoError(t, model.DB.First(&reloaded, existing.Id).Error)
	assert.Equal(t, "default", reloaded.Group)
}

func TestRegisterFailsClosedWithoutLeakingGroupConfiguration(t *testing.T) {
	setupRegistrationGroupControllerTest(t)
	require.NoError(t, model.DB.Create(&model.Option{Key: "GroupRatio", Value: `{"default":1}`}).Error)
	setting.ApplyInvalidRegistrationGroupConfiguration("secret-group", map[string]float64{"default": 1}, nil)

	createRegistrationInviter(t, "blocked-inviter", "blocked-valid-invite")
	recorder := performRegisterRequest(t, `{"username":"blocked","password":"password-1234","aff_code":"blocked-valid-invite"}`)
	require.Equal(t, http.StatusOK, recorder.Code)
	assert.Contains(t, recorder.Body.String(), `"success":false`)
	message := i18n.T(nil, i18n.MsgUserRegisterFailed)
	assert.Contains(t, recorder.Body.String(), message)
	assert.NotContains(t, recorder.Body.String(), "secret-group")
	assert.NotContains(t, recorder.Body.String(), "registration group")

	var count int64
	require.NoError(t, model.DB.Model(&model.User{}).Where("username = ?", "blocked").Count(&count).Error)
	assert.Zero(t, count)
}
