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

package service

import (
	"fmt"
	"time"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"
)

// Delayed bans are armed by an administrator from the user management page
// (e.g. "email_invalid": the account email does not pass the configured
// format policy). The account keeps working during the grace period so the
// user can fix the problem; a background pass lifts the pending ban as soon
// as the fix condition holds, and disables the account once the deadline
// passes without a fix. Custom (non email_invalid) reasons have no machine
// checkable fix condition, so they resolve only through the admin clear
// action or expire into a full ban.

// pendingBanEnforceInterval is how often expired pending bans are enforced.
const pendingBanEnforceInterval = time.Minute

func StartPendingBanEnforcement() {
	go func() {
		ticker := time.NewTicker(pendingBanEnforceInterval)
		defer ticker.Stop()
		for range ticker.C {
			EnforcePendingBans()
		}
	}()
}

// EnforcePendingBans runs one enforcement pass: it lifts pending bans whose
// fix condition now holds and bans the accounts whose deadline passed.
func EnforcePendingBans() {
	users, err := model.GetPendingBanUsers()
	if err != nil {
		common.SysError(fmt.Sprintf("pending ban scan failed: %v", err))
		return
	}
	now := time.Now().Unix()
	for _, user := range users {
		if user.Role == common.RoleRootUser {
			// A root user must never be auto-banned by the scanner; the
			// controller refuses to arm a pending ban on root in the first
			// place, so this only defends against legacy rows.
			_ = model.ClearUserPendingBan(user.Id)
			continue
		}
		if pendingBanResolved(user) {
			if err := model.ClearUserPendingBan(user.Id); err != nil {
				common.SysError(fmt.Sprintf("failed to lift pending ban for user #%d: %v", user.Id, err))
				continue
			}
			model.RecordLog(user.Id, model.LogTypeSystem, "整改事项已完成，延迟封禁已自动解除")
			continue
		}
		if now < user.PendingBanDeadline {
			continue
		}
		banOverduePendingBanUser(user)
	}
}

// pendingBanResolved reports whether the pending ban's fix condition holds.
func pendingBanResolved(user model.User) bool {
	if user.PendingBanReason != model.PendingBanReasonEmailInvalid {
		return false
	}
	_, err := ValidateAccountEmail(user.Email)
	return err == nil
}

func banOverduePendingBanUser(user model.User) {
	target := model.User{Id: user.Id, Status: common.UserStatusDisabled}
	if err := target.Update(false); err != nil {
		common.SysError(fmt.Sprintf("failed to ban overdue pending-ban user #%d: %v", user.Id, err))
		return
	}
	if err := model.ClearUserPendingBan(user.Id); err != nil {
		common.SysError(fmt.Sprintf("failed to clear pending ban fields for banned user #%d: %v", user.Id, err))
	}
	if err := model.InvalidateUserTokensCache(user.Id); err != nil {
		common.SysLog(fmt.Sprintf("failed to invalidate tokens cache for banned user #%d: %v", user.Id, err))
	}
	model.RecordLog(user.Id, model.LogTypeSystem, fmt.Sprintf("逾期未完成整改（%s），账号已被封禁", user.PendingBanReason))
	common.SysLog(fmt.Sprintf("pending ban enforced: user #%d (%s) banned, reason=%s", user.Id, user.Username, user.PendingBanReason))
}
