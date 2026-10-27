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
	"fmt"

	"github.com/QuantumNous/new-api/common"

	"gorm.io/gorm"
)

// deprecatedIPRateLimitOptionKey was the first WebUI-exposed name for what
// NginxMode now represents. The enforcement code never saw it: the option
// dispatcher only routed boolean keys ending in "Enabled" and this key ends in
// "Disabled", so the toggle was stored, shown as on, and applied to nothing.
const deprecatedIPRateLimitOptionKey = "RateLimitByIPDisabled"

// MigrateRenamedIPRateLimitOption carries the abandoned option onto NginxMode.
//
// Only an explicit "true" is carried forward. Such a row can exist only because
// a root operator asked for IP-keyed limiting to stop, and the old UI told them
// it had; dropping it would re-block a deployment that is working around a
// shared Docker NAT address. "false" already matches the default, and anything
// else was never parseable, so both are discarded rather than guessed at. An
// existing NginxMode row wins either way: it was written by code that acts on
// it. Deleting the legacy row makes repeated runs no-ops and keeps GetOptions
// from feeding a key nothing reads back to the WebUI.
func MigrateRenamedIPRateLimitOption() error {
	if DB == nil {
		return nil
	}
	return DB.Transaction(func(tx *gorm.DB) error {
		var legacy Option
		err := tx.Where(&Option{Key: deprecatedIPRateLimitOptionKey}).First(&legacy).Error
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("read legacy option %s: %w", deprecatedIPRateLimitOptionKey, err)
		}

		if legacy.Value == "true" {
			var current Option
			err := tx.Where(&Option{Key: "NginxMode"}).First(&current).Error
			switch {
			case err == nil:
				common.SysLog(fmt.Sprintf("retiring option %s: NginxMode is already stored as %q",
					deprecatedIPRateLimitOptionKey, current.Value))
			case errors.Is(err, gorm.ErrRecordNotFound):
				if err := tx.Create(&Option{Key: "NginxMode", Value: "true"}).Error; err != nil {
					return fmt.Errorf("enable NginxMode from %s: %w", deprecatedIPRateLimitOptionKey, err)
				}
				common.SysLog(fmt.Sprintf(
					"option %s moved to NginxMode: IP-keyed rate limiting is off, address limiting is now the reverse proxy's job",
					deprecatedIPRateLimitOptionKey,
				))
			default:
				return fmt.Errorf("read option NginxMode: %w", err)
			}
		} else {
			common.SysLog(fmt.Sprintf("retiring option %s=%q: that toggle was never enforced",
				deprecatedIPRateLimitOptionKey, legacy.Value))
		}

		if err := tx.Delete(&legacy).Error; err != nil {
			return fmt.Errorf("delete legacy option %s: %w", deprecatedIPRateLimitOptionKey, err)
		}
		return nil
	})
}
