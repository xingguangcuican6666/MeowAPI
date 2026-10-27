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
	"fmt"
	"slices"
	"sync"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/setting"
	"github.com/QuantumNous/new-api/setting/ratio_setting"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

var registrationGroupOptionKeys = []string{
	setting.DefaultRegistrationGroupOptionKey,
	"GroupRatio",
}

var registrationGroupOptionMutationMu sync.Mutex

func isRegistrationGroupOption(key string) bool {
	return slices.Contains(registrationGroupOptionKeys, key)
}

func defaultRegistrationGroupOptions() map[string]string {
	return map[string]string{
		setting.DefaultRegistrationGroupOptionKey: setting.DefaultRegistrationGroup,
		"GroupRatio": ratio_setting.GroupRatio2JSONString(),
	}
}

func registrationGroupPairFromOptions(options []*Option) map[string]string {
	values := defaultRegistrationGroupOptions()
	for _, option := range options {
		if isRegistrationGroupOption(option.Key) {
			values[option.Key] = option.Value
		}
	}
	return values
}

func parseRegistrationGroupOptions(values map[string]string) (map[string]float64, error) {
	if err := ratio_setting.CheckGroupRatio(values["GroupRatio"]); err != nil {
		return nil, err
	}
	groups, err := ratio_setting.ParseGroupRatioJSONString(values["GroupRatio"])
	if err != nil {
		return nil, err
	}
	if err := setting.ValidateRegistrationGroup(values[setting.DefaultRegistrationGroupOptionKey], groups); err != nil {
		return nil, err
	}
	return groups, nil
}

func applyRegistrationGroupOptions(values map[string]string, allowInvalid bool) error {
	groups, err := ratio_setting.ParseGroupRatioJSONString(values["GroupRatio"])
	if err != nil {
		groups = ratio_setting.GetGroupRatioCopy()
		if allowInvalid {
			setting.ApplyInvalidRegistrationGroupConfiguration(values[setting.DefaultRegistrationGroupOptionKey], groups, err)
			setRegistrationGroupOptionMap(values)
		}
		return err
	}
	if validationErr := setting.ValidateRegistrationGroup(values[setting.DefaultRegistrationGroupOptionKey], groups); validationErr != nil {
		if allowInvalid {
			if updateErr := ratio_setting.UpdateGroupRatioByJSONString(values["GroupRatio"]); updateErr != nil {
				return updateErr
			}
			setting.ApplyInvalidRegistrationGroupConfiguration(values[setting.DefaultRegistrationGroupOptionKey], groups, validationErr)
			setRegistrationGroupOptionMap(values)
		}
		return validationErr
	}
	if err := ratio_setting.UpdateGroupRatioByJSONString(values["GroupRatio"]); err != nil {
		return err
	}
	if err := setting.ApplyRegistrationGroupConfiguration(values[setting.DefaultRegistrationGroupOptionKey], groups); err != nil {
		return err
	}
	setRegistrationGroupOptionMap(values)
	return nil
}

func setRegistrationGroupOptionMap(values map[string]string) {
	common.OptionMapRWMutex.Lock()
	for _, key := range registrationGroupOptionKeys {
		common.OptionMap[key] = values[key]
	}
	common.OptionMapRWMutex.Unlock()
}

func loadRegistrationGroupOptions(options []*Option) {
	values := registrationGroupPairFromOptions(options)
	if err := applyRegistrationGroupOptions(values, true); err != nil {
		common.SysError("invalid registration group configuration: " + err.Error())
	}
}

func readRegistrationGroupOptions(db *gorm.DB) (map[string]string, error) {
	var rows []Option
	if err := db.Where(commonKeyCol+" IN ?", registrationGroupOptionKeys).Find(&rows).Error; err != nil {
		return nil, err
	}
	values := defaultRegistrationGroupOptions()
	for _, row := range rows {
		values[row.Key] = row.Value
	}
	return values, nil
}

func updateRegistrationGroupOptions(updates map[string]string) error {
	registrationGroupOptionMutationMu.Lock()
	defer registrationGroupOptionMutationMu.Unlock()
	for key, value := range updates {
		if err := validateOptionValue(key, value); err != nil {
			return err
		}
	}

	var committed map[string]string
	err := DB.Transaction(func(tx *gorm.DB) error {
		defaults := defaultRegistrationGroupOptions()
		for _, key := range registrationGroupOptionKeys {
			row := Option{Key: key, Value: defaults[key]}
			if err := tx.Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error; err != nil {
				return err
			}
		}
		values, err := readRegistrationGroupOptions(lockForUpdate(tx))
		if err != nil {
			return err
		}
		for key, value := range updates {
			if isRegistrationGroupOption(key) {
				values[key] = value
			}
		}
		if _, err := parseRegistrationGroupOptions(values); err != nil {
			return err
		}
		for _, key := range registrationGroupOptionKeys {
			if err := tx.Model(&Option{}).Where(commonKeyCol+" = ?", key).Update("value", values[key]).Error; err != nil {
				return err
			}
		}
		// MySQL reports zero affected rows when a value is rewritten unchanged, so
		// confirm the paired options by reading them back rather than relying on
		// dialect-dependent RowsAffected.
		stored, err := readRegistrationGroupOptions(tx)
		if err != nil {
			return err
		}
		for _, key := range registrationGroupOptionKeys {
			if stored[key] != values[key] {
				return fmt.Errorf("failed to update option %s", key)
			}
		}
		for key, value := range updates {
			if isRegistrationGroupOption(key) {
				continue
			}
			option := Option{Key: key}
			if err := tx.FirstOrCreate(&option, Option{Key: key}).Error; err != nil {
				return err
			}
			option.Value = value
			if err := tx.Save(&option).Error; err != nil {
				return err
			}
		}
		committed = values
		return nil
	})
	if err != nil {
		return err
	}
	return applyRegistrationGroupOptions(committed, false)
}
