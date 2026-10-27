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

package setting

import (
	"errors"
	"fmt"
	"maps"
	"strings"
	"sync/atomic"
	"unicode/utf8"
)

const (
	DefaultRegistrationGroupOptionKey = "DefaultRegistrationGroup"
	DefaultRegistrationGroup          = "default"
	maxUserGroupLength                = 64
)

var ErrRegistrationGroupUnavailable = errors.New("registration group configuration is unavailable")

type registrationGroupSnapshot struct {
	configured string
	groups     map[string]struct{}
	err        error
}

var registrationGroups atomic.Pointer[registrationGroupSnapshot]

func init() {
	ApplyRegistrationGroupConfiguration(DefaultRegistrationGroup, map[string]float64{
		"default": 1,
		"vip":     1,
		"svip":    1,
	})
}

func ValidateRegistrationGroup(name string, groups map[string]float64) error {
	if !utf8.ValidString(name) {
		return fmt.Errorf("%w: group name must be valid UTF-8", ErrRegistrationGroupUnavailable)
	}
	if name == "" || strings.TrimSpace(name) != name {
		return fmt.Errorf("%w: group name must be non-empty without surrounding whitespace", ErrRegistrationGroupUnavailable)
	}
	if name == "auto" {
		return fmt.Errorf("%w: auto is reserved for token routing", ErrRegistrationGroupUnavailable)
	}
	if utf8.RuneCountInString(name) > maxUserGroupLength || len(name) > maxUserGroupLength {
		return fmt.Errorf("%w: group name exceeds %d characters or bytes", ErrRegistrationGroupUnavailable, maxUserGroupLength)
	}
	if _, ok := groups[name]; !ok {
		return fmt.Errorf("%w: group %q is not configured", ErrRegistrationGroupUnavailable, name)
	}
	return nil
}

func ApplyRegistrationGroupConfiguration(configured string, groups map[string]float64) error {
	err := ValidateRegistrationGroup(configured, groups)
	publishRegistrationGroupConfiguration(configured, groups, err)
	return err
}

func ApplyInvalidRegistrationGroupConfiguration(configured string, groups map[string]float64, err error) {
	if err == nil {
		err = ErrRegistrationGroupUnavailable
	}
	publishRegistrationGroupConfiguration(configured, groups, fmt.Errorf("%w: %v", ErrRegistrationGroupUnavailable, err))
}

func publishRegistrationGroupConfiguration(configured string, groups map[string]float64, err error) {
	groupSet := make(map[string]struct{}, len(groups))
	for group := range groups {
		groupSet[group] = struct{}{}
	}
	registrationGroups.Store(&registrationGroupSnapshot{
		configured: configured,
		groups:     groupSet,
		err:        err,
	})
}

func ResolveRegistrationGroup(explicit string) (string, error) {
	snapshot := registrationGroups.Load()
	if snapshot == nil {
		return "", ErrRegistrationGroupUnavailable
	}
	if snapshot.err != nil {
		return "", snapshot.err
	}
	group := explicit
	if group == "" {
		group = snapshot.configured
	}
	if !utf8.ValidString(group) || group == "" || strings.TrimSpace(group) != group || group == "auto" || utf8.RuneCountInString(group) > maxUserGroupLength || len(group) > maxUserGroupLength {
		return "", fmt.Errorf("%w: invalid group name", ErrRegistrationGroupUnavailable)
	}
	if _, ok := snapshot.groups[group]; !ok {
		return "", fmt.Errorf("%w: group %q is not configured", ErrRegistrationGroupUnavailable, group)
	}
	return group, nil
}

// RegistrationGroupConfiguration exposes the currently published registration
// group snapshot so callers can observe, save, and restore the live setting.
func RegistrationGroupConfiguration() (string, map[string]struct{}, error) {
	snapshot := registrationGroups.Load()
	if snapshot == nil {
		return "", nil, ErrRegistrationGroupUnavailable
	}
	return snapshot.configured, maps.Clone(snapshot.groups), snapshot.err
}
