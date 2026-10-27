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
	"regexp"
	"strings"
	"sync/atomic"

	"github.com/QuantumNous/new-api/common"
)

// EmailFormatMatches reports whether the email satisfies the administrator's
// custom EmailFormatRegex policy. An empty configuration is a no-op (the
// built-in validator in ValidateAccountEmail still applies); an invalid
// pattern is logged once per value and treated as no constraint so a broken
// configuration cannot lock every account out.
type emailFormatCacheEntry struct {
	raw string
	re  *regexp.Regexp // nil = invalid pattern, no constraint
}

var emailFormatCache atomic.Pointer[emailFormatCacheEntry]

func EmailFormatMatches(email string) bool {
	raw := strings.TrimSpace(common.EmailFormatRegex)
	if raw == "" {
		return true
	}
	entry := emailFormatCache.Load()
	if entry == nil || entry.raw != raw {
		compiled, err := regexp.Compile(raw)
		if err != nil {
			common.SysError(fmt.Sprintf("invalid EmailFormatRegex, ignoring the custom email format policy: %v", err))
			compiled = nil
		}
		entry = &emailFormatCacheEntry{raw: raw, re: compiled}
		emailFormatCache.Store(entry)
	}
	if entry.re == nil {
		return true
	}
	return entry.re.MatchString(email)
}
