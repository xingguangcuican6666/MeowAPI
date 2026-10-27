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
	"testing"

	"github.com/QuantumNous/new-api/common"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEmailFormatMatches(t *testing.T) {
	original := common.EmailFormatRegex
	t.Cleanup(func() { common.EmailFormatRegex = original })

	// Empty (or blank) configuration applies no extra constraint.
	common.EmailFormatRegex = ""
	assert.True(t, EmailFormatMatches("anything at all"))
	common.EmailFormatRegex = "   "
	assert.True(t, EmailFormatMatches("anything at all"))

	common.EmailFormatRegex = `^[^@]+@example\.com$`
	assert.True(t, EmailFormatMatches("user@example.com"))
	assert.False(t, EmailFormatMatches("user@other.com"))

	// A broken pattern is ignored instead of rejecting everything.
	common.EmailFormatRegex = `[`
	assert.True(t, EmailFormatMatches("user@other.com"))
}

func TestValidateAccountEmailAppliesCustomFormat(t *testing.T) {
	original := common.EmailFormatRegex
	t.Cleanup(func() { common.EmailFormatRegex = original })

	common.EmailFormatRegex = `^[^@]+@example\.com$`
	_, err := ValidateAccountEmail("User@Example.com")
	require.NoError(t, err)
	_, err = ValidateAccountEmail("user@other.com")
	assert.Equal(t, ErrAccountEmailInvalid, err)
}
