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
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// setupUserChannelBreakerTest isolates the breaker state and replaces the
// clock with a controllable one; it returns a pointer used to advance time.
func setupUserChannelBreakerTest(t *testing.T) *int64 {
	t.Helper()
	userChannelFailuresMu.Lock()
	userChannelFailures = make(map[int]map[int]*userChannelFailureState)
	userChannelFailuresMu.Unlock()
	now := int64(1_000_000)
	userChannelBreakerNow = func() int64 { return now }
	t.Cleanup(func() {
		userChannelFailuresMu.Lock()
		userChannelFailures = make(map[int]map[int]*userChannelFailureState)
		userChannelFailuresMu.Unlock()
		userChannelBreakerNow = func() int64 { return time.Now().Unix() }
	})
	return &now
}

func TestUserChannelBreakerExcludesOnlyAfterThresholdWithinWindow(t *testing.T) {
	now := setupUserChannelBreakerTest(t)

	for i := 0; i < userChannelFailureThreshold; i++ {
		RecordUserChannelFailure(7, 42, "upstream_error", "failure")
		assert.Empty(t, UserExcludedChannelIDs(7), "failures within the threshold must not exclude the channel")
	}
	RecordUserChannelFailure(7, 42, "upstream_error", "sixth failure")
	assert.Equal(t, []int{42}, UserExcludedChannelIDs(7))
	assert.True(t, IsUserChannelExcluded(7, 42))
	assert.False(t, IsUserChannelExcluded(7, 43))
	assert.False(t, IsUserChannelExcluded(8, 42), "the breaker must stay per user")

	// The window bounds the exclusion even without new failures.
	*now += int64(userChannelFailureWindow/time.Second) + 1
	assert.Empty(t, UserExcludedChannelIDs(7))
	assert.False(t, IsUserChannelExcluded(7, 42))
}

func TestUserChannelBreakerSuccessResetsTheStreak(t *testing.T) {
	now := setupUserChannelBreakerTest(t)

	for i := 0; i <= userChannelFailureThreshold; i++ {
		RecordUserChannelFailure(7, 42, "upstream_error", "failure")
	}
	require.Equal(t, []int{42}, UserExcludedChannelIDs(7))

	ResetUserChannelFailures(7, 42)
	assert.Empty(t, UserExcludedChannelIDs(7), "a real success on the channel must clear the streak")

	for i := 0; i <= userChannelFailureThreshold; i++ {
		RecordUserChannelFailure(7, 42, "upstream_error", "failure")
	}
	assert.Equal(t, []int{42}, UserExcludedChannelIDs(7))

	// A fresh success at a later time still clears the whole episode.
	*now += 60
	ResetUserChannelFailures(7, 42)
	RecordUserChannelFailure(7, 42, "upstream_error", "failure")
	assert.Empty(t, UserExcludedChannelIDs(7))
}

func TestUserChannelBreakerWindowOnlyCountsRecentFailures(t *testing.T) {
	now := setupUserChannelBreakerTest(t)

	for i := 0; i < userChannelFailureThreshold; i++ {
		RecordUserChannelFailure(7, 42, "upstream_error", "failure")
	}
	// Continuing the streak after the window: the older failures no longer
	// count as consecutive failures within the window.
	*now += int64(userChannelFailureWindow/time.Second) + 1
	RecordUserChannelFailure(7, 42, "upstream_error", "failure after a quiet window")
	assert.Empty(t, UserExcludedChannelIDs(7))
}

func TestFirstUserChannelFailureKeepsTheEpisodeStart(t *testing.T) {
	now := setupUserChannelBreakerTest(t)

	RecordUserChannelFailure(7, 42, "first_code", "first failure message")
	RecordUserChannelFailure(7, 42, "later_code", "later failure message")
	*now += 30
	RecordUserChannelFailure(7, 43, "other_code", "other channel failure")

	errorCode, message, ok := FirstUserChannelFailure(7)
	require.True(t, ok)
	assert.Equal(t, "first_code", errorCode)
	assert.Equal(t, "first failure message", message)

	ResetUserChannelFailures(7, 42)
	_, _, ok = FirstUserChannelFailure(7)
	require.True(t, ok, "the other channel's episode is still inside the window")

	*now += int64(userChannelFailureWindow/time.Second) + 1
	_, _, ok = FirstUserChannelFailure(7)
	assert.False(t, ok, "expired episodes must not be echoed to the user")
}

func TestUserChannelBreakerIgnoresInvalidIdentifiers(t *testing.T) {
	setupUserChannelBreakerTest(t)

	RecordUserChannelFailure(0, 42, "code", "message")
	RecordUserChannelFailure(7, 0, "code", "message")
	assert.Empty(t, UserExcludedChannelIDs(0))
	assert.Empty(t, UserExcludedChannelIDs(7))
	assert.False(t, IsUserChannelExcluded(7, 42))
	_, _, ok := FirstUserChannelFailure(7)
	assert.False(t, ok)
}
