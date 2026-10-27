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

	"github.com/QuantumNous/new-api/common"
)

func setupChannelCooldownTest(t *testing.T) *int64 {
	t.Helper()
	channelCooldownStatesMu.Lock()
	channelCooldownStates = make(map[channelModelKey]*channelModelState)
	channelCooldownStatesMu.Unlock()
	now := int64(1_000_000)
	channelCooldownClock = func() int64 { return now }
	common.ChannelCooldownFailureThreshold = 5
	common.ChannelCooldownBaseSeconds = 30
	common.ChannelCooldownMaxSeconds = 1800
	common.ChannelSlowFirstByteSeconds = 120
	common.ChannelModelMissingCooldownSeconds = 3600
	t.Cleanup(func() {
		channelCooldownStatesMu.Lock()
		channelCooldownStates = make(map[channelModelKey]*channelModelState)
		channelCooldownStatesMu.Unlock()
		channelCooldownClock = func() int64 { return time.Now().Unix() }
	})
	return &now
}

func TestChannelCooldownArmsAfterConsecutiveFailures(t *testing.T) {
	now := setupChannelCooldownTest(t)

	// Below the threshold nothing is skipped.
	for i := 0; i < 4; i++ {
		RecordChannelAttemptOutcome(42, "gpt-4o", true)
	}
	assert.False(t, ChannelInErrorCooldown(42, "gpt-4o"))

	// The fifth consecutive failure arms the base 30s skip.
	RecordChannelAttemptOutcome(42, "gpt-4o", true)
	assert.True(t, ChannelInErrorCooldown(42, "gpt-4o"))
	assert.Equal(t, []int{42}, CooldownExcludedChannelIds("gpt-4o"))

	// The skip expires on its own without changing any channel state.
	*now += 31
	assert.False(t, ChannelInErrorCooldown(42, "gpt-4o"))
	assert.Empty(t, CooldownExcludedChannelIds("gpt-4o"))
}

func TestChannelCooldownEscalatesWithStreak(t *testing.T) {
	now := setupChannelCooldownTest(t)

	for i := 0; i < 5; i++ {
		RecordChannelAttemptOutcome(42, "gpt-4o", true)
	}
	*now += 31
	// Streak 6 doubles the skip to 60s.
	RecordChannelAttemptOutcome(42, "gpt-4o", true)
	*now += 31
	assert.True(t, ChannelInErrorCooldown(42, "gpt-4o"), "streak 6 must skip for 60s")
	*now += 30
	assert.False(t, ChannelInErrorCooldown(42, "gpt-4o"))

	// Repeated failures keep re-arming the skip as the streak escalates, and
	// even the longest (capped) cooldown expires on its own.
	for i := 0; i < 30; i++ {
		RecordChannelAttemptOutcome(43, "gpt-4o", true)
		*now += 1
		if i >= 4 {
			require.True(t, ChannelInErrorCooldown(43, "gpt-4o"), "a failing channel must stay skipped")
		}
	}
	*now += 1801
	assert.False(t, ChannelInErrorCooldown(43, "gpt-4o"))
	assert.Equal(t, 1800*time.Second, channelCooldownDuration(100, false))
}

func TestChannelCooldownResetsOnSuccess(t *testing.T) {
	setupChannelCooldownTest(t)

	for i := 0; i < 5; i++ {
		RecordChannelAttemptOutcome(42, "gpt-4o", true)
	}
	require.True(t, ChannelInErrorCooldown(42, "gpt-4o"))

	// A success clears an active skip and the streak.
	RecordChannelAttemptOutcome(42, "gpt-4o", false)
	assert.False(t, ChannelInErrorCooldown(42, "gpt-4o"))
	for i := 0; i < 4; i++ {
		RecordChannelAttemptOutcome(42, "gpt-4o", true)
	}
	assert.False(t, ChannelInErrorCooldown(42, "gpt-4o"), "the streak must restart after a success")

	RecordChannelAttemptOutcome(42, "gpt-4o", true)
	assert.True(t, ChannelInErrorCooldown(42, "gpt-4o"))
}

func TestChannelSlowFirstByteArmsImmediately(t *testing.T) {
	now := setupChannelCooldownTest(t)

	// A fast stream never trips the breaker.
	RecordChannelAttemptOutcome(42, "gpt-4o", false)
	RecordChannelSlowFirstByte(42, "gpt-4o", 119*time.Second)
	assert.False(t, ChannelInErrorCooldown(42, "gpt-4o"))

	// A single over-limit first byte skips the pair for the base duration,
	// without waiting for the failure threshold.
	RecordChannelSlowFirstByte(42, "gpt-4o", 121*time.Second)
	assert.True(t, ChannelInErrorCooldown(42, "gpt-4o"))
	*now += 31
	assert.False(t, ChannelInErrorCooldown(42, "gpt-4o"))

	// Disabled slow detection (0) never skips.
	common.ChannelSlowFirstByteSeconds = 0
	RecordChannelSlowFirstByte(42, "gpt-4o", 10*time.Minute)
	assert.False(t, ChannelInErrorCooldown(42, "gpt-4o"))
}

func TestChannelCooldownIsolatesModelAndChannel(t *testing.T) {
	setupChannelCooldownTest(t)

	for i := 0; i < 5; i++ {
		RecordChannelAttemptOutcome(42, "gpt-4o", true)
	}
	assert.True(t, ChannelInErrorCooldown(42, "gpt-4o"))
	assert.False(t, ChannelInErrorCooldown(42, "claude-3"), "other models of the same channel stay usable")
	assert.False(t, ChannelInErrorCooldown(43, "gpt-4o"), "other channels stay usable")
	assert.Empty(t, CooldownExcludedChannelIds("claude-3"))
	assert.Equal(t, []int{42}, CooldownExcludedChannelIds("gpt-4o"))
}

func TestChannelModelMissingArmsLongSkip(t *testing.T) {
	now := setupChannelCooldownTest(t)

	// A single miss is not enough evidence to lock the pair out.
	RecordChannelModelMissing(42, "gpt-4o")
	assert.False(t, ChannelInErrorCooldown(42, "gpt-4o"))

	// The second consecutive miss skips the pair for the long duration.
	RecordChannelModelMissing(42, "gpt-4o")
	assert.True(t, ChannelInErrorCooldown(42, "gpt-4o"))
	assert.Equal(t, []int{42}, CooldownExcludedChannelIds("gpt-4o"))

	// The missing skip outlasts even the capped failure cooldown.
	*now += 1801
	assert.True(t, ChannelInErrorCooldown(42, "gpt-4o"))
	*now += 1800
	assert.False(t, ChannelInErrorCooldown(42, "gpt-4o"))

	// Duplicate names in one call count as one miss.
	RecordChannelModelMissing(43, "dup", "dup")
	RecordChannelModelMissing(43, "dup")
	assert.True(t, ChannelInErrorCooldown(43, "dup"))
}

func TestChannelModelMissingClearedBySuccess(t *testing.T) {
	setupChannelCooldownTest(t)

	RecordChannelModelMissing(42, "gpt-4o")
	RecordChannelModelMissing(42, "gpt-4o")
	require.True(t, ChannelInErrorCooldown(42, "gpt-4o"))

	// A success clears a misjudged missing skip and the miss streak.
	RecordChannelAttemptOutcome(42, "gpt-4o", false)
	assert.False(t, ChannelInErrorCooldown(42, "gpt-4o"))
	assert.Empty(t, CooldownExcludedChannelIds("gpt-4o"))
	RecordChannelModelMissing(42, "gpt-4o")
	assert.False(t, ChannelInErrorCooldown(42, "gpt-4o"), "the miss streak must restart after a success")
}

func TestChannelFirstByteStallArmsImmediately(t *testing.T) {
	now := setupChannelCooldownTest(t)

	// A single stall arms the base skip even though the failure streak is 1.
	RecordChannelAttemptOutcome(42, "gpt-4o", true)
	RecordChannelFirstByteStall(42, "gpt-4o")
	assert.True(t, ChannelInErrorCooldown(42, "gpt-4o"))

	// The stall itself did not advance the streak: once the skip expires, the
	// streak (1) is still below the threshold, so a regular failure keeps
	// serving.
	*now += 31
	assert.False(t, ChannelInErrorCooldown(42, "gpt-4o"))
	RecordChannelAttemptOutcome(42, "gpt-4o", true)
	assert.False(t, ChannelInErrorCooldown(42, "gpt-4o"), "a stall must not double-count the streak")
}

func TestChannelCooldownDurationTable(t *testing.T) {
	setupChannelCooldownTest(t)

	// Failures below the threshold never arm a cooldown.
	assert.Zero(t, channelCooldownDuration(1, false))
	assert.Zero(t, channelCooldownDuration(4, false))
	assert.Zero(t, channelCooldownDuration(0, false))

	// From the threshold on, the base doubles per extra bad outcome.
	assert.Equal(t, 30*time.Second, channelCooldownDuration(5, false))
	assert.Equal(t, 60*time.Second, channelCooldownDuration(6, false))
	assert.Equal(t, 120*time.Second, channelCooldownDuration(7, false))

	// A slow first byte arms at least the base, regardless of the streak.
	assert.Equal(t, 30*time.Second, channelCooldownDuration(1, true))
	assert.Equal(t, 30*time.Second, channelCooldownDuration(4, true))
	assert.Equal(t, 30*time.Second, channelCooldownDuration(5, true))
	assert.Equal(t, 60*time.Second, channelCooldownDuration(6, true))

	// Long streaks cap at the configured maximum.
	assert.Equal(t, 1800*time.Second, channelCooldownDuration(100, false))
	assert.Equal(t, 1800*time.Second, channelCooldownDuration(100, true))
}
