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
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
)

// Per-(channel, model) cooldown breaker. Every real upstream attempt (retries
// included) feeds its outcome into the (channel, model) pair it used — when a
// channel's model mapping resolves one requested name to an ordered queue of
// upstream models, that is the upstream model the attempt actually used, so
// each mapped model cools down independently; after
// common.ChannelCooldownFailureThreshold consecutive bad outcomes the pair is
// skipped for an escalating cooldown that starts at
// common.ChannelCooldownBaseSeconds and doubles per extra bad outcome up to
// common.ChannelCooldownMaxSeconds. A measured streaming first-byte latency
// above common.ChannelSlowFirstByteSeconds is a bad outcome too and arms the
// base cooldown immediately, even below the failure threshold. Any successful
// attempt resets the streak and clears the cooldown. The channel status itself
// is never changed — the skip is advisory and expires on its own.
//
// Model-missing errors (upstream 404 model_not_found and equivalents) are
// deterministic for the pair, so after channelModelMissingThreshold of them in
// a row the pair is skipped for the much longer
// common.ChannelModelMissingCooldownSeconds instead of the escalating failure
// cooldown, keeping requests away from a model the channel no longer serves
// without disabling the channel. A success clears it, so a misjudged pair
// recovers on its next attempt.
//
// Stale entries are dropped by a background janitor so the map cannot grow
// with retired channel/model combinations.

type channelModelKey struct {
	channelId int
	model     string
}

type channelModelState struct {
	badStreak     int
	lastBadAt     int64 // unix seconds
	cooldownUntil int64 // unix seconds
	missingStreak int
	missingUntil  int64 // unix seconds
}

var (
	channelCooldownStatesMu sync.Mutex
	channelCooldownStates   = make(map[channelModelKey]*channelModelState)
)

// Test seam for cooldown expiry; production always uses wall-clock time.
var channelCooldownClock = func() int64 { return time.Now().Unix() }

// channelCooldownJanitorTTL is how long a quiet, uncooled entry survives.
const channelCooldownJanitorTTL int64 = 1800

func init() {
	go cleanupChannelCooldownStates()
}

func cleanupChannelCooldownStates() {
	for range time.Tick(10 * time.Minute) {
		now := channelCooldownClock()
		channelCooldownStatesMu.Lock()
		for key, state := range channelCooldownStates {
			if now >= state.cooldownUntil && now >= state.missingUntil && now-state.lastBadAt > channelCooldownJanitorTTL {
				delete(channelCooldownStates, key)
			}
		}
		channelCooldownStatesMu.Unlock()
	}
}

// RecordChannelAttemptOutcome feeds one real upstream attempt outcome into the
// (channel, model) cooldown breaker.
func RecordChannelAttemptOutcome(channelId int, modelName string, failed bool) {
	if channelId <= 0 {
		return
	}
	if failed {
		recordChannelBadOutcome(channelId, modelName, false)
		return
	}
	resetChannelCooldown(channelId, modelName)
}

// RecordChannelSlowFirstByte arms the cooldown when a measured streaming
// first-byte latency exceeds common.ChannelSlowFirstByteSeconds; slow bytes
// count toward the same escalation streak as failures and arm the base
// cooldown immediately, without waiting for the failure threshold.
func RecordChannelSlowFirstByte(channelId int, modelName string, ttft time.Duration) {
	limit := common.ChannelSlowFirstByteSeconds
	if channelId <= 0 || limit <= 0 || ttft <= time.Duration(limit)*time.Second {
		return
	}
	recordChannelBadOutcome(channelId, modelName, true)
}

func recordChannelBadOutcome(channelId int, modelName string, immediate bool) {
	channelCooldownStatesMu.Lock()
	defer channelCooldownStatesMu.Unlock()
	key := channelModelKey{channelId: channelId, model: modelName}
	state := channelCooldownStates[key]
	if state == nil {
		state = &channelModelState{}
		channelCooldownStates[key] = state
	}
	state.badStreak++
	now := channelCooldownClock()
	if cooldown := channelCooldownDuration(state.badStreak, immediate); cooldown > 0 {
		state.cooldownUntil = now + int64(cooldown.Seconds())
	}
	state.lastBadAt = now
}

// channelCooldownDuration returns the cooldown owed by a streak of bad
// outcomes. Failures only arm it once the streak reaches the threshold;
// immediate (slow first byte) never arms less than the base. The shift is
// clamped so long streaks cannot overflow the duration.
func channelCooldownDuration(streak int, immediate bool) time.Duration {
	base := time.Duration(common.ChannelCooldownBaseSeconds) * time.Second
	if base <= 0 {
		return 0
	}
	if !immediate && streak < common.ChannelCooldownFailureThreshold {
		return 0
	}
	shift := max(streak-common.ChannelCooldownFailureThreshold, 0)
	if shift > 16 {
		shift = 16
	}
	duration := base << uint(shift)
	if max := time.Duration(common.ChannelCooldownMaxSeconds) * time.Second; max > 0 && duration > max {
		duration = max
	}
	return duration
}

func resetChannelCooldown(channelId int, modelName string) {
	channelCooldownStatesMu.Lock()
	defer channelCooldownStatesMu.Unlock()
	state := channelCooldownStates[channelModelKey{channelId: channelId, model: modelName}]
	if state == nil {
		return
	}
	state.badStreak = 0
	state.cooldownUntil = 0
	state.missingStreak = 0
	state.missingUntil = 0
}

// RecordChannelFirstByteStall arms the base cooldown immediately after an
// attempt hit the first-byte deadline without producing any data. The failure
// streak is already counted by RecordChannelAttemptOutcome, so this only moves
// the cooldown forward — a hung upstream must not absorb more requests while
// the streak is still below the failure threshold.
func RecordChannelFirstByteStall(channelId int, modelName string) {
	if channelId <= 0 {
		return
	}
	channelCooldownStatesMu.Lock()
	defer channelCooldownStatesMu.Unlock()
	key := channelModelKey{channelId: channelId, model: modelName}
	state := channelCooldownStates[key]
	if state == nil {
		state = &channelModelState{}
		channelCooldownStates[key] = state
	}
	now := channelCooldownClock()
	if base := time.Duration(common.ChannelCooldownBaseSeconds) * time.Second; base > 0 {
		if until := now + int64(base.Seconds()); until > state.cooldownUntil {
			state.cooldownUntil = until
		}
	}
	state.lastBadAt = now
}

// channelModelMissingThreshold is how many consecutive model-missing errors
// arm the long per-model skip; two keep a single false positive from locking a
// serving pair out for an hour.
const channelModelMissingThreshold = 2

// RecordChannelModelMissing feeds a model-missing upstream error (404
// model_not_found and equivalents) into the (channel, model) pairs. Once a
// pair accumulates channelModelMissingThreshold consecutive misses it is
// skipped for common.ChannelModelMissingCooldownSeconds. Attempts are keyed by
// the upstream model actually used; callers pass additional keys (e.g. the
// origin model of a single-entry mapping) when selection-time exclusion should
// cover them too.
func RecordChannelModelMissing(channelId int, modelNames ...string) {
	if channelId <= 0 {
		return
	}
	seen := make(map[string]struct{}, len(modelNames))
	channelCooldownStatesMu.Lock()
	defer channelCooldownStatesMu.Unlock()
	now := channelCooldownClock()
	for _, modelName := range modelNames {
		if modelName == "" {
			continue
		}
		if _, dup := seen[modelName]; dup {
			continue
		}
		seen[modelName] = struct{}{}
		key := channelModelKey{channelId: channelId, model: modelName}
		state := channelCooldownStates[key]
		if state == nil {
			state = &channelModelState{}
			channelCooldownStates[key] = state
		}
		state.missingStreak++
		state.lastBadAt = now
		if state.missingStreak < channelModelMissingThreshold {
			continue
		}
		if cooldown := time.Duration(common.ChannelModelMissingCooldownSeconds) * time.Second; cooldown > 0 {
			if until := now + int64(cooldown.Seconds()); until > state.missingUntil {
				state.missingUntil = until
			}
		}
	}
}

// ChannelInErrorCooldown reports whether the channel is temporarily skipped
// for the given model, either by the failure cooldown or the long
// model-missing skip.
func ChannelInErrorCooldown(channelId int, modelName string) bool {
	if channelId <= 0 {
		return false
	}
	channelCooldownStatesMu.Lock()
	defer channelCooldownStatesMu.Unlock()
	state := channelCooldownStates[channelModelKey{channelId: channelId, model: modelName}]
	if state == nil {
		return false
	}
	now := channelCooldownClock()
	return now < state.cooldownUntil || now < state.missingUntil
}

// CooldownExcludedChannelIds lists the channels currently skipped for the
// given model by the cooldown breaker.
func CooldownExcludedChannelIds(modelName string) []int {
	channelCooldownStatesMu.Lock()
	defer channelCooldownStatesMu.Unlock()
	now := channelCooldownClock()
	var excluded []int
	for key, state := range channelCooldownStates {
		if key.model == modelName && (now < state.cooldownUntil || now < state.missingUntil) {
			excluded = append(excluded, key.channelId)
		}
	}
	return excluded
}
