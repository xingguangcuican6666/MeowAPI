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
	"unicode/utf8"
)

// Per-user channel breaker. When a user's real requests keep failing on one
// channel, later requests from that user skip the channel until the latest
// failure falls outside the window. Only the first upstream attempt of a
// request is recorded: gateway-side retries inside one request are not the
// user's own requests and must not move the counter.
const (
	userChannelFailureThreshold    = 5               // excluded once consecutive failures exceed 5
	userChannelFailureWindow       = 5 * time.Minute // failures older than this no longer count
	userChannelFailureSweepSeconds = 60
	userChannelFailureMessageLimit = 512
)

type userChannelFailureState struct {
	streak         int    // consecutive failures without an intervening success
	firstFailureAt int64  // unix seconds, start of the current streak
	lastFailureAt  int64  // unix seconds
	firstErrorCode string // error code of the first failure in the streak
	firstMessage   string // message of the first failure in the streak
}

var (
	userChannelFailuresMu      sync.Mutex
	userChannelFailures        = make(map[int]map[int]*userChannelFailureState) // userId -> channelId -> state
	userChannelFailuresSweptAt int64
)

// Test seam for window expiry; production code always uses wall-clock time.
var userChannelBreakerNow = func() int64 { return time.Now().Unix() }

func userChannelWindowSeconds() int64 {
	return int64(userChannelFailureWindow / time.Second)
}

// RecordUserChannelFailure bumps the consecutive failure count of one channel
// for one user. A failure that starts after the previous episode went stale
// opens a new streak and becomes the episode's first failure.
func RecordUserChannelFailure(userId, channelId int, errorCode, message string) {
	if userId <= 0 || channelId <= 0 {
		return
	}
	userChannelFailuresMu.Lock()
	defer userChannelFailuresMu.Unlock()
	now := userChannelBreakerNow()
	sweepUserChannelFailuresLocked(now)
	channels := userChannelFailures[userId]
	if channels == nil {
		channels = make(map[int]*userChannelFailureState)
		userChannelFailures[userId] = channels
	}
	state := channels[channelId]
	if state == nil {
		state = &userChannelFailureState{}
		channels[channelId] = state
	}
	if now-state.lastFailureAt > userChannelWindowSeconds() {
		state.streak = 0
	}
	if state.streak == 0 {
		state.firstFailureAt = now
		state.firstErrorCode = errorCode
		state.firstMessage = truncateUserChannelFailureMessage(message)
	}
	state.streak++
	state.lastFailureAt = now
}

// ResetUserChannelFailures clears the breaker state of one channel for one
// user; called when a real request succeeds on that channel.
func ResetUserChannelFailures(userId, channelId int) {
	if userId <= 0 || channelId <= 0 {
		return
	}
	userChannelFailuresMu.Lock()
	defer userChannelFailuresMu.Unlock()
	channels := userChannelFailures[userId]
	if channels == nil {
		return
	}
	delete(channels, channelId)
	if len(channels) == 0 {
		delete(userChannelFailures, userId)
	}
}

// UserExcludedChannelIDs lists the channels the user must skip because their
// consecutive failure streak exceeds the threshold and is still in the window.
func UserExcludedChannelIDs(userId int) []int {
	if userId <= 0 {
		return nil
	}
	userChannelFailuresMu.Lock()
	defer userChannelFailuresMu.Unlock()
	channels := userChannelFailures[userId]
	if len(channels) == 0 {
		return nil
	}
	now := userChannelBreakerNow()
	var excluded []int
	for channelId, state := range channels {
		if userChannelFailureHot(state, now) {
			excluded = append(excluded, channelId)
		}
	}
	return excluded
}

// IsUserChannelExcluded reports whether one channel is currently skipped for
// the user, for callers that check a single candidate channel.
func IsUserChannelExcluded(userId, channelId int) bool {
	if userId <= 0 || channelId <= 0 {
		return false
	}
	userChannelFailuresMu.Lock()
	defer userChannelFailuresMu.Unlock()
	state := userChannelFailures[userId][channelId]
	if state == nil {
		return false
	}
	return userChannelFailureHot(state, userChannelBreakerNow())
}

// FirstUserChannelFailure returns the error code and message of the earliest
// failure still inside the window, so an exhausted-breaker response can echo
// the failure that started the episode.
func FirstUserChannelFailure(userId int) (errorCode, message string, ok bool) {
	if userId <= 0 {
		return "", "", false
	}
	userChannelFailuresMu.Lock()
	defer userChannelFailuresMu.Unlock()
	channels := userChannelFailures[userId]
	if len(channels) == 0 {
		return "", "", false
	}
	now := userChannelBreakerNow()
	var first *userChannelFailureState
	for _, state := range channels {
		if now-state.lastFailureAt >= userChannelWindowSeconds() {
			continue
		}
		if first == nil || state.firstFailureAt < first.firstFailureAt {
			first = state
		}
	}
	if first == nil {
		return "", "", false
	}
	return first.firstErrorCode, first.firstMessage, true
}

func userChannelFailureHot(state *userChannelFailureState, now int64) bool {
	return state.streak > userChannelFailureThreshold && now-state.lastFailureAt < userChannelWindowSeconds()
}

func sweepUserChannelFailuresLocked(now int64) {
	if now-userChannelFailuresSweptAt < userChannelFailureSweepSeconds {
		return
	}
	userChannelFailuresSweptAt = now
	window := userChannelWindowSeconds()
	for userId, channels := range userChannelFailures {
		for channelId, state := range channels {
			if now-state.lastFailureAt >= window {
				delete(channels, channelId)
			}
		}
		if len(channels) == 0 {
			delete(userChannelFailures, userId)
		}
	}
}

func truncateUserChannelFailureMessage(message string) string {
	if len(message) <= userChannelFailureMessageLimit {
		return message
	}
	truncated := message[:userChannelFailureMessageLimit]
	for len(truncated) > 0 && !utf8.ValidString(truncated) {
		truncated = truncated[:len(truncated)-1]
	}
	return truncated
}
