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
	"sync"
	"time"

	"github.com/QuantumNous/new-api/common"
)

// Per-(channel, model) first-byte latency tracker for weighted routing. Each
// streaming success updates an EWMA of the time-to-first-byte for the pair and
// a per-model aggregate across all channels. While both sides have enough
// samples, ChannelLatencyWeight returns a multiplier below 1 for pairs that are
// slower than the model's average, so the weighted random walk inside a
// priority tier prefers faster channels instead of treating every candidate
// equally. It never boosts above 1 and never excludes: an unlucky pair keeps a
// floor share of traffic, and pairs without enough data are untouched.
//
// The tracker is fed with the requested (origin) model name so channel
// selection can look the weight up directly.

type channelLatencyKey struct {
	channelId int
	model     string
}

type channelLatencyState struct {
	ewmaMs     float64
	samples    int
	lastUpdate int64 // unix seconds
}

var (
	channelLatencyStatesMu sync.Mutex
	channelLatencyStates   = make(map[channelLatencyKey]*channelLatencyState)
	modelLatencyStates     = make(map[string]*channelLatencyState)
)

// Test seam for recency; production always uses wall-clock time.
var channelLatencyClock = func() int64 { return time.Now().Unix() }

const (
	channelLatencyJanitorTTL int64   = 1800
	channelLatencyEWMAAlpha          = 0.3
	channelLatencyMinSamples int     = 3
	modelLatencyMinSamples   int     = 10
	channelLatencyMinWeight  float64 = 0.1
)

func init() {
	go cleanupChannelLatencyStates()
}

func cleanupChannelLatencyStates() {
	for range time.Tick(10 * time.Minute) {
		now := channelLatencyClock()
		channelLatencyStatesMu.Lock()
		for key, state := range channelLatencyStates {
			if now-state.lastUpdate > channelLatencyJanitorTTL {
				delete(channelLatencyStates, key)
			}
		}
		for model, state := range modelLatencyStates {
			if now-state.lastUpdate > channelLatencyJanitorTTL {
				delete(modelLatencyStates, model)
			}
		}
		channelLatencyStatesMu.Unlock()
	}
}

// updateEWMA must be called with channelLatencyStatesMu held.
func updateEWMA(state *channelLatencyState, ttftMs float64) {
	if state.samples == 0 {
		state.ewmaMs = ttftMs
	} else {
		state.ewmaMs += channelLatencyEWMAAlpha * (ttftMs - state.ewmaMs)
	}
	state.samples++
	state.lastUpdate = channelLatencyClock()
}

// RecordChannelTtft feeds one measured streaming time-to-first-byte into the
// pair's EWMA and the model-wide aggregate.
func RecordChannelTtft(channelId int, modelName string, ttft time.Duration) {
	if channelId <= 0 || modelName == "" || !common.ChannelLatencyWeightingEnabled || ttft <= 0 {
		return
	}
	ttftMs := float64(ttft.Milliseconds())
	channelLatencyStatesMu.Lock()
	defer channelLatencyStatesMu.Unlock()
	key := channelLatencyKey{channelId: channelId, model: modelName}
	state := channelLatencyStates[key]
	if state == nil {
		state = &channelLatencyState{}
		channelLatencyStates[key] = state
	}
	updateEWMA(state, ttftMs)
	aggregate := modelLatencyStates[modelName]
	if aggregate == nil {
		aggregate = &channelLatencyState{}
		modelLatencyStates[modelName] = aggregate
	}
	updateEWMA(aggregate, ttftMs)
}

// ChannelLatencyWeight returns the selection weight multiplier for the pair:
// 1.0 when weighting is disabled or there is not enough data yet, otherwise
// clamp(modelAverage / channelAverage, channelLatencyMinWeight, 1) so slower
// than average pairs are demoted without ever being excluded.
func ChannelLatencyWeight(channelId int, modelName string) float64 {
	if channelId <= 0 || modelName == "" || !common.ChannelLatencyWeightingEnabled {
		return 1
	}
	channelLatencyStatesMu.Lock()
	defer channelLatencyStatesMu.Unlock()
	channelState := channelLatencyStates[channelLatencyKey{channelId: channelId, model: modelName}]
	modelState := modelLatencyStates[modelName]
	if channelState == nil || modelState == nil ||
		channelState.samples < channelLatencyMinSamples || modelState.samples < modelLatencyMinSamples ||
		channelState.ewmaMs <= 0 || modelState.ewmaMs <= 0 {
		return 1
	}
	weight := modelState.ewmaMs / channelState.ewmaMs
	if weight > 1 {
		return 1
	}
	return max(weight, channelLatencyMinWeight)
}
