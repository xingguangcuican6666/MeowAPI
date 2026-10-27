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

package perfmetrics

import (
	"sync"
	"sync/atomic"
	"time"
)

// modelLiveStatus tracks per-model request counters and the most recent
// outcome since process start. It backs the model-square card footer
// (success/failure counts, last success time, last first-byte latency) and is
// independent of the perf-metrics bucket persistence.
type modelLiveStatus struct {
	successCount  atomic.Int64
	failureCount  atomic.Int64
	lastSuccessAt atomic.Int64 // unix seconds, 0 = none
	lastRequestAt atomic.Int64 // unix seconds
	lastTtftMs    atomic.Int64 // 0 = unknown / non-stream
}

var modelLiveStatuses sync.Map // model name -> *modelLiveStatus

type ModelLiveStatusSnapshot struct {
	SuccessCount  int64
	FailureCount  int64
	LastSuccessAt int64
	LastRequestAt int64
	LastTtftMs    int64
}

func recordModelLiveStatus(sample Sample) {
	if sample.Model == "" {
		return
	}
	statusAny, _ := modelLiveStatuses.LoadOrStore(sample.Model, &modelLiveStatus{})
	status := statusAny.(*modelLiveStatus)
	now := time.Now().Unix()
	status.lastRequestAt.Store(now)
	if sample.Success {
		status.successCount.Add(1)
		status.lastSuccessAt.Store(now)
	} else {
		status.failureCount.Add(1)
	}
	if sample.HasTtft && sample.TtftMs >= 0 {
		status.lastTtftMs.Store(sample.TtftMs)
	}
}

func modelLiveStatusSnapshot(modelName string) (ModelLiveStatusSnapshot, bool) {
	value, ok := modelLiveStatuses.Load(modelName)
	if !ok {
		return ModelLiveStatusSnapshot{}, false
	}
	status := value.(*modelLiveStatus)
	return ModelLiveStatusSnapshot{
		SuccessCount:  status.successCount.Load(),
		FailureCount:  status.failureCount.Load(),
		LastSuccessAt: status.lastSuccessAt.Load(),
		LastRequestAt: status.lastRequestAt.Load(),
		LastTtftMs:    status.lastTtftMs.Load(),
	}, true
}
