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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
)

func TestSplitTargetsCopiesSettingsPerKey(t *testing.T) {
	priority := int64(10)
	source := &Channel{
		Id:        7,
		Name:      "pool",
		Key:       "sk-aaa\nsk-bbb\n\nsk-ccc",
		Models:    "gpt-4o,claude-3",
		Group:     "default",
		Type:      1,
		Priority:  &priority,
		Status:    common.ChannelStatusEnabled,
		UsedQuota: 12345,
		ChannelInfo: ChannelInfo{
			IsMultiKey:   true,
			MultiKeySize: 3,
			MultiKeyMode: constant.MultiKeyModePolling,
		},
	}
	children := source.SplitTargets()
	require.Len(t, children, 3)

	for i, want := range []string{"sk-aaa", "sk-bbb", "sk-ccc"} {
		child := children[i]
		assert.Equal(t, want, child.Key)
		assert.Equal(t, fmt.Sprintf("pool #%d", i+1), child.Name)
		assert.Zero(t, child.Id, "children must insert as new rows")
		assert.False(t, child.ChannelInfo.IsMultiKey, "children are single-key channels")
		assert.Nil(t, child.Keys)
		assert.Equal(t, "gpt-4o,claude-3", child.Models, "routing settings must be copied")
		assert.Equal(t, "default", child.Group)
		assert.Same(t, &priority, child.Priority, "routing settings must be copied")
		assert.Zero(t, child.UsedQuota, "counters must be reset")
		assert.Empty(t, child.OtherInfo)
		assert.Equal(t, common.ChannelStatusEnabled, child.Status)
	}
}

func TestSplitTargetsDisablesKnownBadKeys(t *testing.T) {
	source := &Channel{
		Id:     7,
		Name:   "pool",
		Key:    "sk-good\nsk-bad",
		Status: common.ChannelStatusEnabled,
		ChannelInfo: ChannelInfo{
			IsMultiKey:         true,
			MultiKeySize:       2,
			MultiKeyStatusList: map[int]int{1: common.ChannelStatusAutoDisabled},
		},
	}
	children := source.SplitTargets()
	require.Len(t, children, 2)
	assert.Equal(t, common.ChannelStatusEnabled, children[0].Status)
	assert.Equal(t, common.ChannelStatusManuallyDisabled, children[1].Status,
		"a disabled key must not start receiving traffic after the split")
}

func TestSplitTargetsInheritsDisabledSource(t *testing.T) {
	source := &Channel{
		Id:          7,
		Name:        "pool",
		Key:         "sk-a\nsk-b",
		Status:      common.ChannelStatusManuallyDisabled,
		ChannelInfo: ChannelInfo{IsMultiKey: true, MultiKeySize: 2},
	}
	children := source.SplitTargets()
	require.Len(t, children, 2)
	for _, child := range children {
		assert.Equal(t, common.ChannelStatusManuallyDisabled, child.Status,
			"splitting must not activate a disabled channel")
	}
}

func TestSplitTargetsRejectsNonSplittableChannels(t *testing.T) {
	single := &Channel{Id: 1, Key: "sk-one", Status: common.ChannelStatusEnabled}
	assert.Nil(t, single.SplitTargets())

	multiOneKey := &Channel{
		Id:          1,
		Key:         "sk-one",
		Status:      common.ChannelStatusEnabled,
		ChannelInfo: ChannelInfo{IsMultiKey: true, MultiKeySize: 1},
	}
	assert.Nil(t, multiOneKey.SplitTargets())
}

func mergeTestChannel(id int, key string) *Channel {
	return &Channel{
		Id:     id,
		Name:   fmt.Sprintf("ch-%d", id),
		Key:    key,
		Type:   1,
		Models: "gpt-4o",
		Group:  "default",
		Status: common.ChannelStatusEnabled,
	}
}

func TestMergeTargetCombinesKeysInOrder(t *testing.T) {
	merged, err := MergeTarget(
		[]*Channel{mergeTestChannel(1, "sk-a"), mergeTestChannel(2, "sk-b"), mergeTestChannel(3, "sk-a")},
		"", "",
	)
	require.NoError(t, err)
	assert.Equal(t, "sk-a\nsk-b", merged.Key, "keys are joined in channel order with duplicates dropped")
	assert.Equal(t, 2, merged.ChannelInfo.MultiKeySize)
	assert.True(t, merged.ChannelInfo.IsMultiKey)
	assert.Equal(t, constant.MultiKeyModePolling, merged.ChannelInfo.MultiKeyMode, "empty mode defaults to polling")
	assert.Equal(t, common.ChannelStatusEnabled, merged.Status)
	assert.Zero(t, merged.Id, "the merged channel inserts as a new row")
	assert.Equal(t, "ch-1", merged.Name, "the first channel name is kept when no name is given")
	assert.Equal(t, "gpt-4o", merged.Models)

	merged, err = MergeTarget(
		[]*Channel{mergeTestChannel(1, "sk-a"), mergeTestChannel(2, "sk-b")},
		"pooled", constant.MultiKeyModeRandom,
	)
	require.NoError(t, err)
	assert.Equal(t, "pooled", merged.Name)
	assert.Equal(t, constant.MultiKeyModeRandom, merged.ChannelInfo.MultiKeyMode)
}

func TestMergeTargetRejectsMismatchedChannels(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Channel)
		label  string
	}{
		{"type", func(c *Channel) { c.Type = 14 }, "类型"},
		{"models", func(c *Channel) { c.Models = "claude-3" }, "模型列表"},
		{"group", func(c *Channel) { c.Group = "vip" }, "分组"},
		{"priority", func(c *Channel) { p := int64(5); c.Priority = &p }, "优先级"},
		{"setting", func(c *Channel) { s := "{}"; c.Setting = &s }, "额外设置"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			other := mergeTestChannel(2, "sk-b")
			testCase.mutate(other)
			_, err := MergeTarget([]*Channel{mergeTestChannel(1, "sk-a"), other}, "", "")
			require.Error(t, err)
			assert.Contains(t, err.Error(), testCase.label)
		})
	}
}

func TestMergeTargetRejectsUnmergeableKeys(t *testing.T) {
	// A key that itself looks like a JSON array would corrupt the joined key
	// string, since GetKeys would re-parse the whole channel key as an array.
	arrayKey := mergeTestChannel(1, "[oops]\nsk-a")
	arrayKey.ChannelInfo = ChannelInfo{IsMultiKey: true}
	_, err := MergeTarget([]*Channel{arrayKey, mergeTestChannel(2, "sk-b")}, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "JSON 数组")

	// Two channels sharing the only key merge down to a single key.
	duplicate := mergeTestChannel(2, "sk-a")
	_, err = MergeTarget([]*Channel{mergeTestChannel(1, "sk-a"), duplicate}, "", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "少于 2 个")
}

func TestMergeTargetRequiresTwoChannels(t *testing.T) {
	_, err := MergeTarget([]*Channel{mergeTestChannel(1, "sk-a")}, "", "")
	require.Error(t, err)
	_, err = MergeTarget(nil, "", "")
	require.Error(t, err)
}

func TestConvertToMultiKeyAppendsDeduplicatedKeys(t *testing.T) {
	channel := &Channel{
		Id:  9,
		Key: "sk-first",
		ChannelInfo: ChannelInfo{
			MultiKeyMode: constant.MultiKeyModePolling,
		},
	}
	require.NoError(t, channel.ConvertToMultiKey(
		[]string{" sk-second ", "sk-first", "", "sk-third"}, constant.MultiKeyModeRandom))

	assert.Equal(t, "sk-first\nsk-second\nsk-third", channel.Key)
	assert.True(t, channel.ChannelInfo.IsMultiKey)
	assert.Equal(t, 3, channel.ChannelInfo.MultiKeySize)
	assert.Equal(t, constant.MultiKeyModeRandom, channel.ChannelInfo.MultiKeyMode)
	assert.Nil(t, channel.Keys)
}

func TestConvertToMultiKeyRejectsInvalidConversions(t *testing.T) {
	multiKey := &Channel{
		Key: "sk-a\nsk-b",
		ChannelInfo: ChannelInfo{
			IsMultiKey:   true,
			MultiKeySize: 2,
		},
	}
	require.Error(t, multiKey.ConvertToMultiKey([]string{"sk-c"}, constant.MultiKeyModePolling))

	jsonKey := &Channel{Key: `[{"access_token":"x"}]`}
	require.Error(t, jsonKey.ConvertToMultiKey([]string{"sk-b"}, constant.MultiKeyModePolling))

	// Only the original key survives deduplication: nothing new to convert.
	single := &Channel{Key: "sk-only"}
	require.Error(t, single.ConvertToMultiKey([]string{"sk-only", " "}, constant.MultiKeyModePolling))
}
