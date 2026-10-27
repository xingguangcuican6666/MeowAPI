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
	"errors"
	"fmt"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/constant"
)

// SplitTargets returns one single-key channel per key of a multi-key channel,
// copying every routing, billing and override setting. The returned channels
// are not persisted; they carry Id 0 so GORM inserts them as new rows. A key
// that was disabled on the source multi-key channel lands as a disabled child
// so known-bad keys do not start receiving traffic. It returns nil when the
// channel is not multi-key or holds at most one key.
func (channel *Channel) SplitTargets() []Channel {
	if !channel.ChannelInfo.IsMultiKey {
		return nil
	}
	keys := channel.GetKeys()
	if len(keys) <= 1 {
		return nil
	}
	children := make([]Channel, 0, len(keys))
	for i, key := range keys {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		child := *channel
		child.Id = 0
		child.Key = key
		child.Name = fmt.Sprintf("%s #%d", channel.Name, len(children)+1)
		child.ChannelInfo = ChannelInfo{}
		child.Keys = nil
		child.CreatedTime = common.GetTimestamp()
		child.TestTime = 0
		child.ResponseTime = 0
		child.Balance = 0
		child.BalanceUpdatedTime = 0
		child.UsedQuota = 0
		child.OtherInfo = ""
		child.Status = channel.Status
		if child.Status == common.ChannelStatusEnabled {
			if keyStatus, ok := channel.ChannelInfo.MultiKeyStatusList[i]; ok && keyStatus != common.ChannelStatusEnabled {
				child.Status = common.ChannelStatusManuallyDisabled
			}
		}
		children = append(children, child)
	}
	return children
}

// MergeTarget validates that the given channels can be combined into one
// multi-key channel and builds it (not persisted). All channels must agree on
// type, endpoint, models, group and every override; keys are collected in
// channel order with duplicates dropped. It returns an error describing the
// first blocking difference.
func MergeTarget(channels []*Channel, name string, mode constant.MultiKeyMode) (*Channel, error) {
	if len(channels) < 2 {
		return nil, errors.New("合并至少需要选择两个渠道")
	}
	for _, channel := range channels {
		if channel == nil {
			return nil, errors.New("渠道不存在")
		}
	}
	first := channels[0]
	for _, other := range channels[1:] {
		if field := mergeMismatchLabel(first, other); field != "" {
			return nil, fmt.Errorf("渠道 #%d 与渠道 #%d 的「%s」不一致，无法合并", first.Id, other.Id, field)
		}
	}
	keys := make([]string, 0, len(channels))
	seen := make(map[string]struct{})
	for _, channel := range channels {
		for _, key := range channel.GetKeys() {
			key = strings.TrimSpace(key)
			if key == "" {
				continue
			}
			if strings.HasPrefix(key, "[") {
				return nil, fmt.Errorf("渠道 #%d 的密钥是 JSON 数组格式，无法直接合并；请先将其拆分为单密钥渠道", channel.Id)
			}
			if _, duplicate := seen[key]; duplicate {
				continue
			}
			seen[key] = struct{}{}
			keys = append(keys, key)
		}
	}
	if len(keys) < 2 {
		return nil, errors.New("合并后的密钥数量少于 2 个，无需合并为多密钥渠道")
	}
	if mode != constant.MultiKeyModeRandom && mode != constant.MultiKeyModePolling {
		mode = constant.MultiKeyModePolling
	}
	merged := *first
	merged.Id = 0
	merged.Key = strings.Join(keys, "\n")
	if name = strings.TrimSpace(name); name != "" {
		merged.Name = name
	}
	merged.ChannelInfo = ChannelInfo{
		IsMultiKey:   true,
		MultiKeySize: len(keys),
		MultiKeyMode: mode,
	}
	merged.Keys = nil
	merged.Status = common.ChannelStatusEnabled
	merged.CreatedTime = common.GetTimestamp()
	merged.TestTime = 0
	merged.ResponseTime = 0
	merged.Balance = 0
	merged.BalanceUpdatedTime = 0
	merged.UsedQuota = 0
	merged.OtherInfo = ""
	return &merged, nil
}

// ConvertToMultiKey turns a single-key channel into a multi-key channel by
// appending the given keys after its current key, deduplicated. It rejects
// channels that are already multi-key and keys in JSON-array format, matching
// the merge restrictions. The mutation is not persisted; callers save the
// channel themselves.
func (channel *Channel) ConvertToMultiKey(extraKeys []string, mode constant.MultiKeyMode) error {
	if channel.ChannelInfo.IsMultiKey {
		return errors.New("渠道已是多密钥渠道")
	}
	keys := make([]string, 0, len(extraKeys)+1)
	seen := make(map[string]struct{})
	for _, key := range append([]string{channel.Key}, extraKeys...) {
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		if strings.HasPrefix(key, "[") {
			return errors.New("密钥是 JSON 数组格式，无法转换为多密钥渠道；请先拆分为单密钥渠道")
		}
		if _, duplicate := seen[key]; duplicate {
			continue
		}
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	if len(keys) < 2 {
		return errors.New("转换后的密钥数量少于 2 个，无需转换为多密钥渠道")
	}
	if mode != constant.MultiKeyModeRandom && mode != constant.MultiKeyModePolling {
		mode = constant.MultiKeyModePolling
	}
	channel.Key = strings.Join(keys, "\n")
	channel.ChannelInfo = ChannelInfo{
		IsMultiKey:   true,
		MultiKeySize: len(keys),
		MultiKeyMode: mode,
	}
	channel.Keys = nil
	return nil
}

// mergeMismatchLabel compares every field that changes upstream behavior and
// returns a human-readable label for the first field the two channels differ
// on, or "" when they are compatible for merging.
func mergeMismatchLabel(first *Channel, other *Channel) string {
	if first.Type != other.Type {
		return "类型"
	}
	if !sameTrimmedString(first.BaseURL, other.BaseURL) {
		return "代理地址"
	}
	if first.Models != other.Models {
		return "模型列表"
	}
	if first.Group != other.Group {
		return "分组"
	}
	if first.Other != other.Other {
		return "其他参数"
	}
	if !sameTrimmedString(first.ModelMapping, other.ModelMapping) {
		return "模型映射"
	}
	if !sameTrimmedString(first.Setting, other.Setting) {
		return "额外设置"
	}
	if !sameTrimmedString(first.ParamOverride, other.ParamOverride) {
		return "参数覆盖"
	}
	if !sameTrimmedString(first.HeaderOverride, other.HeaderOverride) {
		return "请求头覆盖"
	}
	if !sameTrimmedString(first.StatusCodeMapping, other.StatusCodeMapping) {
		return "状态码映射"
	}
	if first.OtherSettings != other.OtherSettings {
		return "其他设置"
	}
	if !sameTrimmedString(first.OpenAIOrganization, other.OpenAIOrganization) {
		return "OpenAI 组织"
	}
	if !sameTrimmedString(first.TestModel, other.TestModel) {
		return "测试模型"
	}
	if !sameTrimmedString(first.Tag, other.Tag) {
		return "标签"
	}
	if !samePointerValue(first.AutoBan, other.AutoBan) {
		return "自动禁用"
	}
	if !samePointerValue(first.Priority, other.Priority) {
		return "优先级"
	}
	if !samePointerValue(first.Weight, other.Weight) {
		return "权重"
	}
	return ""
}

func sameTrimmedString(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return strings.TrimSpace(*a) == strings.TrimSpace(*b)
}

func samePointerValue[T comparable](a, b *T) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}
