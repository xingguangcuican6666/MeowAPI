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
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/model"

	"gorm.io/gorm"
	"gorm.io/gorm/clause"
)

// Node link merge sync. The child's local rows are imported into the master
// database through the tunnel before the child switches over. The merge is
// additive: rows are re-keyed to avoid collisions and identity conflicts are
// resolved in the master's favour, so nothing already on the master is
// modified or deleted. High-volume telemetry tables (logs, quota data, top-ups,
// redemptions) are intentionally not merged.

type NodeLinkMergeReport struct {
	OptionsInserted int64 `json:"options_inserted"`
	ChannelsAdded   int64 `json:"channels_added"`
	UsersAdded      int64 `json:"users_added"`
	UsersSkipped    int64 `json:"users_skipped"`
	TokensAdded     int64 `json:"tokens_added"`
	TokensSkipped   int64 `json:"tokens_skipped"`
}

type nodeLinkIDMap struct {
	channels map[int]int
	users    map[int]int
}

func mergeLocalDatabaseInto(masterDB *gorm.DB) (*NodeLinkMergeReport, error) {
	report := &NodeLinkMergeReport{}

	var masterMaxChannel, masterMaxUser int64
	if err := masterDB.Model(&model.Channel{}).Select("COALESCE(MAX(id),0)").Scan(&masterMaxChannel).Error; err != nil {
		return nil, err
	}
	if err := masterDB.Model(&model.User{}).Select("COALESCE(MAX(id),0)").Scan(&masterMaxUser).Error; err != nil {
		return nil, err
	}
	ids := &nodeLinkIDMap{
		channels: map[int]int{},
		users:    map[int]int{},
	}
	nextChannelID := &masterMaxChannel
	nextUserID := &masterMaxUser

	if err := mergeNodeLinkOptions(masterDB); err != nil {
		return nil, err
	}
	if err := mergeNodeLinkChannels(masterDB, ids, nextChannelID, report); err != nil {
		return nil, err
	}
	if err := mergeNodeLinkUsers(masterDB, ids, nextUserID, report); err != nil {
		return nil, err
	}
	if err := mergeNodeLinkTokens(masterDB, ids, report); err != nil {
		return nil, err
	}
	return report, nil
}

func mergeNodeLinkOptions(masterDB *gorm.DB) error {
	var localOptions []*model.Option
	if err := model.DB.Find(&localOptions).Error; err != nil {
		return err
	}
	masterKeys := map[string]bool{}
	var masterOptions []*model.Option
	if err := masterDB.Find(&masterOptions).Error; err != nil {
		return err
	}
	for _, option := range masterOptions {
		masterKeys[option.Key] = true
	}
	for _, option := range localOptions {
		if masterKeys[option.Key] {
			continue // master wins on conflicts
		}
		row := model.Option{Key: option.Key, Value: option.Value}
		if err := masterDB.Clauses(clause.OnConflict{DoNothing: true}).Create(&row).Error; err != nil {
			return fmt.Errorf("合并配置 %s 失败: %w", option.Key, err)
		}
	}
	return nil
}

func mergeNodeLinkChannels(masterDB *gorm.DB, ids *nodeLinkIDMap, nextChannelID *int64, report *NodeLinkMergeReport) error {
	var localChannels []*model.Channel
	if err := model.DB.Find(&localChannels).Error; err != nil {
		return err
	}
	for _, channel := range localChannels {
		newID := *nextChannelID + 1
		*nextChannelID = newID
		ids.channels[channel.Id] = int(newID)

		imported := *channel
		imported.Id = int(newID)
		imported.CreatedTime = common.GetTimestamp()
		if err := masterDB.Create(&imported).Error; err != nil {
			return fmt.Errorf("合并渠道 %d 失败: %w", channel.Id, err)
		}
		if err := imported.AddAbilities(masterDB); err != nil {
			return fmt.Errorf("合并渠道 %d 能力失败: %w", channel.Id, err)
		}
		report.ChannelsAdded++
	}
	return nil
}

func localUserIdentityTaken(masterDB *gorm.DB, username, email string) (bool, error) {
	var count int64
	query := masterDB.Model(&model.User{})
	if username != "" && email != "" {
		if err := query.Where("LOWER(username) = ? OR LOWER(email) = ?", strings.ToLower(username), strings.ToLower(email)).Count(&count).Error; err != nil {
			return false, err
		}
	} else if username != "" {
		if err := query.Where("LOWER(username) = ?", strings.ToLower(username)).Count(&count).Error; err != nil {
			return false, err
		}
	} else if email != "" {
		if err := query.Where("LOWER(email) = ?", strings.ToLower(email)).Count(&count).Error; err != nil {
			return false, err
		}
	}
	return count > 0, nil
}

func mergeNodeLinkUsers(masterDB *gorm.DB, ids *nodeLinkIDMap, nextUserID *int64, report *NodeLinkMergeReport) error {
	var localUsers []*model.User
	if err := model.DB.Find(&localUsers).Error; err != nil {
		return err
	}
	for _, user := range localUsers {
		taken, err := localUserIdentityTaken(masterDB, user.Username, user.Email)
		if err != nil {
			return err
		}
		if taken {
			report.UsersSkipped++
			continue
		}
		newID := *nextUserID + 1
		*nextUserID = newID
		ids.users[user.Id] = int(newID)

		imported := *user
		imported.Id = int(newID)
		imported.AffCode = "" // re-assigned below; unique index forbids duplicates
		if err := masterDB.Create(&imported).Error; err != nil {
			return fmt.Errorf("合并用户 %s 失败: %w", user.Username, err)
		}
		if imported.AffCode == "" {
			newAff := common.GetRandomString(4)
			if err := masterDB.Model(&model.User{}).Where("id = ?", newID).Update("aff_code", newAff).Error; err != nil {
				return err
			}
		}
		report.UsersAdded++
	}
	return nil
}

func mergeNodeLinkTokens(masterDB *gorm.DB, ids *nodeLinkIDMap, report *NodeLinkMergeReport) error {
	// The tunnel handle speaks the master's dialect, which may differ from
	// the child's; `key` is a reserved word on both with different quoting.
	keyCol := "`key`"
	if masterDB.Dialector.Name() == "postgres" {
		keyCol = `"key"`
	}
	var localTokens []*model.Token
	if err := model.DB.Find(&localTokens).Error; err != nil {
		return err
	}
	for _, token := range localTokens {
		newUserID, ok := ids.users[token.UserId]
		if !ok {
			report.TokensSkipped++
			continue // owner user conflicted and stayed on the child
		}
		var keyCount int64
		if err := masterDB.Model(&model.Token{}).Where(keyCol+" = ?", token.Key).Count(&keyCount).Error; err != nil {
			return err
		}
		if keyCount > 0 {
			report.TokensSkipped++
			continue
		}
		imported := *token
		imported.Id = 0
		imported.UserId = newUserID
		if err := masterDB.Create(&imported).Error; err != nil {
			return fmt.Errorf("合并令牌 %d 失败: %w", token.Id, err)
		}
		report.TokensAdded++
	}
	return nil
}
