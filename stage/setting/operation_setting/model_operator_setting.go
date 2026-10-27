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

package operation_setting

import (
	"fmt"
	"strings"

	"github.com/QuantumNous/new-api/common"
	"github.com/QuantumNous/new-api/setting/config"
)

// ModelOperatorSetting implements the per-model "sole operator" routing rule:
// a model listed in ModelChannelMap must be served by its designated channel,
// and only when that channel is currently unusable (disabled, outside the
// group pool, rejected by request filters, or in cooldown/breaker exclusion)
// does selection fall back to the default routing logic. Models without a
// mapping keep the default behavior untouched.
type ModelOperatorSetting struct {
	Enabled         bool           `json:"enabled"`
	ModelChannelMap map[string]int `json:"model_channel_map"`
}

var modelOperatorSetting = ModelOperatorSetting{
	Enabled:         false,
	ModelChannelMap: map[string]int{},
}

func init() {
	config.GlobalConfig.Register("model_operator_setting", &modelOperatorSetting)
}

func GetModelOperatorSetting() *ModelOperatorSetting {
	return &modelOperatorSetting
}

// OperatorChannelID returns the designated operator channel id for the model,
// or 0 when the setting is disabled or the model has no mapping.
func (s *ModelOperatorSetting) OperatorChannelID(model string) int {
	if s == nil || !s.Enabled {
		return 0
	}
	channelID, ok := s.ModelChannelMap[model]
	if !ok || channelID <= 0 {
		return 0
	}
	return channelID
}

// ModelOperatorMapOptionKey is the options-table key holding the map JSON.
const ModelOperatorMapOptionKey = "model_operator_setting.model_channel_map"

// ValidateModelOperatorMap checks that the stored value decodes into a
// model -> channel id map with non-empty model names and positive channel ids.
func ValidateModelOperatorMap(value string) error {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	channelMap := map[string]int{}
	if err := common.Unmarshal([]byte(value), &channelMap); err != nil {
		return fmt.Errorf("model operator map must be a JSON object of model name to channel id: %w", err)
	}
	for model, channelID := range channelMap {
		if strings.TrimSpace(model) == "" {
			return fmt.Errorf("model operator map has an empty model name")
		}
		if channelID <= 0 {
			return fmt.Errorf("model operator map entry %q has an invalid channel id: %d", model, channelID)
		}
	}
	return nil
}
