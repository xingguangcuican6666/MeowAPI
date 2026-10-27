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

package setting

import "github.com/QuantumNous/new-api/common"

// UpstreamPrivacyProtectionEnabled hides upstream channel details — the model
// mapping result — from end users. Gateways normally record which upstream
// model actually served a mapped request (`is_model_mapped` /
// `upstream_model_name` in the consume log's other JSON, and
// `properties.upstream_model_name` on task records), and that mapping reveals
// which provider and upstream model sit behind a public model name.
//
// While enabled, those fields are stripped from every user-visible projection:
// self/token usage logs and the user's task list and task fetch responses.
// Administrators lose nothing: the dashboard "all logs" / "all tasks" views
// keep showing the mapping, and the stored log rows are untouched, so turning
// the toggle off restores user visibility immediately.
//
// Bootstrap default comes from UPSTREAM_PRIVACY_PROTECTION; the root setting
// of the same name overrides it at runtime. Off by default so no existing
// deployment hides information users previously saw.
var UpstreamPrivacyProtectionEnabled = false

func init() {
	UpstreamPrivacyProtectionEnabled = common.GetEnvOrDefaultBool("UPSTREAM_PRIVACY_PROTECTION", false)
}
