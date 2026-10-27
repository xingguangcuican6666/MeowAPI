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

// SanitizeUpstreamErrorEnabled hides upstream error text from downstream
// clients. Gateways forward failures verbatim today, so an upstream body —
// which routinely carries provider account identifiers, balance or quota
// figures, internal hostnames and URLs, request IDs of another system, and
// sometimes fragments of the prompt — reaches whoever called the API.
//
// While enabled, the text served to non-admin API callers is replaced by a
// fixed sentence. What is preserved in the response: the HTTP status code, the
// protocol error type, and the error code, so clients can still branch on
// `insufficient_quota`, `rate_limit_exceeded`, `content_policy_violation` and
// friends. Internally the verbatim upstream error is kept everywhere it
// matters: channel auto-disable keyword/status-code matching, retry
// classification, and the error logs all compare against the real error, and
// administrators and root also receive the verbatim error in their own API
// responses.
//
// Errors this service authored itself (invalid request, insufficient quota of
// our own wallet, channel selection failures, rate limiting) keep their
// message, because the client cannot act on those failures otherwise.
//
// Bootstrap default comes from SANITIZE_UPSTREAM_ERROR; the root setting of the
// same name overrides it at runtime. On by default: forwarding upstream error
// bodies verbatim is a disclosure defect, not a feature, and the sanitized
// response still carries the HTTP status, protocol error type and error code so
// clients keep their error handling. Deployments that depend on the verbatim
// text can set SANITIZE_UPSTREAM_ERROR=false or flip the root setting.
var SanitizeUpstreamErrorEnabled = true

func init() {
	SanitizeUpstreamErrorEnabled = common.GetEnvOrDefaultBool("SANITIZE_UPSTREAM_ERROR", true)
}
