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

import { getServerErrorSources } from '@/lib/server-error-message'

/**
 * The stable machine code every banned-account response carries.
 *
 * The backend answers a disabled account with this code on the login, OAuth,
 * WeChat, passkey, secure-verification and session-refresh paths, and the
 * dashboard routes to the account-state page whenever it sees it. Keep the
 * value in sync with `common.AuthErrorCodeUserDisabled` on the Go side.
 */
export const AUTH_USER_DISABLED_CODE = 'AUTH_USER_DISABLED'

/**
 * Public route that explains the account state.
 *
 * A banned user has no valid session, so this path must stay outside the
 * `_authenticated` layout or the guard would bounce back to `/sign-in`.
 */
export const ACCOUNT_SUSPENDED_PATH = '/account-suspended'

/**
 * Whether a failure — raw response payload, `AxiosError`, or anything wrapping
 * one via `cause` — reports the banned-account code.
 *
 * The ban reaches the client through two different statuses: `401` from the
 * dashboard middleware and `403` from the refresh endpoint and the read-only
 * token guard. Matching on the code rather than the status keeps both paths
 * landing on the same explanatory page.
 */
export function hasAccountDisabledCode(value: unknown): boolean {
  return getServerErrorSources(value).some(
    (source) => source.code === AUTH_USER_DISABLED_CODE
  )
}

/**
 * Send the browser to the account-state page.
 *
 * Uses a full navigation instead of the router because the ban is discovered
 * inside the axios interceptor and the refresh runner, both of which run
 * outside any React render. The `pathname` guard makes the call idempotent:
 * a request fired from the account-state page itself must not re-trigger the
 * redirect, which would otherwise loop on every retry.
 *
 * @returns whether a navigation was started.
 */
export function redirectToAccountSuspended(): boolean {
  if (typeof window === 'undefined') return false
  if (window.location.pathname === ACCOUNT_SUSPENDED_PATH) return false
  window.location.replace(ACCOUNT_SUSPENDED_PATH)
  return true
}

/**
 * Hand a failed sign-in, OAuth callback or verification attempt over to the
 * account-state page when — and only when — it was refused because the account
 * is disabled.
 *
 * The page states the verdict, so the caller must not also raise a toast for
 * the same failure: the navigation replaces the document a moment later and the
 * toast would read as a second, contradictory explanation.
 *
 * @returns whether the failure was a ban and the redirect was started.
 */
export function redirectToAccountSuspendedIfBanned(value: unknown): boolean {
  if (!hasAccountDisabledCode(value)) return false
  return redirectToAccountSuspended()
}
