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

import type { QueryClient } from '@tanstack/react-query'
import { redirect } from '@tanstack/react-router'

import { resolveAuthentication } from '@/lib/auth-session'
import {
  isValidCustomNavHref,
  parseHeaderNavModulesFromStatus,
  type CustomNavItem,
} from '@/lib/nav-modules'
import { statusQueryOptions, type StatusData } from '@/lib/status-query'
import { useAuthStore } from '@/stores/auth-store'

/**
 * Resolve the iframe item a `/custom/$itemId` request refers to, or redirect.
 *
 * Status is awaited through the shared query cache rather than read from it, so
 * a direct open or a refresh (empty cache) resolves the same as an in-app
 * navigation. Fails closed: an unreadable status, an unknown id, an item that
 * is not an iframe item, or an unsafe href all send the visitor home. The
 * backend still authorizes the framed site's own requests.
 *
 * `returnTo` is the in-app path to come back to after signing in; the sign-in
 * route sanitizes it again before following it.
 */
export async function resolveCustomNavItem(
  queryClient: QueryClient,
  itemId: string,
  returnTo: string
): Promise<CustomNavItem> {
  let status: StatusData | null
  try {
    status = await queryClient.fetchQuery(statusQueryOptions)
  } catch {
    throw redirect({ to: '/' })
  }

  const item = parseHeaderNavModulesFromStatus(status).customItems.find(
    (candidate) => candidate.id === itemId
  )
  if (
    !item ||
    item.openMode !== 'iframe' ||
    !isValidCustomNavHref(item.href, 'iframe')
  ) {
    throw redirect({ to: '/' })
  }

  if (item.requireAuth) {
    // The root guard skips its refresh for visitors without a session hint,
    // which is not a verdict. Ask the server before treating them as signed out.
    await resolveAuthentication()
    if (!useAuthStore.getState().auth.user) {
      throw redirect({ to: '/sign-in', search: { redirect: returnTo } })
    }
  }

  return item
}
