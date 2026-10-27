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

import { api } from '@/lib/api'

import type {
  ApiResponse,
  OAuthConsentContext,
  OAuthConsentRedirect,
} from './types'

// Fetch the pending authorization request (client + requested scopes) that the
// opaque request token refers to. The token is validated server-side.
export async function getOAuthConsentContext(
  request: string
): Promise<ApiResponse<OAuthConsentContext>> {
  const res = await api.get('/api/oauth-server/authorize/context', {
    params: { request },
  })
  return res.data
}

// Approve the pending request: the server issues an authorization code and
// returns the exact redirect target (an external client URL).
export async function approveOAuthConsent(
  request: string
): Promise<ApiResponse<OAuthConsentRedirect>> {
  const res = await api.post('/api/oauth-server/authorize/approve', { request })
  return res.data
}

// Deny the pending request: the server returns the redirect target carrying an
// access_denied error for the client.
export async function denyOAuthConsent(
  request: string
): Promise<ApiResponse<OAuthConsentRedirect>> {
  const res = await api.post('/api/oauth-server/authorize/deny', { request })
  return res.data
}
