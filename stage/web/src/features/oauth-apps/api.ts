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
  OAuthClient,
  OAuthClientRequest,
  OAuthClientSecretResponse,
  OAuthScope,
} from './types'

// ============================================================================
// OAuth Application (client) Management — admin only (RootAuth on the server).
// ============================================================================

// List all registered OAuth clients (returns a plain, unpaginated array).
export async function getOAuthClients(): Promise<ApiResponse<OAuthClient[]>> {
  const res = await api.get('/api/oauth-server/clients')
  return res.data
}

// Get a single OAuth client by its numeric id.
export async function getOAuthClient(
  id: number
): Promise<ApiResponse<OAuthClient>> {
  const res = await api.get(`/api/oauth-server/clients/${id}`)
  return res.data
}

// Create a new OAuth client. The plaintext secret is returned exactly once
// (empty for public clients).
export async function createOAuthClient(
  data: OAuthClientRequest
): Promise<ApiResponse<OAuthClientSecretResponse>> {
  const res = await api.post('/api/oauth-server/clients', data)
  return res.data
}

// Update an existing OAuth client. The stored secret is preserved.
export async function updateOAuthClient(
  id: number,
  data: OAuthClientRequest
): Promise<ApiResponse<OAuthClient>> {
  const res = await api.put(`/api/oauth-server/clients/${id}`, data)
  return res.data
}

// Delete an OAuth client (cascades its tokens and user grants on the server).
export async function deleteOAuthClient(id: number): Promise<ApiResponse> {
  const res = await api.delete(`/api/oauth-server/clients/${id}`)
  return res.data
}

// Regenerate a confidential client's secret, invalidating the previous one.
// The new plaintext secret is returned exactly once.
export async function rotateOAuthClientSecret(
  id: number
): Promise<ApiResponse<OAuthClientSecretResponse>> {
  const res = await api.post(`/api/oauth-server/clients/${id}/rotate-secret`)
  return res.data
}

// List the scopes the authorization server supports.
export async function getOAuthServerScopes(): Promise<
  ApiResponse<OAuthScope[]>
> {
  const res = await api.get('/api/oauth-server/scopes')
  return res.data
}
