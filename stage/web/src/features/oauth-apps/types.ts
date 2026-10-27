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

import { z } from 'zod'

// ============================================================================
// OAuth Client (application) Schema & Types
//
// These describe third-party applications registered against new-api's built-in
// OAuth 2.0 / OpenID Connect authorization server. Distinct from the OAuth
// *client* login providers that let users sign in to new-api.
// ============================================================================

export const oauthClientSchema = z.object({
  id: z.number(),
  client_id: z.string(),
  name: z.string(),
  description: z.string().nullish().default(''),
  logo: z.string().nullish().default(''),
  homepage: z.string().nullish().default(''),
  redirect_uris: z.array(z.string()).nullish().default([]),
  scopes: z.array(z.string()).nullish().default([]),
  is_public: z.boolean(),
  // Admin-vetted flag gating the sensitive scopes (wallet.topup, apikeys.manage).
  trusted: z.boolean().nullish().default(false),
  status: z.number(), // 1: enabled, 2: disabled
  owner_user_id: z.number(),
  created_at: z.number(),
  updated_at: z.number(),
})

export type OAuthClient = z.infer<typeof oauthClientSchema>

// A scope offered by the authorization server, as returned by GET /scopes.
export interface OAuthScope {
  name: string
  title: string
  description: string
  oidc: boolean
  // Sensitive scopes grant a privileged action and require a Trusted client.
  sensitive: boolean
}

// ============================================================================
// API Request/Response Types
// ============================================================================

export interface ApiResponse<T = unknown> {
  success: boolean
  message?: string
  data?: T
}

// Payload sent to create/update a client (omits id/client_id/secret).
export interface OAuthClientRequest {
  name: string
  description: string
  logo: string
  homepage: string
  redirect_uris: string[]
  scopes: string[]
  is_public: boolean
  // Only honored for admin/root callers; ignored server-side otherwise.
  trusted: boolean
  status: number
}

// Create and rotate-secret return the client together with the plaintext
// secret exactly once. The secret is empty ("") for public clients.
export interface OAuthClientSecretResponse {
  client: OAuthClient
  secret: string
}

// ============================================================================
// Dialog Types
// ============================================================================

export type OAuthAppsDialogType =
  | 'create'
  | 'update'
  | 'delete'
  | 'rotate'
  | 'secret'
