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

import type { TFunction } from 'i18next'
import { z } from 'zod'

import { OAUTH_APP_STATUS } from '../constants'
import type { OAuthClient, OAuthClientRequest } from '../types'

// ============================================================================
// URL validation helpers
// ============================================================================

/**
 * A registered redirect URI must be an absolute URI and, per RFC 6749 §3.1.2,
 * must not include a fragment component. Custom (native app) schemes are
 * allowed; the server still enforces an exact match at authorization time.
 */
export function isValidRedirectUri(value: string): boolean {
  const trimmed = value.trim()
  if (!trimmed || trimmed.includes('#')) return false
  try {
    return Boolean(new URL(trimmed).protocol)
  } catch {
    return false
  }
}

/** Logos and homepages are rendered in the UI, so restrict them to http(s). */
export function isHttpUrl(value: string): boolean {
  try {
    const { protocol } = new URL(value.trim())
    return protocol === 'http:' || protocol === 'https:'
  } catch {
    return false
  }
}

// ============================================================================
// Form Schema
// ============================================================================

export function getOAuthClientFormSchema(t: TFunction) {
  return z
    .object({
      name: z.string().trim().min(1, t('Please enter a name')),
      description: z.string(),
      logo: z.string(),
      homepage: z.string(),
      redirect_uris: z
        .array(z.string())
        .min(1, t('Add at least one redirect URI')),
      scopes: z.array(z.string()).min(1, t('Select at least one scope')),
      is_public: z.boolean(),
      // Admin-only; a common user's value is ignored server-side.
      trusted: z.boolean(),
      status: z.number(),
    })
    .superRefine((data, ctx) => {
      if (data.redirect_uris.some((uri) => !isValidRedirectUri(uri))) {
        ctx.addIssue({
          code: 'custom',
          path: ['redirect_uris'],
          message: t(
            'Redirect URIs must be absolute URLs without a fragment (#).'
          ),
        })
      }
      if (data.logo.trim() && !isHttpUrl(data.logo)) {
        ctx.addIssue({
          code: 'custom',
          path: ['logo'],
          message: t('Enter a valid http(s) URL.'),
        })
      }
      if (data.homepage.trim() && !isHttpUrl(data.homepage)) {
        ctx.addIssue({
          code: 'custom',
          path: ['homepage'],
          message: t('Enter a valid http(s) URL.'),
        })
      }
    })
}

export type OAuthClientFormValues = z.infer<
  ReturnType<typeof getOAuthClientFormSchema>
>

// ============================================================================
// Form Defaults & Transforms
// ============================================================================

export const OAUTH_CLIENT_FORM_DEFAULT_VALUES: OAuthClientFormValues = {
  name: '',
  description: '',
  logo: '',
  homepage: '',
  redirect_uris: [],
  scopes: ['openid'],
  is_public: false,
  trusted: false,
  status: OAUTH_APP_STATUS.ENABLED,
}

export function transformFormToPayload(
  data: OAuthClientFormValues
): OAuthClientRequest {
  return {
    name: data.name.trim(),
    description: data.description.trim(),
    logo: data.logo.trim(),
    homepage: data.homepage.trim(),
    redirect_uris: data.redirect_uris.map((uri) => uri.trim()).filter(Boolean),
    scopes: data.scopes,
    is_public: data.is_public,
    trusted: data.trusted,
    status: data.status,
  }
}

export function transformClientToFormDefaults(
  client: OAuthClient
): OAuthClientFormValues {
  return {
    name: client.name,
    description: client.description ?? '',
    logo: client.logo ?? '',
    homepage: client.homepage ?? '',
    redirect_uris: client.redirect_uris ?? [],
    scopes: client.scopes ?? [],
    is_public: client.is_public,
    trusted: client.trusted ?? false,
    status: client.status,
  }
}
