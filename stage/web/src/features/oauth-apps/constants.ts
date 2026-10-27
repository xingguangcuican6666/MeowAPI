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

import type { StatusBadgeProps } from '@/components/status-badge'

// ============================================================================
// React Query keys
// ============================================================================

export const OAUTH_CLIENTS_QUERY_KEY = ['oauth-server', 'clients'] as const

// ============================================================================
// OAuth Application Status Configuration
// label values are i18n keys; use t(config.label) in components (e.g. StatusBadge)
// ============================================================================

export const OAUTH_APP_STATUS = {
  ENABLED: 1,
  DISABLED: 2,
} as const

export const OAUTH_APP_STATUSES: Record<
  number,
  Pick<StatusBadgeProps, 'variant'> & {
    label: string
    value: number
  }
> = {
  [OAUTH_APP_STATUS.ENABLED]: {
    label: 'Enabled',
    variant: 'success',
    value: OAUTH_APP_STATUS.ENABLED,
  },
  [OAUTH_APP_STATUS.DISABLED]: {
    label: 'Disabled',
    variant: 'neutral',
    value: OAUTH_APP_STATUS.DISABLED,
  },
} as const

// ============================================================================
// Error Messages (i18n keys: use t(ERROR_MESSAGES.xxx) when displaying)
// ============================================================================

export const ERROR_MESSAGES = {
  UNEXPECTED: 'An unexpected error occurred',
  LOAD_FAILED: 'Failed to load OAuth applications',
  CREATE_FAILED: 'Failed to create OAuth application',
  UPDATE_FAILED: 'Failed to update OAuth application',
  DELETE_FAILED: 'Failed to delete OAuth application',
  ROTATE_FAILED: 'Failed to regenerate client secret',
  SCOPES_LOAD_FAILED: 'Failed to load available scopes',
} as const

// ============================================================================
// Success Messages (i18n keys: use t(SUCCESS_MESSAGES.xxx) when displaying)
// ============================================================================

export const SUCCESS_MESSAGES = {
  OAUTH_APP_CREATED: 'OAuth application created successfully',
  OAUTH_APP_UPDATED: 'OAuth application updated successfully',
  OAUTH_APP_DELETED: 'OAuth application deleted successfully',
  OAUTH_APP_ENABLED: 'OAuth application enabled successfully',
  OAUTH_APP_DISABLED: 'OAuth application disabled successfully',
  SECRET_ROTATED: 'Client secret regenerated successfully',
} as const
