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

import {
  CUSTOM_NAV_TITLE_MAX_LENGTH,
  isValidCustomNavHref,
} from '@/lib/nav-modules'

/** Shape of one saved custom navigation item (mirrors `CustomNavItem`). */
export const customNavItemSchema = z.object({
  id: z.string(),
  title: z.string(),
  href: z.string(),
  openMode: z.enum(['internal', 'iframe', 'external']),
  requireAuth: z.boolean(),
})

/**
 * Add/Edit dialog schema. The link rules depend on the chosen open mode, so
 * they live in one object-level check that reports on the `href` field.
 */
export function getCustomNavItemFormSchema(t: TFunction) {
  return z
    .object({
      title: z
        .string()
        .trim()
        .min(1, t('Please enter a title'))
        .max(
          CUSTOM_NAV_TITLE_MAX_LENGTH,
          t('Title must be at most {{max}} characters', {
            max: CUSTOM_NAV_TITLE_MAX_LENGTH,
          })
        ),
      href: z.string().trim(),
      openMode: customNavItemSchema.shape.openMode,
      requireAuth: z.boolean(),
    })
    .superRefine((data, ctx) => {
      if (isValidCustomNavHref(data.href, data.openMode)) return

      let message = t('Enter a valid http(s) URL.')
      if (data.href === '') {
        message = t('Please enter a link')
      } else if (data.openMode === 'internal') {
        message = t(
          'Enter an app path starting with / (for example /pricing) or a valid http(s) URL.'
        )
      }
      ctx.addIssue({ code: 'custom', path: ['href'], message })
    })
}

export type CustomNavItemFormValues = z.infer<
  ReturnType<typeof getCustomNavItemFormSchema>
>

export const CUSTOM_NAV_ITEM_FORM_DEFAULT_VALUES: CustomNavItemFormValues = {
  title: '',
  href: '',
  openMode: 'internal',
  requireAuth: false,
}
