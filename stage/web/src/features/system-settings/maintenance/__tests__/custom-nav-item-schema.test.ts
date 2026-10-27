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
import { describe, expect, it } from 'vitest'

import { CUSTOM_NAV_TITLE_MAX_LENGTH } from '@/lib/nav-modules'

import { getCustomNavItemFormSchema } from '../custom-nav-item-schema'

// Echo the message key (with the one interpolation the schema uses) so each
// assertion can tell which translated message the schema picked.
const echoT = ((key: string, options?: Record<string, unknown>) =>
  key.replace('{{max}}', String(options?.max))) as unknown as TFunction
const schema = getCustomNavItemFormSchema(echoT)

const INTERNAL_MESSAGE =
  'Enter an app path starting with / (for example /pricing) or a valid http(s) URL.'
const URL_MESSAGE = 'Enter a valid http(s) URL.'
const EMPTY_MESSAGE = 'Please enter a link'

type OpenMode = 'internal' | 'iframe' | 'external'

function parseForm(fields: {
  title?: string
  href: string
  openMode: OpenMode
}) {
  return schema.safeParse({
    title: 'Docs',
    requireAuth: false,
    ...fields,
  })
}

describe('custom navigation item form schema', () => {
  it.each([
    ['internal', '/pricing'],
    ['internal', '/console/log?page=2#top'],
    ['internal', 'https://example.com/docs'],
    ['iframe', 'https://example.com/embed'],
    ['iframe', 'http://intranet.example/status'],
    ['external', 'https://example.com'],
    ['external', 'http://example.com/a?b=c'],
  ] as const)('accepts a %s link of %s', (openMode, href) => {
    expect(parseForm({ openMode, href }).success).toBe(true)
  })

  it.each([
    ['internal', 'pricing', INTERNAL_MESSAGE],
    ['internal', '//evil.example/x', INTERNAL_MESSAGE],
    ['internal', '/\\evil.example', INTERNAL_MESSAGE],
    ['internal', '/with space', INTERNAL_MESSAGE],
    ['internal', 'javascript:alert(1)', INTERNAL_MESSAGE],
    ['internal', 'data:text/html,hi', INTERNAL_MESSAGE],
    ['internal', 'ftp://example.com/file', INTERNAL_MESSAGE],
    ['iframe', '/pricing', URL_MESSAGE],
    ['iframe', 'javascript:alert(1)', URL_MESSAGE],
    ['iframe', 'https://user:pw@example.com', URL_MESSAGE],
    ['external', '/pricing', URL_MESSAGE],
    ['external', 'mailto:someone@example.com', URL_MESSAGE],
    ['external', 'example.com', URL_MESSAGE],
    ['external', 'javascript:alert(1)', URL_MESSAGE],
  ] as const)(
    'rejects a %s link of %s on the link field',
    (openMode, href, message) => {
      const result = parseForm({ openMode, href })

      expect(result.success).toBe(false)
      expect(result.error?.issues).toEqual([
        expect.objectContaining({ path: ['href'], message }),
      ])
    }
  )

  it.each(['internal', 'iframe', 'external'] as const)(
    'asks for a link when the %s link is blank',
    (openMode) => {
      const result = parseForm({ openMode, href: '   ' })

      expect(result.error?.issues).toEqual([
        expect.objectContaining({ path: ['href'], message: EMPTY_MESSAGE }),
      ])
    }
  )

  it('judges the same link again when the open mode changes', () => {
    expect(parseForm({ openMode: 'internal', href: '/pricing' }).success).toBe(
      true
    )
    expect(parseForm({ openMode: 'iframe', href: '/pricing' }).success).toBe(
      false
    )
  })

  it('trims the title and the link before saving them', () => {
    const result = parseForm({
      title: '  Status page  ',
      openMode: 'external',
      href: '  https://status.example.com  ',
    })

    expect(result.data).toEqual({
      title: 'Status page',
      href: 'https://status.example.com',
      openMode: 'external',
      requireAuth: false,
    })
  })

  it.each([
    ['empty', '', 'Please enter a title'],
    ['blank', '   ', 'Please enter a title'],
    [
      'too long',
      'x'.repeat(CUSTOM_NAV_TITLE_MAX_LENGTH + 1),
      `Title must be at most ${CUSTOM_NAV_TITLE_MAX_LENGTH} characters`,
    ],
  ])('rejects a %s title', (_name, title, message) => {
    const result = parseForm({
      title,
      openMode: 'external',
      href: 'https://a.io',
    })

    expect(result.error?.issues).toEqual([
      expect.objectContaining({ path: ['title'], message }),
    ])
  })

  it('accepts a title of exactly the maximum length', () => {
    const title = 'x'.repeat(CUSTOM_NAV_TITLE_MAX_LENGTH)

    expect(
      parseForm({ title, openMode: 'external', href: 'https://a.io' }).success
    ).toBe(true)
  })

  it('reports a bad title and a bad link together', () => {
    const result = parseForm({
      title: '',
      openMode: 'external',
      href: 'javascript:alert(1)',
    })

    expect(result.error?.issues.map((issue) => issue.path[0]).sort()).toEqual([
      'href',
      'title',
    ])
  })
})
