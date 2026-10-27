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

import { describe, expect, test } from 'vitest'

import {
  CUSTOM_NAV_MAX_ITEMS,
  isValidCustomNavHref,
  parseCustomNavItems,
  parseHeaderNavModules,
  type CustomNavOpenMode,
} from '../nav-modules'

describe('isValidCustomNavHref', () => {
  test.each<[string, CustomNavOpenMode]>([
    ['https://docs.example.com/guide?a=1#top', 'iframe'],
    ['http://localhost:8080/', 'external'],
    ['HTTPS://Docs.Example.com', 'iframe'],
    ['https://[2001:db8::1]/path', 'external'],
    ['https://example.com/@user', 'iframe'],
    ['/pricing', 'internal'],
    ['/console/log?page=2', 'internal'],
    ['https://example.com', 'internal'],
  ])('accepts %s for %s', (href, openMode) => {
    expect(isValidCustomNavHref(href, openMode)).toBe(true)
  })

  test.each<[string, CustomNavOpenMode]>([
    ['javascript:alert(1)', 'iframe'],
    ['JaVaScRiPt:alert(1)', 'external'],
    ['data:text/html,<script>alert(1)</script>', 'iframe'],
    ['//evil.example', 'internal'],
    ['/\\evil.example', 'internal'],
    ['/pricing', 'iframe'],
    ['/pricing', 'external'],
    ['https://user:pw@example.com', 'iframe'],
    ['https://user@example.com', 'external'],
    ['http:evil.example', 'iframe'],
    ['https:///evil.example', 'iframe'],
    ['https://example.com\\@evil.example', 'external'],
    ['https://exa mple.com', 'iframe'],
    ['https://example.com/\tpath', 'external'],
    ['ftp://example.com', 'external'],
    ['pricing', 'internal'],
    ['', 'internal'],
    ['   ', 'iframe'],
  ])('rejects %j for %s', (href, openMode) => {
    expect(isValidCustomNavHref(href, openMode)).toBe(false)
  })

  test('rejects a link longer than the stored limit', () => {
    const href = `https://example.com/${'a'.repeat(2048)}`

    expect(isValidCustomNavHref(href, 'iframe')).toBe(false)
  })
})

describe('parseCustomNavItems', () => {
  const valid = {
    id: 'docs-1',
    title: 'Docs',
    href: 'https://docs.example.com',
    openMode: 'iframe',
    requireAuth: true,
  }

  test('keeps a complete item and trims its text fields', () => {
    const items = parseCustomNavItems([
      { ...valid, title: '  Docs  ', href: ' https://docs.example.com ' },
    ])

    expect(items).toEqual([valid])
  })

  test('defaults requireAuth to false when it is absent or unreadable', () => {
    const items = parseCustomNavItems([
      { ...valid, id: 'a', requireAuth: undefined },
      { ...valid, id: 'b', requireAuth: 'maybe' },
    ])

    expect(items.map((item) => item.requireAuth)).toEqual([false, false])
  })

  test('drops hostile or incomplete entries and keeps the rest', () => {
    const items = parseCustomNavItems([
      { ...valid, id: 'bad-href', href: 'javascript:alert(1)' },
      { ...valid, id: 'bad mode', openMode: 'popup' },
      { ...valid, id: 'bad/id!' },
      { ...valid, id: 'no-title', title: '   ' },
      { ...valid, id: 'long-title', title: 'x'.repeat(51) },
      null,
      'docs',
      valid,
    ])

    expect(items).toEqual([valid])
  })

  test('keeps only the first of two items sharing an id', () => {
    const items = parseCustomNavItems([
      valid,
      { ...valid, title: 'Impostor', href: 'https://evil.example' },
    ])

    expect(items).toEqual([valid])
  })

  test('stops at the item limit', () => {
    const many = Array.from({ length: CUSTOM_NAV_MAX_ITEMS + 5 }, (_, i) => ({
      ...valid,
      id: `item-${i}`,
    }))

    expect(parseCustomNavItems(many)).toHaveLength(CUSTOM_NAV_MAX_ITEMS)
  })

  test.each([undefined, null, 'docs', 7, { id: 'docs-1' }])(
    'returns no items for a non-array value %j',
    (raw) => {
      expect(parseCustomNavItems(raw)).toEqual([])
    }
  )
})

describe('parseHeaderNavModules customItems', () => {
  test('reads customItems from the stored JSON string', () => {
    const modules = parseHeaderNavModules(
      JSON.stringify({
        docs: false,
        customItems: [
          {
            id: 'docs-1',
            title: 'Docs',
            href: 'https://docs.example.com',
            openMode: 'external',
            requireAuth: false,
          },
        ],
      })
    )

    expect(modules.docs).toBe(false)
    expect(modules.customItems.map((item) => item.id)).toEqual(['docs-1'])
  })

  test('has no custom items for a legacy config without the key', () => {
    const modules = parseHeaderNavModules('{"home":true,"about":false}')

    expect(modules.customItems).toEqual([])
    expect(modules.about).toBe(false)
  })
})
