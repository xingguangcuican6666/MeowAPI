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

import { describe, expect, it } from 'vitest'

import { CUSTOM_NAV_MAX_ITEMS } from '@/lib/nav-modules'

import {
  HEADER_NAV_DEFAULT,
  parseHeaderNavModules,
  serializeHeaderNavModules,
} from '../config'

const validItem = {
  id: 'custom-ok',
  title: 'Docs',
  href: 'https://example.com',
  openMode: 'external',
  requireAuth: false,
}

const legacyConfig = {
  home: true,
  console: false,
  pricing: { enabled: false, requireAuth: true },
  rankings: true,
  docs: 'false',
  about: 1,
}

describe('header navigation config parsing', () => {
  it('keeps the module flags of a legacy config and adds an empty custom list', () => {
    const parsed = parseHeaderNavModules(JSON.stringify(legacyConfig))

    expect(parsed).toEqual({
      home: true,
      console: false,
      pricing: { enabled: false, requireAuth: true },
      rankings: { enabled: true, requireAuth: false },
      docs: false,
      about: true,
      customItems: [],
    })
  })

  it('passes unknown modules through as booleans', () => {
    const parsed = parseHeaderNavModules(JSON.stringify({ future: '1' }))

    expect(parsed.future).toBe(true)
    expect(JSON.parse(serializeHeaderNavModules(parsed)).future).toBe(true)
  })

  it.each([
    ['an empty string', ''],
    ['undefined', undefined],
    ['invalid JSON', 'not json'],
  ])('falls back to the defaults for %s', (_name, stored) => {
    expect(parseHeaderNavModules(stored)).toEqual(HEADER_NAV_DEFAULT)
  })

  it('hands out a fresh default list so callers cannot mutate the defaults', () => {
    const parsed = parseHeaderNavModules('not json')
    parsed.customItems.push({ ...validItem, openMode: 'external' })

    expect(HEADER_NAV_DEFAULT.customItems).toEqual([])
    expect(parseHeaderNavModules(undefined).customItems).toEqual([])
  })

  it('reads a valid custom item of each open mode', () => {
    const items = [
      { ...validItem, id: 'custom-a', openMode: 'internal', href: '/pricing' },
      { ...validItem, id: 'custom-b', openMode: 'iframe', requireAuth: true },
      { ...validItem, id: 'custom-c', openMode: 'external' },
    ]

    const parsed = parseHeaderNavModules(JSON.stringify({ customItems: items }))

    expect(parsed.customItems).toEqual(items)
  })

  it.each([
    ['a javascript: link', { ...validItem, href: 'javascript:alert(1)' }],
    [
      'a data: page in an iframe',
      {
        ...validItem,
        openMode: 'iframe',
        href: 'data:text/html,<script>alert(1)</script>',
      },
    ],
    [
      'a protocol-relative internal link',
      { ...validItem, openMode: 'internal', href: '//evil.example/x' },
    ],
    [
      'a link carrying credentials',
      { ...validItem, href: 'https://user:secret@example.com' },
    ],
    ['an id with a space', { ...validItem, id: 'has space' }],
    ['an id that is too long', { ...validItem, id: 'a'.repeat(65) }],
    ['a blank title', { ...validItem, title: '   ' }],
    ['a title that is too long', { ...validItem, title: 'x'.repeat(51) }],
    ['an unknown open mode', { ...validItem, openMode: 'popup' }],
    ['a null entry', null],
    ['a string entry', 'javascript:alert(1)'],
  ])('drops %s', (_name, entry) => {
    const parsed = parseHeaderNavModules(
      JSON.stringify({ customItems: [entry, validItem] })
    )

    expect(parsed.customItems).toEqual([validItem])
  })

  it('keeps the first of two items that share an id', () => {
    const parsed = parseHeaderNavModules(
      JSON.stringify({
        customItems: [validItem, { ...validItem, title: 'Impostor' }],
      })
    )

    expect(parsed.customItems).toEqual([validItem])
  })

  it('ignores a custom list that is not an array', () => {
    const parsed = parseHeaderNavModules(
      JSON.stringify({ customItems: { 0: validItem } })
    )

    expect(parsed.customItems).toEqual([])
  })

  it('reads at most the maximum number of custom items', () => {
    const items = Array.from({ length: CUSTOM_NAV_MAX_ITEMS + 5 }, (_, n) => ({
      ...validItem,
      id: `custom-${n}`,
    }))

    const parsed = parseHeaderNavModules(JSON.stringify({ customItems: items }))

    expect(parsed.customItems).toEqual(items.slice(0, CUSTOM_NAV_MAX_ITEMS))
  })
})

describe('header navigation config serialization', () => {
  it('writes an empty custom list for a legacy config and round-trips it', () => {
    const parsed = parseHeaderNavModules(JSON.stringify(legacyConfig))

    const serialized = serializeHeaderNavModules(parsed)

    expect(JSON.parse(serialized)).toEqual({
      home: true,
      console: false,
      pricing: { enabled: false, requireAuth: true },
      rankings: { enabled: true, requireAuth: false },
      docs: false,
      about: true,
      customItems: [],
    })
    expect(parseHeaderNavModules(serialized)).toEqual(parsed)
    expect(serializeHeaderNavModules(parseHeaderNavModules(serialized))).toBe(
      serialized
    )
  })

  it('round-trips custom items without reordering them', () => {
    const items = [
      { ...validItem, id: 'custom-a', openMode: 'iframe', requireAuth: true },
      { ...validItem, id: 'custom-b' },
    ]
    const parsed = parseHeaderNavModules(JSON.stringify({ customItems: items }))

    const reparsed = parseHeaderNavModules(serializeHeaderNavModules(parsed))

    expect(reparsed.customItems).toEqual(items)
  })

  it('never persists an unsafe item that was built in memory', () => {
    const config = {
      ...HEADER_NAV_DEFAULT,
      customItems: [
        {
          id: 'custom-evil',
          title: 'Evil',
          href: 'javascript:alert(1)',
          openMode: 'external' as const,
          requireAuth: false,
        },
        { ...validItem, openMode: 'external' as const },
      ],
    }

    const stored = JSON.parse(serializeHeaderNavModules(config))

    expect(stored.customItems).toEqual([validItem])
  })
})
