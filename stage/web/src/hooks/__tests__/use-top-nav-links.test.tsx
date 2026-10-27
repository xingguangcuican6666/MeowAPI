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

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { cleanup, renderHook } from '@testing-library/react'
import type { ReactNode } from 'react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { STATUS_QUERY_KEY, type StatusData } from '@/lib/status-query'
import { useAuthStore } from '@/stores/auth-store'

import { useTopNavLinks } from '../use-top-nav-links'

beforeEach(() => {
  vi.stubGlobal('localStorage', {
    getItem: () => null,
    setItem: () => undefined,
    removeItem: () => undefined,
  })
})

afterEach(() => {
  cleanup()
  vi.unstubAllGlobals()
  useAuthStore.getState().auth.reset()
})

function linksFor(customItems: unknown[] | undefined, signedIn = false) {
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  const status: StatusData = {
    HeaderNavModules: JSON.stringify({ customItems }),
  }
  client.setQueryData(STATUS_QUERY_KEY, status)
  if (signedIn) {
    useAuthStore.getState().auth.setUser({
      id: 1,
      username: 'alice',
      role: 1,
    })
  }
  function Wrapper(props: { children: ReactNode }) {
    return (
      <QueryClientProvider client={client}>
        {props.children}
      </QueryClientProvider>
    )
  }
  return renderHook(() => useTopNavLinks(), { wrapper: Wrapper }).result.current
}

describe('custom top navigation items', () => {
  it('keeps the built-in links unchanged when no custom item is configured', () => {
    expect(linksFor(undefined).map((link) => link.title)).toEqual([
      'Home',
      'Console',
      'Model Square',
      'Rankings',
      'Docs',
      'About',
    ])
  })

  it('places custom items after Docs and before About in stored order', () => {
    const links = linksFor([
      { id: 'first', title: 'First', href: '/first', openMode: 'internal' },
      {
        id: 'second',
        title: 'Second',
        href: 'https://example.com/second',
        openMode: 'external',
      },
    ])
    expect(links.map((link) => link.title)).toEqual([
      'Home',
      'Console',
      'Model Square',
      'Rankings',
      'Docs',
      'First',
      'Second',
      'About',
    ])
  })

  it('opens an external item in a new tab at its stored URL', () => {
    const links = linksFor([
      {
        id: 'partner',
        title: 'Partner',
        href: 'https://partner.example.com/',
        openMode: 'external',
      },
    ])
    expect(links.find((link) => link.title === 'Partner')).toEqual({
      title: 'Partner',
      href: 'https://partner.example.com/',
      external: true,
      requiresAuth: false,
    })
  })

  it('routes an iframe item by id without carrying its URL in the address', () => {
    const links = linksFor([
      {
        id: 'portal',
        title: 'Portal',
        href: 'https://portal.example.com/app?tab=1',
        openMode: 'iframe',
      },
    ])
    expect(links.find((link) => link.title === 'Portal')).toEqual({
      title: 'Portal',
      href: '/custom/portal',
      requiresAuth: false,
    })
  })

  it('keeps an internal item at the stored path', () => {
    const links = linksFor([
      {
        id: 'status',
        title: 'Status',
        href: '/pricing?tab=plans',
        openMode: 'internal',
      },
    ])
    expect(links.find((link) => link.title === 'Status')).toEqual({
      title: 'Status',
      href: '/pricing?tab=plans',
      requiresAuth: false,
    })
  })

  it.each([
    ['internal', '/guarded'],
    ['iframe', 'https://example.com/guarded'],
    ['external', 'https://example.com/guarded'],
  ])(
    'asks visitors to sign in for a protected %s item only while signed out',
    (openMode, href) => {
      const item = {
        id: 'guarded',
        title: 'Guarded',
        href,
        openMode,
        requireAuth: true,
      }
      const signedOut = linksFor([item], false)
      const signedIn = linksFor([item], true)
      expect(
        signedOut.find((link) => link.title === 'Guarded')?.requiresAuth
      ).toBe(true)
      expect(
        signedIn.find((link) => link.title === 'Guarded')?.requiresAuth
      ).toBe(false)
    }
  )

  it('never asks for sign-in on an item that is not protected', () => {
    const links = linksFor([
      {
        id: 'open',
        title: 'Open',
        href: '/open',
        openMode: 'internal',
        requireAuth: false,
      },
    ])
    expect(links.find((link) => link.title === 'Open')?.requiresAuth).toBe(
      false
    )
  })

  it('drops items whose href is unsafe for their open mode', () => {
    const links = linksFor([
      {
        id: 'script',
        title: 'Script',
        href: 'javascript:alert(1)',
        openMode: 'external',
      },
      {
        id: 'frame',
        title: 'Frame',
        href: 'data:text/html,hello',
        openMode: 'iframe',
      },
      { id: 'fine', title: 'Fine', href: '/fine', openMode: 'internal' },
    ])
    expect(links.map((link) => link.title)).toEqual([
      'Home',
      'Console',
      'Model Square',
      'Rankings',
      'Docs',
      'Fine',
      'About',
    ])
    expect(links.some((link) => link.href.startsWith('javascript:'))).toBe(
      false
    )
  })
})
