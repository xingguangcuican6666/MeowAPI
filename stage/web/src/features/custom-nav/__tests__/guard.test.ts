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

import { QueryClient } from '@tanstack/react-query'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { getStatus } from '@/lib/api'
import { resolveAuthentication } from '@/lib/auth-session'
import {
  parseHeaderNavModulesFromStatus,
  type CustomNavItem,
} from '@/lib/nav-modules'
import { useAuthStore } from '@/stores/auth-store'

import { resolveCustomNavItem } from '../lib/guard'

vi.mock('@/lib/api', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/api')>()),
  getStatus: vi.fn(),
}))
vi.mock('@/lib/auth-session', async (importOriginal) => ({
  ...(await importOriginal<typeof import('@/lib/auth-session')>()),
  resolveAuthentication: vi.fn(),
}))
vi.mock('@/lib/nav-modules', async (importOriginal) => {
  const actual = await importOriginal<typeof import('@/lib/nav-modules')>()
  return {
    ...actual,
    // Delegates to the real parser; one test overrides a single call.
    parseHeaderNavModulesFromStatus: vi.fn(
      actual.parseHeaderNavModulesFromStatus
    ),
  }
})

const customItems = [
  {
    id: 'portal',
    title: 'Portal',
    href: 'https://portal.example.com/app',
    openMode: 'iframe',
    requireAuth: false,
  },
  {
    id: 'private',
    title: 'Private',
    href: 'https://private.example.com/',
    openMode: 'iframe',
    requireAuth: true,
  },
  {
    id: 'partner',
    title: 'Partner',
    href: 'https://partner.example.com/',
    openMode: 'external',
    requireAuth: false,
  },
  { id: 'local', title: 'Local', href: '/pricing', openMode: 'internal' },
  {
    id: 'script',
    title: 'Script',
    href: 'javascript:alert(1)',
    openMode: 'iframe',
  },
]

const alice = { id: 1, username: 'alice', role: 1 }
const aliceSession = {
  sid: 'session-1',
  current: true,
  login_method: 'password',
  ip: '127.0.0.1',
  user_agent: 'vitest',
  created_at: 0,
  last_active_at: 0,
  expires_at: 0,
}

function newClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } })
}

beforeEach(() => {
  vi.mocked(getStatus).mockResolvedValue({
    HeaderNavModules: JSON.stringify({ customItems }),
  })
  vi.mocked(resolveAuthentication).mockResolvedValue({ kind: 'anonymous' })
})

afterEach(() => {
  useAuthStore.getState().auth.reset()
})

describe('resolveCustomNavItem', () => {
  it('resolves an iframe item on a direct open with an empty status cache', async () => {
    const item = await resolveCustomNavItem(
      newClient(),
      'portal',
      '/custom/portal'
    )
    expect(item).toMatchObject({
      id: 'portal',
      href: 'https://portal.example.com/app',
      openMode: 'iframe',
    })
    expect(getStatus).toHaveBeenCalledTimes(1)
  })

  it('does not consult the session for an item that needs no sign-in', async () => {
    await resolveCustomNavItem(newClient(), 'portal', '/custom/portal')
    expect(resolveAuthentication).not.toHaveBeenCalled()
  })

  it.each([
    ['an unknown id', 'missing'],
    ['an external item', 'partner'],
    ['an internal item', 'local'],
    ['an item with an unsafe href', 'script'],
  ])('sends %s home', async (_label, itemId) => {
    await expect(
      resolveCustomNavItem(newClient(), itemId, `/custom/${itemId}`)
    ).rejects.toMatchObject({ options: { to: '/' } })
  })

  it('refuses an unsafe iframe href even if the parser lets it through', async () => {
    const unsafe: CustomNavItem = {
      id: 'script',
      title: 'Script',
      href: 'javascript:alert(1)',
      openMode: 'iframe',
      requireAuth: false,
    }
    vi.mocked(parseHeaderNavModulesFromStatus).mockReturnValueOnce({
      ...parseHeaderNavModulesFromStatus(null),
      customItems: [unsafe],
    })
    await expect(
      resolveCustomNavItem(newClient(), 'script', '/custom/script')
    ).rejects.toMatchObject({ options: { to: '/' } })
  })

  it('fails closed when status cannot be read', async () => {
    vi.mocked(getStatus).mockRejectedValue(new Error('status unavailable'))
    await expect(
      resolveCustomNavItem(newClient(), 'portal', '/custom/portal')
    ).rejects.toMatchObject({ options: { to: '/' } })
  })

  it('sends a signed-out visitor to sign-in and back to the item', async () => {
    await expect(
      resolveCustomNavItem(newClient(), 'private', '/custom/private')
    ).rejects.toMatchObject({
      options: { to: '/sign-in', search: { redirect: '/custom/private' } },
    })
    expect(resolveAuthentication).toHaveBeenCalledTimes(1)
  })

  it('serves a protected item to a signed-in visitor', async () => {
    useAuthStore.getState().auth.setUser(alice)
    const item = await resolveCustomNavItem(
      newClient(),
      'private',
      '/custom/private'
    )
    expect(item.id).toBe('private')
  })

  it('serves a protected item once the session is restored from the server', async () => {
    vi.mocked(resolveAuthentication).mockImplementation(async () => {
      useAuthStore.getState().auth.setUser(alice)
      return {
        kind: 'authenticated',
        bundle: {
          access_token: 'token',
          token_type: 'Bearer',
          access_expires_at: 0,
          user: alice,
          session: aliceSession,
        },
      }
    })
    const item = await resolveCustomNavItem(
      newClient(),
      'private',
      '/custom/private'
    )
    expect(item.id).toBe('private')
  })
})
