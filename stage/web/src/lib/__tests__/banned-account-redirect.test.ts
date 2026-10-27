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

import { AxiosError, type AxiosAdapter } from 'axios'
import { toast } from 'sonner'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { ACCOUNT_SUSPENDED_PATH } from '@/features/auth/lib/banned-account'
import { api } from '@/lib/http-client'
import { useAuthStore, type AuthBundle } from '@/stores/auth-store'

const originalAdapter = api.defaults.adapter
const originalLocation = window.location
const originalLocationDescriptor = Object.getOwnPropertyDescriptor(
  window,
  'location'
)

const activeBundle: AuthBundle = {
  access_token: 'access',
  token_type: 'Bearer',
  access_expires_at: 2_000_000_000,
  user: { id: 1, username: 'banned-user', role: 1 },
  session: {
    sid: 'session-a',
    current: true,
    login_method: 'password',
    ip: '127.0.0.1',
    user_agent: 'test',
    created_at: 100,
    last_active_at: 100,
    expires_at: 2_000_000_000,
  },
}

function installLocation(pathname: string) {
  const replace = vi.fn()
  Object.defineProperty(window, 'location', {
    configurable: true,
    writable: true,
    value: {
      pathname,
      origin: originalLocation.origin,
      href: `${originalLocation.origin}${pathname}`,
      search: '',
      hash: '',
      replace,
    },
  })
  return replace
}

function restoreLocation() {
  const descriptor = originalLocationDescriptor ?? {
    configurable: true,
    writable: true,
    value: originalLocation,
  }
  Object.defineProperty(window, 'location', descriptor)
}

afterEach(() => {
  api.defaults.adapter = originalAdapter
  vi.restoreAllMocks()
  useAuthStore.getState().auth.reset('idle')
  restoreLocation()
  window.history.replaceState({}, '', '/')
})

describe('banned account at runtime', () => {
  it('neither refreshes nor replays a request refused with the ban code', async () => {
    useAuthStore.getState().auth.setBundle(activeBundle)
    const replace = installLocation('/dashboard')
    const notify = vi.spyOn(toast, 'error').mockReturnValue('error')
    const refreshSend = vi.spyOn(XMLHttpRequest.prototype, 'send')

    let requests = 0
    const adapter: AxiosAdapter = async (config) => {
      requests += 1
      // The dashboard middleware answers a banned account with 401 + code.
      throw new AxiosError('HTTP 401', 'ERR_BAD_REQUEST', config, undefined, {
        data: { success: false, code: 'AUTH_USER_DISABLED' },
        status: 401,
        statusText: 'Unauthorized',
        headers: {},
        config,
      })
    }
    api.defaults.adapter = adapter

    await api.get('/api/user/self').catch(() => undefined)

    expect(requests).toBe(1)
    expect(refreshSend).not.toHaveBeenCalled()
    expect(replace).toHaveBeenCalledWith(ACCOUNT_SUSPENDED_PATH)
    // The page itself states the verdict; a toast would be a second,
    // competing explanation of the same thing.
    expect(notify).not.toHaveBeenCalled()
    expect(useAuthStore.getState().auth.user).toBeNull()
  })

  it('routes to the account-state page when the refresh itself reports the ban', async () => {
    useAuthStore.getState().auth.setBundle(activeBundle)
    const replace = installLocation('/dashboard')
    const notify = vi.spyOn(toast, 'error').mockReturnValue('error')

    // The refresh endpoint answers a ban with 403 + code.
    vi.spyOn(XMLHttpRequest.prototype, 'send').mockImplementation(
      function (this: XMLHttpRequest) {
        Object.defineProperties(this, {
          status: { value: 403, configurable: true },
          statusText: { value: 'Forbidden', configurable: true },
          responseText: {
            value: JSON.stringify({
              success: false,
              code: 'AUTH_USER_DISABLED',
              message: 'Your account has been suspend!',
            }),
            configurable: true,
          },
          readyState: { value: 4, configurable: true },
        })
        this.onloadend?.(new ProgressEvent('loadend'))
      }
    )

    let requests = 0
    const adapter: AxiosAdapter = async (config) => {
      requests += 1
      throw new AxiosError('HTTP 401', 'ERR_BAD_REQUEST', config, undefined, {
        data: { success: false, code: 'AUTH_TOKEN_EXPIRED' },
        status: 401,
        statusText: 'Unauthorized',
        headers: {},
        config,
      })
    }
    api.defaults.adapter = adapter

    await api.get('/api/user/self').catch(() => undefined)

    // The original request is never replayed against a banned account.
    expect(requests).toBe(1)
    expect(replace).toHaveBeenCalledWith(ACCOUNT_SUSPENDED_PATH)
    expect(notify).not.toHaveBeenCalled()
    expect(useAuthStore.getState().auth.user).toBeNull()
  })

  it('still sends an ordinary expired token back to the sign-in page', async () => {
    useAuthStore.getState().auth.setBundle(activeBundle)
    const replace = installLocation('/dashboard')
    const notify = vi.spyOn(toast, 'error').mockReturnValue('error')

    vi.spyOn(XMLHttpRequest.prototype, 'send').mockImplementation(
      function (this: XMLHttpRequest) {
        Object.defineProperties(this, {
          status: { value: 401, configurable: true },
          statusText: { value: 'Unauthorized', configurable: true },
          responseText: {
            value: JSON.stringify({ success: false }),
            configurable: true,
          },
          readyState: { value: 4, configurable: true },
        })
        this.onloadend?.(new ProgressEvent('loadend'))
      }
    )

    const adapter: AxiosAdapter = async (config) => {
      throw new AxiosError('HTTP 401', 'ERR_BAD_REQUEST', config, undefined, {
        data: { success: false, code: 'AUTH_TOKEN_EXPIRED' },
        status: 401,
        statusText: 'Unauthorized',
        headers: {},
        config,
      })
    }
    api.defaults.adapter = adapter

    await api.get('/api/user/self').catch(() => undefined)

    expect(replace).toHaveBeenCalledWith('/sign-in')
    expect(notify.mock.calls.map(([message]) => message)).toEqual([
      'Session expired!',
    ])
  })
})
