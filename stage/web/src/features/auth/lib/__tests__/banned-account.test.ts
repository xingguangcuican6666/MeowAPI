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

import {
  AxiosError,
  AxiosHeaders,
  type InternalAxiosRequestConfig,
} from 'axios'
import { afterEach, describe, expect, it, vi } from 'vitest'

import {
  ACCOUNT_SUSPENDED_PATH,
  AUTH_USER_DISABLED_CODE,
  hasAccountDisabledCode,
  redirectToAccountSuspended,
  redirectToAccountSuspendedIfBanned,
} from '../banned-account'

const originalLocation = window.location
const originalLocationDescriptor = Object.getOwnPropertyDescriptor(
  window,
  'location'
)

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

function bannedAxiosError(status: number) {
  const config: InternalAxiosRequestConfig = { headers: new AxiosHeaders() }
  return new AxiosError(
    'Request failed',
    'ERR_BAD_REQUEST',
    config,
    undefined,
    {
      data: {
        success: false,
        code: AUTH_USER_DISABLED_CODE,
        message: 'Your account has been suspend!',
      },
      status,
      statusText: 'Forbidden',
      headers: {},
      config,
    }
  )
}

afterEach(() => {
  restoreLocation()
  vi.restoreAllMocks()
})

describe('hasAccountDisabledCode', () => {
  it('recognizes the ban code on a raw business payload, an axios error and a wrapped cause', () => {
    expect(
      hasAccountDisabledCode({ success: false, code: AUTH_USER_DISABLED_CODE })
    ).toBe(true)
    const axiosError = bannedAxiosError(403)
    expect(hasAccountDisabledCode(axiosError)).toBe(true)
    expect(
      hasAccountDisabledCode(new Error('Login failed', { cause: axiosError }))
    ).toBe(true)
  })

  it('accepts the ban on both statuses the backend uses', () => {
    expect(hasAccountDisabledCode(bannedAxiosError(401))).toBe(true)
    expect(hasAccountDisabledCode(bannedAxiosError(403))).toBe(true)
  })

  it('does not treat another auth failure or a matching message as a ban', () => {
    expect(
      hasAccountDisabledCode({
        success: false,
        code: 'AUTH_SESSION_REVOKED',
      })
    ).toBe(false)
    expect(
      hasAccountDisabledCode({
        success: false,
        message: 'Your account has been suspend!',
      })
    ).toBe(false)
    expect(hasAccountDisabledCode(undefined)).toBe(false)
  })
})

describe('redirectToAccountSuspended', () => {
  it('replaces the current document with the account-state page', () => {
    const replace = installLocation('/dashboard')
    expect(redirectToAccountSuspended()).toBe(true)
    expect(replace).toHaveBeenCalledWith(ACCOUNT_SUSPENDED_PATH)
  })

  it('does not navigate again when the account-state page is already showing', () => {
    const replace = installLocation(ACCOUNT_SUSPENDED_PATH)
    expect(redirectToAccountSuspended()).toBe(false)
    expect(replace).not.toHaveBeenCalled()
  })
})

describe('redirectToAccountSuspendedIfBanned', () => {
  it('leaves ordinary failures to the caller and reports them as unhandled', () => {
    const replace = installLocation('/sign-in')
    expect(
      redirectToAccountSuspendedIfBanned({
        success: false,
        code: 'AUTH_INTERNAL_ERROR',
      })
    ).toBe(false)
    expect(replace).not.toHaveBeenCalled()
  })

  it('takes over a refused sign-in that carries the ban code', () => {
    const replace = installLocation('/sign-in')
    expect(
      redirectToAccountSuspendedIfBanned({
        success: false,
        code: AUTH_USER_DISABLED_CODE,
      })
    ).toBe(true)
    expect(replace).toHaveBeenCalledWith(ACCOUNT_SUSPENDED_PATH)
  })
})
