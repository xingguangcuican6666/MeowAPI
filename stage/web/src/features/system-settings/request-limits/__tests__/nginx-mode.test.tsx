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
import { cleanup, render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { useState } from 'react'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { api } from '@/lib/api'

import { SettingsPageProvider } from '../../components/settings-page-context'
import { RateLimitSection } from '../rate-limit-section'

const clients: QueryClient[] = []

const defaultValues = {
  ModelRequestRateLimitEnabled: false,
  ModelRequestRateLimitCount: 0,
  ModelRequestRateLimitSuccessCount: 1000,
  ModelRequestRateLimitDurationMinutes: 1,
  ModelRequestRateLimitGroup: '',
  NginxMode: false,
  DisableRateLimit: false,
}

afterEach(() => {
  cleanup()
  clients.forEach((client) => client.clear())
  clients.length = 0
  vi.restoreAllMocks()
})

async function renderSection(overrides: Partial<typeof defaultValues> = {}) {
  vi.spyOn(api, 'get').mockResolvedValue({ data: { success: true } } as never)
  vi.spyOn(api, 'put').mockResolvedValue({
    data: { success: true, message: '' },
  } as never)
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  clients.push(client)
  function Fixture() {
    const [actionsContainer, setActionsContainer] =
      useState<HTMLDivElement | null>(null)
    return (
      <>
        <div ref={setActionsContainer} />
        <SettingsPageProvider
          actionsContainer={actionsContainer}
          suppressSectionHeader={false}
        >
          <RateLimitSection
            defaultValues={{ ...defaultValues, ...overrides }}
          />
        </SettingsPageProvider>
      </>
    )
  }
  render(
    <QueryClientProvider client={client}>
      <Fixture />
    </QueryClientProvider>
  )
  return screen.findByRole('switch', {
    name: 'Nginx mode (behind a reverse proxy)',
  })
}

describe('nginx mode setting', () => {
  it('saves the enforcement key so the toggle is not inert', async () => {
    const toggle = await renderSection()
    const user = userEvent.setup()

    expect(toggle).not.toBeChecked()
    await user.click(toggle)
    await user.click(screen.getByRole('button', { name: 'Save rate limits' }))

    // The retired key name was never read by the backend, so the assertion
    // that matters is which key reaches the option API.
    await waitFor(() =>
      expect(api.put).toHaveBeenCalledWith('/api/option/', {
        key: 'NginxMode',
        value: true,
      })
    )
    expect(api.put).toHaveBeenCalledTimes(1)
  })

  it('reflects a stored setting and can switch it back off', async () => {
    const toggle = await renderSection({ NginxMode: true })
    const user = userEvent.setup()

    expect(toggle).toBeChecked()
    await user.click(toggle)
    await user.click(screen.getByRole('button', { name: 'Save rate limits' }))

    await waitFor(() =>
      expect(api.put).toHaveBeenCalledWith('/api/option/', {
        key: 'NginxMode',
        value: false,
      })
    )
  })

  it('does not submit when nothing changed', async () => {
    const toggle = await renderSection()
    const user = userEvent.setup()

    expect(toggle).not.toBeChecked()
    await user.click(screen.getByRole('button', { name: 'Save rate limits' }))
    await waitFor(() => expect(api.put).not.toHaveBeenCalled())
  })
})
