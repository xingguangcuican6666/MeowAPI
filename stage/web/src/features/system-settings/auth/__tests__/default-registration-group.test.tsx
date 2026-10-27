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
import { BasicAuthSection } from '../basic-auth-section'

const clients: QueryClient[] = []

const defaultValues = {
  PasswordLoginEnabled: true,
  PasswordRegisterEnabled: true,
  InviteCodeRegisterEnabled: true,
  EmailVerificationEnabled: false,
  RegisterEnabled: false,
  DefaultRegistrationGroup: 'default',
  EmailDomainRestrictionEnabled: false,
  EmailAliasRestrictionEnabled: false,
  EmailDomainWhitelist: '',
  EmailFormatRegex: '',
}

afterEach(() => {
  cleanup()
  clients.forEach((client) => client.clear())
  clients.length = 0
})

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
        <BasicAuthSection defaultValues={defaultValues} />
      </SettingsPageProvider>
    </>
  )
}

/** Renders the section and returns the loaded group selector. */
async function renderSection(
  groupsQuery: { data?: string[]; error?: Error } = {
    data: ['vip', 'default', 'free'],
  }
) {
  vi.spyOn(api, 'get').mockImplementation((async () => {
    if (groupsQuery.error) throw groupsQuery.error
    return {
      data: { success: true, message: '', data: groupsQuery.data ?? [] },
    }
  }) as never)
  vi.spyOn(api, 'put').mockResolvedValue({
    data: { success: true, message: '' },
  })
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  clients.push(client)
  render(
    <QueryClientProvider client={client}>
      <Fixture />
    </QueryClientProvider>
  )
  const group = await screen.findByRole('combobox', {
    name: 'Default Registration Group',
  })
  // The saved group is only marked unavailable once the list has settled.
  await waitFor(() =>
    expect(group).toHaveValue(
      groupsQuery.error || (groupsQuery.data ?? []).length === 0
        ? 'default (Unavailable)'
        : 'default'
    )
  )
  return group
}

describe('default registration group setting', () => {
  it('stays visible when registration is off and submits the selected group', async () => {
    const group = await renderSection()
    const user = userEvent.setup()

    expect(
      screen.getByRole('switch', { name: 'Registration Enabled' })
    ).not.toBeChecked()
    expect(group).toBeEnabled()

    await user.click(screen.getByRole('button', { name: 'Save Changes' }))
    expect(api.put).not.toHaveBeenCalled()

    await user.click(group)
    expect(
      screen.getAllByRole('option').map((option) => option.textContent)
    ).toEqual(['default', 'free', 'vip'])
    await user.click(screen.getByRole('option', { name: 'free' }))
    await waitFor(() => expect(group).toHaveValue('free'))

    await user.click(screen.getByRole('button', { name: 'Save Changes' }))
    await waitFor(() =>
      expect(api.put).toHaveBeenCalledWith('/api/option/', {
        key: 'DefaultRegistrationGroup',
        value: 'free',
      })
    )
    expect(api.put).toHaveBeenCalledTimes(1)
  })

  it('selects a group from the keyboard', async () => {
    const group = await renderSection()
    const user = userEvent.setup()

    await user.click(group)
    await user.keyboard('{ArrowDown}{ArrowDown}{Enter}')
    await waitFor(() => expect(group).toHaveValue('vip'))

    await user.click(screen.getByRole('button', { name: 'Save Changes' }))
    await waitFor(() =>
      expect(api.put).toHaveBeenCalledWith('/api/option/', {
        key: 'DefaultRegistrationGroup',
        value: 'vip',
      })
    )
  })

  it('preserves the saved group when the list fails to load and recovers on retry', async () => {
    let loaded = false
    vi.spyOn(api, 'get').mockImplementation((async () => {
      if (!loaded) {
        loaded = true
        throw new Error('groups unavailable')
      }
      return {
        data: {
          success: true,
          message: '',
          data: ['vip', 'default', 'free'],
        },
      }
    }) as never)
    vi.spyOn(api, 'put').mockResolvedValue({
      data: { success: true, message: '' },
    })
    const client = new QueryClient({
      defaultOptions: {
        queries: { retry: false },
        mutations: { retry: false },
      },
    })
    clients.push(client)
    render(
      <QueryClientProvider client={client}>
        <Fixture />
      </QueryClientProvider>
    )
    const group = await screen.findByRole('combobox', {
      name: 'Default Registration Group',
    })
    await waitFor(() => expect(group).toBeDisabled())
    expect(group).toHaveValue('default (Unavailable)')
    const failure = await screen.findByText('Failed to load groups')
    // The shared error state fades in; wait for the animation to settle.
    await waitFor(() => expect(failure).toBeVisible())
    expect(
      screen.getByText(
        'The saved group is preserved. Retry before changing it.'
      )
    ).toBeInTheDocument()
    expect(screen.queryByText('No groups available')).not.toBeInTheDocument()

    const user = userEvent.setup()
    await user.click(screen.getByRole('button', { name: 'Retry' }))
    await waitFor(() => expect(group).toBeEnabled())
    expect(group).toHaveValue('default')
    await waitFor(() => expect(failure).not.toBeInTheDocument())
    expect(api.get).toHaveBeenCalledTimes(2)
  })

  it('shows the empty state without replacing the saved group', async () => {
    const group = await renderSection({ data: [] })

    expect(group).toBeEnabled()
    expect(group).toHaveValue('default (Unavailable)')
    const empty = await screen.findByText('No groups available')
    await waitFor(() => expect(empty).toBeVisible())

    await userEvent.setup().click(group)
    await waitFor(() =>
      expect(screen.getByRole('option')).toHaveAttribute(
        'aria-disabled',
        'true'
      )
    )
    expect(screen.getByRole('option')).toHaveTextContent(
      'default (Unavailable)'
    )
  })
})
