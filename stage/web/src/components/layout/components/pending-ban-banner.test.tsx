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

import { cleanup, render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { afterEach, describe, expect, it, vi } from 'vitest'

import { useProfile } from '@/features/profile/hooks/use-profile'

import { PendingBanBanner } from './pending-ban-banner'

vi.mock('@/features/profile/hooks/use-profile')

const useTranslation = vi.fn((_namespace: string) => ({
  t: (key: string) => key,
}))

vi.mock('react-i18next', () => ({
  useTranslation: (namespace: string) => useTranslation(namespace),
}))

const profile = {
  pending_ban_reason: 'Update the account email',
  pending_ban_deadline: 1_700_000_000,
}

afterEach(() => {
  cleanup()
  vi.resetAllMocks()
})

describe('PendingBanBanner', () => {
  it('renders a single-line summary with a fixed arrow and opens details', async () => {
    vi.mocked(useProfile).mockReturnValue({ profile } as ReturnType<
      typeof useProfile
    >)
    const user = userEvent.setup()

    render(<PendingBanBanner />)

    const alert = screen.getByRole('alert')
    expect(alert).toHaveClass('relative', 'z-20')
    expect(useTranslation).toHaveBeenCalledWith('translation')
    const trigger = within(alert).getByRole('button')
    expect(trigger).toHaveTextContent(
      'Your account is scheduled to be banned: Pending fix: Update the account email->'
    )
    expect(trigger.querySelector('.truncate')).not.toBeNull()
    expect(trigger.lastElementChild).toHaveTextContent('->')
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()

    await user.click(trigger)

    const dialog = screen.getByRole('dialog', {
      name: 'Your account is scheduled to be banned',
    })
    expect(dialog).toHaveTextContent('Pending fix: Update the account email')
    expect(dialog).toHaveTextContent('Deadline:')
    expect(dialog).toHaveTextContent(
      new Date(profile.pending_ban_deadline * 1000).toLocaleString()
    )
  })

  it('renders nothing when there is no pending ban', () => {
    vi.mocked(useProfile).mockReturnValue({ profile: null } as ReturnType<
      typeof useProfile
    >)

    const { container } = render(<PendingBanBanner />)

    expect(container).toBeEmptyDOMElement()
  })
})
