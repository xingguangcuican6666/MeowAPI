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

import { fireEvent, render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, test, vi } from 'vitest'

import { testChannelRatioProbe } from '../../../api'
import type { Channel } from '../../../types'
import { useChannels } from '../../channels-provider'
import { RatioProbeDialog } from '../ratio-probe-dialog'

vi.mock('../../../api', () => ({
  testChannelRatioProbe: vi.fn(),
}))

vi.mock('../../channels-provider', () => ({
  useChannels: vi.fn(),
}))

const channel = {
  id: 17,
  name: 'Ratio channel',
} as Channel

afterEach(() => {
  vi.clearAllMocks()
})

describe('ratio probe dialog', () => {
  test('probes on open, renders each key result, and supports rerunning the probe', async () => {
    vi.mocked(useChannels).mockReturnValue({
      currentRow: channel,
    } as ReturnType<typeof useChannels>)
    vi.mocked(testChannelRatioProbe).mockResolvedValue({
      success: true,
      data: {
        group: 'default',
        configured: true,
        results: [
          { key_index: 1, status: 'compliant', ratio: 1 },
          {
            key_index: 2,
            status: 'rejected',
            ratio: 1.4,
            message: 'group default ratio 1.4 exceeds max 1',
          },
        ],
      },
    })

    render(<RatioProbeDialog open onOpenChange={vi.fn()} />)

    await waitFor(() =>
      expect(testChannelRatioProbe).toHaveBeenCalledWith(channel.id)
    )
    expect(screen.getByText('default')).toBeInTheDocument()
    expect(screen.getByText('Key 1')).toBeInTheDocument()
    expect(screen.getByText('Key 2')).toBeInTheDocument()
    expect(screen.getByText('Compliant')).toBeInTheDocument()
    expect(screen.getByText('Rejected')).toBeInTheDocument()
    expect(screen.getByText('1x')).toBeInTheDocument()
    expect(screen.getByText('1.4x')).toBeInTheDocument()
    expect(
      screen.getByText('group default ratio 1.4 exceeds max 1')
    ).toBeInTheDocument()

    fireEvent.click(screen.getByRole('button', { name: 'Test' }))
    await waitFor(() => expect(testChannelRatioProbe).toHaveBeenCalledTimes(2))
  })
})
