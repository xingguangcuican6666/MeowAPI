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

import type { Channel } from '../../types'
import {
  CHANNEL_FORM_DEFAULT_VALUES,
  channelFormSchema,
  transformChannelToFormDefaults,
  transformFormDataToUpdatePayload,
} from '../channel-form'

function channelWithSettings(settings: string): Channel {
  return {
    id: 42,
    type: 1,
    key: '',
    name: 'Forced retry channel',
    status: 1,
    created_time: 0,
    test_time: 0,
    response_time: 0,
    base_url: 'https://relay.example/v1',
    other: '',
    models: 'gpt-5',
    group: 'default',
    priority: 0,
    weight: 0,
    settings,
    channel_info: { multi_key_mode: 'random' },
  } as unknown as Channel
}

function forcedRetryForm(overrides: Record<string, unknown> = {}) {
  return {
    ...CHANNEL_FORM_DEFAULT_VALUES,
    name: 'Forced retry channel',
    type: 1,
    base_url: 'https://relay.example/v1/',
    key: 'channel-key',
    models: 'gpt-5',
    automatic_retry_override_enabled: true,
    automatic_retry_status_codes: '200',
    automatic_retry_keywords: 'no available upstream',
    ...overrides,
  }
}

describe('channel forced retry rules round trip', () => {
  // Regression: the editor saved the forced retry rules into the channel
  // settings JSON but never read them back, so reopening the editor showed
  // the switch off while the backend still had (and applied) the saved rules.
  test('a channel with saved forced retry rules reopens with the switch on and its values filled in', () => {
    const form = transformChannelToFormDefaults(
      channelWithSettings(
        JSON.stringify({
          automatic_retry_override_enabled: true,
          automatic_retry_status_codes: '200',
          automatic_retry_keywords: 'no available upstream',
        })
      )
    )

    expect(form.automatic_retry_override_enabled).toBe(true)
    expect(form.automatic_retry_status_codes).toBe('200')
    expect(form.automatic_retry_keywords).toBe('no available upstream')
  })

  test('a channel without forced retry rules keeps the switch off', () => {
    const form = transformChannelToFormDefaults(
      channelWithSettings(
        JSON.stringify({ keep_this_setting: true })
      )
    )

    expect(form.automatic_retry_override_enabled).toBe(false)
    expect(form.automatic_retry_status_codes).toBe('')
    expect(form.automatic_retry_keywords).toBe('')
  })

  test('a saved rule survives a no-op reopen and re-save', () => {
    const saved = JSON.parse(
      transformFormDataToUpdatePayload(forcedRetryForm(), 42).settings || '{}'
    )
    expect(saved.automatic_retry_override_enabled).toBe(true)
    expect(saved.automatic_retry_status_codes).toBe('200')
    expect(saved.automatic_retry_keywords).toBe('no available upstream')

    const reopened = transformChannelToFormDefaults(
      channelWithSettings(
        JSON.stringify({
          ...saved,
          keep_this_setting: true,
        })
      )
    )
    expect(reopened.automatic_retry_override_enabled).toBe(true)

    const resaved = JSON.parse(
      transformFormDataToUpdatePayload(reopened, 42).settings || '{}'
    )
    expect(resaved.automatic_retry_override_enabled).toBe(true)
    expect(resaved.automatic_retry_status_codes).toBe('200')
    expect(resaved.automatic_retry_keywords).toBe('no available upstream')
    expect(resaved.keep_this_setting).toBe(true)
  })

  test('turning the switch off removes the rules from the settings JSON', () => {
    const saved = JSON.parse(
      transformFormDataToUpdatePayload(
        forcedRetryForm({
          automatic_retry_override_enabled: false,
        }),
        42
      ).settings || '{}'
    )
    expect(saved.automatic_retry_override_enabled).toBeUndefined()
    expect(saved.automatic_retry_status_codes).toBeUndefined()
    expect(saved.automatic_retry_keywords).toBeUndefined()
  })
})

describe('channel forced retry status code validation', () => {
  test('invalid status codes fail validation with a field error instead of being saved silently', () => {
    const parsed = channelFormSchema.safeParse(
      forcedRetryForm({ automatic_retry_status_codes: '999,abc' })
    )

    expect(parsed.success).toBe(false)
    if (!parsed.success) {
      expect(
        parsed.error.issues.some(
          (issue) => issue.path[0] === 'automatic_retry_status_codes'
        )
      ).toBe(true)
    }
  })

  test('a valid code list passes', () => {
    const parsed = channelFormSchema.safeParse(
      forcedRetryForm({ automatic_retry_status_codes: '200,500-503' })
    )

    expect(parsed.success).toBe(true)
  })
})
