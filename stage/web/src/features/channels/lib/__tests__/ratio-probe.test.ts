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

import {
  RATIO_PROBE_DEFAULT_PATH,
  RATIO_PROBE_MAX_AUTHORIZATION_LENGTH,
  RATIO_PROBE_SOURCE_CUSTOM,
  RATIO_PROBE_SOURCE_FOLLOW_API,
} from '../../constants'
import type { Channel } from '../../types'
import {
  CHANNEL_FORM_DEFAULT_VALUES,
  channelFormSchema,
  transformChannelToFormDefaults,
  transformFormDataToUpdatePayload,
} from '../channel-form'

function probeForm(
  probe: Record<string, unknown>,
  overrides: Record<string, unknown> = {}
) {
  return {
    ...CHANNEL_FORM_DEFAULT_VALUES,
    name: 'Ratio probe channel',
    type: 1,
    base_url: 'https://relay.example/v1/',
    key: 'channel-key',
    models: 'gpt-5',
    ratio_probe: { ...CHANNEL_FORM_DEFAULT_VALUES.ratio_probe, ...probe },
    ...overrides,
  }
}

function channelWithSettings(settings: string): Channel {
  return {
    id: 42,
    type: 1,
    key: '',
    name: 'Ratio probe channel',
    status: 1,
    created_time: 0,
    test_time: 0,
    response_time: 0,
    base_url: 'https://relay.example/v1',
    other: '',
    balance: 0,
    balance_updated_time: 0,
    models: 'gpt-5',
    group: 'default',
    used_quota: 0,
    setting: null,
    param_override: null,
    header_override: null,
    remark: '',
    max_input_tokens: 0,
    other_info: '',
    settings,
    channel_info: {
      is_multi_key: false,
      multi_key_size: 0,
      multi_key_polling_index: 0,
      multi_key_mode: 'random',
    },
  }
}

function issuePaths(result: ReturnType<typeof channelFormSchema.safeParse>) {
  if (result.success) return []
  return result.error.issues.map((issue) => issue.path.join('.'))
}

describe('channel ratio probe form settings', () => {
  test('a disabled probe never blocks the form', () => {
    const result = channelFormSchema.safeParse(
      probeForm({ enabled: false, max_group_ratio: '', min_group_ratio: '' })
    )
    expect(result.success).toBe(true)
  })

  test('an enabled probe requires at least one bound', () => {
    const result = channelFormSchema.safeParse(probeForm({ enabled: true }))
    expect(issuePaths(result)).toContain('ratio_probe.max_group_ratio')
  })

  test('a custom source requires an absolute Base URL', () => {
    const missing = channelFormSchema.safeParse(
      probeForm({
        enabled: true,
        source: RATIO_PROBE_SOURCE_CUSTOM,
        max_group_ratio: '1',
      })
    )
    expect(issuePaths(missing)).toContain('ratio_probe.base_url')

    const invalid = channelFormSchema.safeParse(
      probeForm({
        enabled: true,
        source: RATIO_PROBE_SOURCE_CUSTOM,
        base_url: 'ftp://probe.example',
        max_group_ratio: '1',
      })
    )
    expect(issuePaths(invalid)).toContain('ratio_probe.base_url')
  })

  test('rejects unusable paths and bounds', () => {
    const badPath = channelFormSchema.safeParse(
      probeForm({
        enabled: true,
        path: 'api/ratio_config',
        max_group_ratio: '1',
      })
    )
    expect(issuePaths(badPath)).toContain('ratio_probe.path')

    const badBound = channelFormSchema.safeParse(
      probeForm({ enabled: true, max_group_ratio: 'free' })
    )
    expect(issuePaths(badBound)).toContain('ratio_probe.max_group_ratio')

    const invertedBounds = channelFormSchema.safeParse(
      probeForm({ enabled: true, max_group_ratio: '1', min_group_ratio: '2' })
    )
    expect(issuePaths(invertedBounds)).toContain('ratio_probe.min_group_ratio')
  })

  test('rejects an Authorization header that cannot be sent', () => {
    const injected = channelFormSchema.safeParse(
      probeForm({
        enabled: true,
        max_group_ratio: '1',
        use_api_key: false,
        authorization: 'Bearer token\r\nX-Injected: 1',
      })
    )
    expect(issuePaths(injected)).toContain('ratio_probe.authorization')

    const tooLong = channelFormSchema.safeParse(
      probeForm({
        enabled: true,
        max_group_ratio: '1',
        use_api_key: false,
        authorization: 'a'.repeat(RATIO_PROBE_MAX_AUTHORIZATION_LENGTH + 1),
      })
    )
    expect(issuePaths(tooLong)).toContain('ratio_probe.authorization')
  })

  test('writes numeric bounds and drops the custom Base URL in follow mode', () => {
    const form = channelFormSchema.parse(
      probeForm({
        enabled: true,
        source: RATIO_PROBE_SOURCE_FOLLOW_API,
        base_url: 'https://probe.example',
        group: ' vip ',
        max_group_ratio: ' 1.2 ',
        min_group_ratio: '',
        use_api_key: false,
        authorization: ' Basic probe-token ',
      })
    )
    const settings = JSON.parse(
      transformFormDataToUpdatePayload(form, 42).settings || '{}'
    )

    expect(settings.ratio_probe).toEqual({
      enabled: true,
      source: RATIO_PROBE_SOURCE_FOLLOW_API,
      base_url: '',
      path: RATIO_PROBE_DEFAULT_PATH,
      group: 'vip',
      use_api_key: false,
      authorization: 'Basic probe-token',
      max_group_ratio: 1.2,
    })
  })

  test('keeps the probe state written by the backend task across saves', () => {
    const form = channelFormSchema.parse(
      probeForm(
        {
          enabled: true,
          max_group_ratio: '1',
        },
        {
          settings: JSON.stringify({
            ratio_probe: {
              enabled: true,
              max_group_ratio: 2,
              last_probe_time: 1750000000,
              last_status: 'rejected',
              last_message: 'group default ratio 2 exceeds max 1',
            },
          }),
        }
      )
    )
    const settings = JSON.parse(
      transformFormDataToUpdatePayload(form, 42).settings || '{}'
    )

    expect(settings.ratio_probe.max_group_ratio).toBe(1)
    expect(settings.ratio_probe.last_probe_time).toBe(1750000000)
    expect(settings.ratio_probe.last_status).toBe('rejected')
  })

  test('removes the probe config when the switch is turned off', () => {
    const form = channelFormSchema.parse(
      probeForm(
        { enabled: false },
        {
          settings: JSON.stringify({
            ratio_probe: { enabled: true, max_group_ratio: 1 },
            keep_this_setting: true,
          }),
        }
      )
    )
    const settings = JSON.parse(
      transformFormDataToUpdatePayload(form, 42).settings || '{}'
    )

    expect(settings.ratio_probe).toBeUndefined()
    expect(settings.keep_this_setting).toBe(true)
  })

  test('backfills the probe form from channel JSON', () => {
    const form = transformChannelToFormDefaults(
      channelWithSettings(
        JSON.stringify({
          ratio_probe: {
            enabled: true,
            source: RATIO_PROBE_SOURCE_CUSTOM,
            base_url: 'https://probe.example',
            path: '/api/pricing',
            group: 'vip',
            max_group_ratio: 1.5,
            use_api_key: false,
            authorization: 'Basic probe-token',
          },
        })
      )
    )

    expect(form.ratio_probe).toEqual({
      enabled: true,
      source: RATIO_PROBE_SOURCE_CUSTOM,
      base_url: 'https://probe.example',
      path: '/api/pricing',
      group: 'vip',
      max_group_ratio: '1.5',
      min_group_ratio: '',
      use_api_key: false,
      authorization: 'Basic probe-token',
    })
  })
})
