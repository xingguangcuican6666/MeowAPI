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
  BILLING_QUERY_NEW_API_PATH,
  BILLING_QUERY_TYPE_NEW_API,
} from '../../constants'
import type { Channel } from '../../types'
import {
  CHANNEL_FORM_DEFAULT_VALUES,
  channelFormSchema,
  transformChannelToFormDefaults,
  transformFormDataToCreatePayload,
  transformFormDataToUpdatePayload,
} from '../channel-form'

function billingForm(overrides: Record<string, unknown> = {}) {
  return {
    ...CHANNEL_FORM_DEFAULT_VALUES,
    name: 'Billing query channel',
    type: 1,
    base_url: 'https://relay.example/v1/',
    key: 'channel-key',
    models: 'gpt-5',
    ...overrides,
  }
}

function configuredBillingForm() {
  return channelFormSchema.parse(
    billingForm({
      billing_query: {
        type: BILLING_QUERY_TYPE_NEW_API,
        base_url: ' https://billing.example/api/// ',
        bearer_token: ' custom-token ',
        user_id: ' 1001 ',
        use_api_key: false,
      },
    })
  )
}

function channelWithSettings(settings: string): Channel {
  return {
    id: 42,
    type: 1,
    key: '',
    name: 'Billing query channel',
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

describe('channel billing query form settings', () => {
  test('uses the New API user self endpoint', () => {
    expect(BILLING_QUERY_NEW_API_PATH).toBe('/api/user/self')
  })

  test('requires an HTTP or HTTPS Base URL only when a query type is selected', () => {
    const defaultQuery = channelFormSchema.safeParse(
      billingForm({
        billing_query: {
          ...CHANNEL_FORM_DEFAULT_VALUES.billing_query,
          type: '',
        },
      })
    )
    expect(defaultQuery.success).toBe(true)

    const missingBaseURL = channelFormSchema.safeParse(
      billingForm({
        billing_query: {
          type: BILLING_QUERY_TYPE_NEW_API,
          base_url: ' ',
          bearer_token: '',
          use_api_key: true,
        },
      })
    )
    expect(missingBaseURL.success).toBe(false)
    if (!missingBaseURL.success) {
      expect(
        missingBaseURL.error.issues.some(
          (issue) =>
            issue.path.join('.') === 'billing_query.base_url' &&
            issue.message === 'Balance query Base URL is required'
        )
      ).toBe(true)
    }

    const invalidBaseURL = channelFormSchema.safeParse(
      billingForm({
        billing_query: {
          type: BILLING_QUERY_TYPE_NEW_API,
          base_url: 'ftp://billing.example',
          bearer_token: '',
          use_api_key: true,
        },
      })
    )
    expect(invalidBaseURL.success).toBe(false)
  })

  test('backfills the independent query settings from channel JSON', () => {
    const form = transformChannelToFormDefaults(
      channelWithSettings(
        JSON.stringify({
          billing_query: {
            type: BILLING_QUERY_TYPE_NEW_API,
            base_url: 'https://billing.example/api/',
            bearer_token: 'custom-token',
            user_id: '1001',
            use_api_key: false,
          },
        })
      )
    )

    expect(form.billing_query).toEqual({
      type: BILLING_QUERY_TYPE_NEW_API,
      base_url: 'https://billing.example/api/',
      bearer_token: 'custom-token',
      user_id: '1001',
      use_api_key: false,
    })
  })

  test('persists custom auth and keeps billing URL independent from relay URL', () => {
    const form = configuredBillingForm()
    const createPayload = transformFormDataToCreatePayload(form)
    const createSettings = JSON.parse(createPayload.channel.settings || '{}')

    expect(createPayload.channel.base_url).toBe('https://relay.example/v1')
    expect(createSettings.billing_query).toEqual({
      type: BILLING_QUERY_TYPE_NEW_API,
      base_url: 'https://billing.example/api',
      bearer_token: 'custom-token',
      user_id: '1001',
      use_api_key: false,
    })

    const updatePayload = transformFormDataToUpdatePayload(form, 42)
    const updateSettings = JSON.parse(updatePayload.settings || '{}')
    expect(updateSettings.billing_query).toEqual(createSettings.billing_query)
  })

  test('removes a previously saved query when the default mode is selected', () => {
    const form = channelFormSchema.parse(
      billingForm({
        settings: JSON.stringify({
          billing_query: {
            type: BILLING_QUERY_TYPE_NEW_API,
            base_url: 'https://billing.example',
          },
          keep_this_setting: true,
        }),
        billing_query: {
          type: '',
          base_url: '',
          bearer_token: '',
          use_api_key: true,
        },
      })
    )
    const payload = transformFormDataToUpdatePayload(form, 42)
    const settings = JSON.parse(payload.settings || '{}')

    expect(settings.billing_query).toBeUndefined()
    expect(settings.keep_this_setting).toBe(true)
  })
})
