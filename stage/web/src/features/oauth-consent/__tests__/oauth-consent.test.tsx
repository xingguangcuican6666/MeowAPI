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

import { render, screen, waitFor } from '@testing-library/react'
import { afterEach, describe, expect, test } from 'vitest'

const { createInstance } = await import('i18next')
const { I18nextProvider, initReactI18next } = await import('react-i18next')
const { QueryClient, QueryClientProvider } =
  await import('@tanstack/react-query')
const { api } = await import('@/lib/api')
const { OAuthConsent } = await import('../index')

// Map the backend's English scope title/description to distinct localized
// strings. If the consent screen renders these, it is keying t() off the
// server-supplied English copy (the project's localization convention) rather
// than printing the raw server string.
const i18n = createInstance()
await i18n.use(initReactI18next).init({
  lng: 'en',
  resources: {
    en: {
      translation: {
        'Read your wallet': 'LOCALIZED_WALLET_TITLE',
        'View your quota balance and the available top-up options':
          'LOCALIZED_WALLET_DESCRIPTION',
      },
    },
  },
})

const CONTEXT = {
  client: { name: 'Acme', description: '', logo: '', homepage: '' },
  scopes: [
    {
      name: 'wallet.read',
      title: 'Read your wallet',
      description: 'View your quota balance and the available top-up options',
      sensitive: false,
    },
    {
      name: 'wallet.topup',
      title: 'Top up your wallet',
      description: 'Create top-up orders on your behalf',
      sensitive: true,
    },
  ],
  // Keep the prompt interactive; already_authorized would auto-approve and
  // redirect before we could assert on the rendered scopes.
  already_authorized: false,
}

type ApiMethod = (url: string, config?: unknown) => Promise<{ data: unknown }>
type MockableApi = { get: ApiMethod }
const apiClient = api as unknown as MockableApi
const originalGet = apiClient.get
let activeClient: InstanceType<typeof QueryClient> | null = null

function installContextFixture() {
  // The consent query has no staleTime, so react-query refetches on mount and
  // the mocked transport must answer rather than rely solely on seeded data.
  apiClient.get = async (url) => {
    if (url === '/api/oauth-server/authorize/context') {
      return { data: { success: true, data: CONTEXT } }
    }
    throw new Error(`Unexpected GET ${url}`)
  }
}

function renderConsent() {
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  activeClient = queryClient
  render(
    <QueryClientProvider client={queryClient}>
      <I18nextProvider i18n={i18n}>
        <OAuthConsent request='req-token' />
      </I18nextProvider>
    </QueryClientProvider>
  )
}

afterEach(() => {
  apiClient.get = originalGet
  if (activeClient) {
    activeClient.clear()
    activeClient = null
  }
  localStorage.clear()
})

describe('OAuth consent — scope rendering', () => {
  test('localizes scope copy by keying t() off the backend English strings', async () => {
    installContextFixture()
    renderConsent()
    expect(await screen.findByText('LOCALIZED_WALLET_TITLE')).toBeTruthy()
    expect(screen.getByText('LOCALIZED_WALLET_DESCRIPTION')).toBeTruthy()
    // The sensitive scope has no resource entry, so t() falls back to the
    // backend title verbatim — localization degrades gracefully.
    expect(screen.getByText('Top up your wallet')).toBeTruthy()
  })

  test('warns when a requested scope is sensitive', async () => {
    installContextFixture()
    renderConsent()
    await screen.findByText('LOCALIZED_WALLET_TITLE')
    await waitFor(() =>
      expect(
        screen.queryByText(
          'This application is requesting sensitive permissions. Only continue if you trust it.'
        )
      ).not.toBeNull()
    )
  })
})
