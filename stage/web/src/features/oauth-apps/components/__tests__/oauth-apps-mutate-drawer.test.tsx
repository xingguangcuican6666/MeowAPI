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

import { render, screen } from '@testing-library/react'
import { afterEach, describe, expect, test } from 'vitest'

const { createInstance } = await import('i18next')
const { I18nextProvider, initReactI18next } = await import('react-i18next')
const { QueryClient, QueryClientProvider } =
  await import('@tanstack/react-query')
const { api } = await import('@/lib/api')
const { useAuthStore } = await import('@/stores/auth-store')
const { ROLE } = await import('@/lib/roles')
const { OAuthAppsProvider } = await import('../oauth-apps-provider')
const { OAuthAppsMutateDrawer } = await import('../oauth-apps-mutate-drawer')

// Empty resources: t() echoes its key, so we assert against the literal English
// labels the component passes to t().
const i18n = createInstance()
await i18n.use(initReactI18next).init({
  lng: 'en',
  resources: { en: { translation: {} } },
})

const SCOPES = [
  {
    name: 'wallet.read',
    title: 'Read your wallet',
    description: 'View your quota balance and the available top-up options',
    oidc: false,
    sensitive: false,
  },
  {
    name: 'wallet.topup',
    title: 'Top up your wallet',
    description: 'Create top-up orders on your behalf',
    oidc: false,
    sensitive: true,
  },
]

type ApiMethod = (url: string, config?: unknown) => Promise<{ data: unknown }>
type MockableApi = { get: ApiMethod }
const apiClient = api as unknown as MockableApi
const originalGet = apiClient.get
let activeClient: InstanceType<typeof QueryClient> | null = null

function installScopeFixture() {
  apiClient.get = async (url) => {
    if (url === '/api/oauth-server/scopes') {
      return { data: { success: true, data: SCOPES } }
    }
    throw new Error(`Unexpected GET ${url}`)
  }
}

function renderDrawerAs(role: number) {
  useAuthStore.getState().auth.setUser({ id: 1, username: 'tester', role })
  const queryClient = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  })
  queryClient.setQueryData(
    ['oauth-server', 'scopes'],
    { success: true, data: SCOPES },
    { updatedAt: Date.now() + 60_000 }
  )
  activeClient = queryClient
  render(
    <QueryClientProvider client={queryClient}>
      <I18nextProvider i18n={i18n}>
        <OAuthAppsProvider>
          <OAuthAppsMutateDrawer open onOpenChange={() => undefined} />
        </OAuthAppsProvider>
      </I18nextProvider>
    </QueryClientProvider>
  )
}

afterEach(() => {
  apiClient.get = originalGet
  useAuthStore.getState().auth.reset()
  if (activeClient) {
    activeClient.clear()
    activeClient = null
  }
  localStorage.clear()
})

describe('OAuth apps mutate drawer — admin-only Trusted toggle', () => {
  test('an administrator sees the Trusted application toggle', async () => {
    installScopeFixture()
    renderDrawerAs(ROLE.ADMIN)
    expect(await screen.findByText('Trusted application')).toBeTruthy()
  })

  test('a common user never sees the Trusted application toggle', async () => {
    installScopeFixture()
    renderDrawerAs(ROLE.USER)
    // Wait for the drawer to mount, then assert the admin-only field is absent.
    await screen.findByText('Register application')
    expect(screen.queryByText('Trusted application')).toBeNull()
  })
})
