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
import {
  createMemoryHistory,
  createRootRoute,
  createRouter,
  RouterProvider,
} from '@tanstack/react-router'
import { cleanup, render, screen } from '@testing-library/react'
import i18next from 'i18next'
import { I18nextProvider } from 'react-i18next'
import { afterEach, describe, expect, it } from 'vitest'

import { AccountSuspendedError } from '../account-suspended'

const i18n = i18next.createInstance()
void i18n.init({
  lng: 'en',
  resources: { en: { translation: {} } },
  fallbackLng: 'en',
  nsSeparator: false,
  interpolation: { escapeValue: false },
})

const client = new QueryClient({
  defaultOptions: { queries: { retry: false } },
})

afterEach(() => {
  cleanup()
  client.clear()
})

async function renderPage() {
  const router = createRouter({
    routeTree: createRootRoute({ component: AccountSuspendedError }),
    history: createMemoryHistory({ initialEntries: ['/account-suspended'] }),
  })
  await router.load()
  return render(
    <QueryClientProvider client={client}>
      <I18nextProvider i18n={i18n}>
        <RouterProvider router={router} />
      </I18nextProvider>
    </QueryClientProvider>
  )
}

describe('account-suspended page', () => {
  it('states the ban with the one message the backend also returns', async () => {
    await renderPage()

    const heading = await screen.findByRole('heading', { level: 1 })
    expect(heading).toHaveTextContent('Your account has been suspend!')
  })

  it('is a page landmark so assistive technology can jump to the verdict', async () => {
    const view = await renderPage()
    expect(view.container.querySelector('main')).not.toBeNull()
    expect(view.container.querySelector('header')).not.toBeNull()
  })

  it('explains that the credentials were revoked and only an administrator can restore them', async () => {
    const view = await renderPage()

    expect(
      screen.getByText(
        'Your access has been suspended by an administrator. All login sessions and API keys for this account were revoked, and it can no longer sign in or place requests.'
      )
    ).toBeVisible()

    const reasons = view.container.querySelector('ol')
    expect(reasons).not.toBeNull()
    expect(reasons).toHaveTextContent(
      'An administrator set this account to disabled, so authentication is refused on every path.'
    )
    expect(reasons).toHaveTextContent(
      'Login sessions, access tokens and API keys belonging to this account stopped working at the moment it was disabled.'
    )
    expect(reasons).toHaveTextContent(
      'Only an administrator can re-enable the account. Retrying the sign-in form will keep failing until that happens.'
    )
  })

  it('lists what the visitor can do', async () => {
    await renderPage()

    expect(
      screen.getByRole('heading', { name: 'What you can do:' })
    ).toBeVisible()
    expect(screen.getByText('Contact your administrator')).toBeVisible()
  })

  it('offers a way to another account and a way back home', async () => {
    await renderPage()

    const anotherAccount = screen.getByRole('button', {
      name: 'Sign in with another account',
    })
    expect(anotherAccount).toHaveAttribute('href', '/sign-in')

    const home = screen.getByRole('link', { name: /Back to Home/ })
    expect(home).toHaveAttribute('href', '/')
  })

  it('does not offer a retry of the refused sign-in', async () => {
    await renderPage()

    // Retrying the same account cannot succeed, so the page must not invite the
    // visitor into a loop — only the other-account and home paths.
    expect(screen.queryByRole('textbox')).toBeNull()
    expect(screen.queryByLabelText(/Password/)).toBeNull()
  })
})
