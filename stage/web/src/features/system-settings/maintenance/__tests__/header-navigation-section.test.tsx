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
  cleanup,
  render,
  screen,
  waitFor,
  within,
} from '@testing-library/react'
import userEvent, { type UserEvent } from '@testing-library/user-event'
import { useState } from 'react'
import { afterEach, describe, expect, it, vi, type MockInstance } from 'vitest'

import { api } from '@/lib/api'
import { CUSTOM_NAV_MAX_ITEMS } from '@/lib/nav-modules'

import { SettingsPageProvider } from '../../components/settings-page-context'
import { parseHeaderNavModules, serializeHeaderNavModules } from '../config'
import { HeaderNavigationSection } from '../header-navigation-section'

const clients: QueryClient[] = []

const statusItem = {
  id: 'custom-status',
  title: 'Status page',
  href: 'https://status.example.com',
  openMode: 'external',
  requireAuth: false,
}

const guideItem = {
  id: 'custom-guide',
  title: 'Pricing guide',
  href: '/pricing',
  openMode: 'internal',
  requireAuth: true,
}

const INTERNAL_LINK_ERROR =
  'Enter an app path starting with / (for example /pricing) or a valid http(s) URL.'
const URL_ERROR = 'Enter a valid http(s) URL.'

afterEach(() => {
  cleanup()
  clients.forEach((client) => client.clear())
  clients.length = 0
  vi.restoreAllMocks()
})

function Fixture(props: { stored: object; docsLink: string }) {
  const [actionsContainer, setActionsContainer] =
    useState<HTMLDivElement | null>(null)
  // Parsed once: the section resets its form whenever `config` changes.
  const [config] = useState(() =>
    parseHeaderNavModules(JSON.stringify(props.stored))
  )

  return (
    <>
      <div ref={setActionsContainer} />
      <SettingsPageProvider
        actionsContainer={actionsContainer}
        suppressSectionHeader={false}
      >
        <HeaderNavigationSection
          config={config}
          initialSerialized={serializeHeaderNavModules(config)}
          docsLink={props.docsLink}
        />
      </SettingsPageProvider>
    </>
  )
}

async function renderSection(stored: object = {}, docsLink = '') {
  const put = vi.spyOn(api, 'put').mockResolvedValue({
    data: { success: true, message: '' },
  })
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  clients.push(client)
  render(
    <QueryClientProvider client={client}>
      <Fixture stored={stored} docsLink={docsLink} />
    </QueryClientProvider>
  )
  await screen.findByRole('button', { name: 'Save navigation' })
  return { put, user: userEvent.setup() }
}

type PutMock = MockInstance<typeof api.put>
type OptionBody = { key: string; value: string }

// The option endpoint is only ever called with a { key, value } body.
function savedBodies(put: PutMock) {
  return put.mock.calls.map((args) => args[1] as OptionBody)
}

function savedCall(put: PutMock, key: string) {
  return savedBodies(put).find((body) => body.key === key)
}

function savedNavigation(put: PutMock) {
  const body = savedCall(put, 'HeaderNavModules')
  expect(body, 'HeaderNavModules was not saved').toBeDefined()
  return JSON.parse(String(body?.value))
}

async function openAddDialog(user: UserEvent) {
  await user.click(screen.getByRole('button', { name: 'Add item' }))
  return screen.findByRole('dialog', { name: 'Add navigation item' })
}

async function chooseOpenMode(
  user: UserEvent,
  dialog: HTMLElement,
  name: string
) {
  await user.click(within(dialog).getByRole('combobox', { name: 'Open mode' }))
  await user.click(await screen.findByRole('option', { name }))
}

async function waitForDialogToClose() {
  await waitFor(() =>
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument()
  )
}

describe('custom navigation items', () => {
  it('lists nothing for a legacy config saved before custom items existed', async () => {
    await renderSection({ home: true, docs: false })

    expect(
      screen.getByText(
        'No custom navigation items yet. Click "Add item" to create one.'
      )
    ).toBeInTheDocument()
    expect(
      screen.getByText(`0 of ${CUSTOM_NAV_MAX_ITEMS} items used`)
    ).toBeInTheDocument()
  })

  it('adds an item from the dialog and keeps it as a draft until Save is pressed', async () => {
    const { put, user } = await renderSection()

    // An unsaved edit elsewhere in the section: the dialog's own form must
    // not submit it (nesting the dialog inside the settings form would).
    await user.click(screen.getByRole('switch', { name: 'About' }))
    const dialog = await openAddDialog(user)
    await user.type(
      within(dialog).getByRole('textbox', { name: 'Title' }),
      'Status page'
    )
    await chooseOpenMode(user, dialog, 'New tab')
    await user.type(
      within(dialog).getByRole('textbox', { name: 'Link' }),
      'https://status.example.com'
    )
    await user.click(
      within(dialog).getByRole('switch', { name: 'Require sign-in' })
    )
    await user.click(within(dialog).getByRole('button', { name: 'Add' }))
    await waitForDialogToClose()

    const row = within(screen.getByRole('table')).getByRole('row', {
      name: /Status page/,
    })
    expect(row).toHaveTextContent('https://status.example.com')
    expect(row).toHaveTextContent('New tab')
    expect(put).not.toHaveBeenCalled()

    await user.click(screen.getByRole('button', { name: 'Save navigation' }))

    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(savedNavigation(put)).toMatchObject({
      about: false,
      customItems: [
        {
          id: expect.stringMatching(/^custom-[a-z0-9]+-[a-z0-9]*$/),
          title: 'Status page',
          href: 'https://status.example.com',
          openMode: 'external',
          requireAuth: true,
        },
      ],
    })
  })

  it('edits an item in place and keeps its id and position', async () => {
    const { put, user } = await renderSection({
      customItems: [statusItem, guideItem],
    })

    await user.click(screen.getByRole('button', { name: 'Edit Status page' }))
    const dialog = await screen.findByRole('dialog', {
      name: 'Edit navigation item',
    })
    const title = within(dialog).getByRole('textbox', { name: 'Title' })
    expect(title).toHaveValue('Status page')
    expect(within(dialog).getByRole('textbox', { name: 'Link' })).toHaveValue(
      'https://status.example.com'
    )
    expect(
      within(dialog).getByRole('combobox', { name: 'Open mode' })
    ).toHaveTextContent('New tab')
    await user.clear(title)
    await user.type(title, 'System status')
    await user.click(within(dialog).getByRole('button', { name: 'Update' }))
    await waitForDialogToClose()
    await user.click(screen.getByRole('button', { name: 'Save navigation' }))

    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(savedNavigation(put).customItems).toEqual([
      { ...statusItem, title: 'System status' },
      guideItem,
    ])
  })

  it('starts each dialog from the values of the item it was opened for', async () => {
    const { user } = await renderSection({
      customItems: [statusItem, guideItem],
    })

    await user.click(screen.getByRole('button', { name: 'Edit Status page' }))
    let dialog = await screen.findByRole('dialog')
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    await waitForDialogToClose()

    await user.click(screen.getByRole('button', { name: 'Edit Pricing guide' }))
    dialog = await screen.findByRole('dialog')
    expect(within(dialog).getByRole('textbox', { name: 'Title' })).toHaveValue(
      'Pricing guide'
    )
    expect(within(dialog).getByRole('textbox', { name: 'Link' })).toHaveValue(
      '/pricing'
    )
    expect(
      within(dialog).getByRole('switch', { name: 'Require sign-in' })
    ).toBeChecked()
    await user.click(within(dialog).getByRole('button', { name: 'Cancel' }))
    await waitForDialogToClose()

    dialog = await openAddDialog(user)
    expect(within(dialog).getByRole('textbox', { name: 'Title' })).toHaveValue(
      ''
    )
    expect(within(dialog).getByRole('textbox', { name: 'Link' })).toHaveValue(
      ''
    )
    expect(
      within(dialog).getByRole('switch', { name: 'Require sign-in' })
    ).not.toBeChecked()
  })

  it('keeps an item when its delete confirmation is cancelled', async () => {
    const { put, user } = await renderSection({ customItems: [statusItem] })

    await user.click(
      screen.getByRole('button', { name: 'Open menu for Status page' })
    )
    await user.click(await screen.findByRole('menuitem', { name: 'Delete' }))
    const confirm = await screen.findByRole('alertdialog', {
      name: 'Delete navigation item?',
    })
    await user.click(within(confirm).getByRole('button', { name: 'Cancel' }))

    await waitFor(() =>
      expect(screen.queryByRole('alertdialog')).not.toBeInTheDocument()
    )
    expect(
      within(screen.getByRole('table')).getByText('Status page')
    ).toBeInTheDocument()
    expect(put).not.toHaveBeenCalled()
  })

  it('removes an item once the delete is confirmed and saves without it', async () => {
    const { put, user } = await renderSection({
      customItems: [statusItem, guideItem],
    })

    await user.click(
      screen.getByRole('button', { name: 'Open menu for Status page' })
    )
    await user.click(await screen.findByRole('menuitem', { name: 'Delete' }))
    const confirm = await screen.findByRole('alertdialog', {
      name: 'Delete navigation item?',
    })
    expect(confirm).toHaveTextContent('"Status page" will be removed')
    await user.click(within(confirm).getByRole('button', { name: 'Delete' }))

    await waitFor(() =>
      expect(
        within(screen.getByRole('table')).queryByText('Status page')
      ).not.toBeInTheDocument()
    )
    expect(put).not.toHaveBeenCalled()
    await user.click(screen.getByRole('button', { name: 'Save navigation' }))

    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(savedNavigation(put).customItems).toEqual([guideItem])
  })

  it('explains what is missing instead of adding an empty item', async () => {
    const { put, user } = await renderSection()

    const dialog = await openAddDialog(user)
    await user.click(within(dialog).getByRole('button', { name: 'Add' }))

    expect(
      await within(dialog).findByText('Please enter a title')
    ).toBeInTheDocument()
    expect(within(dialog).getByText('Please enter a link')).toBeInTheDocument()
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    expect(put).not.toHaveBeenCalled()
  })

  it('refuses a script link and adds nothing', async () => {
    const { user } = await renderSection()

    const dialog = await openAddDialog(user)
    await user.type(
      within(dialog).getByRole('textbox', { name: 'Title' }),
      'Bad link'
    )
    const link = within(dialog).getByRole('textbox', { name: 'Link' })
    await user.type(link, 'javascript:alert(1)')
    await user.click(within(dialog).getByRole('button', { name: 'Add' }))

    expect(
      await within(dialog).findByText(INTERNAL_LINK_ERROR)
    ).toBeInTheDocument()
    expect(link).toHaveAttribute('aria-invalid', 'true')
    expect(screen.getByRole('dialog')).toBeInTheDocument()
    // The page behind a modal dialog is inert, so look it up as hidden.
    expect(
      within(screen.getByRole('table', { hidden: true })).queryByText(
        'Bad link'
      )
    ).not.toBeInTheDocument()
  })

  it('re-checks a typed link when the open mode changes', async () => {
    const { user } = await renderSection()

    const dialog = await openAddDialog(user)
    await user.type(
      within(dialog).getByRole('textbox', { name: 'Title' }),
      'Pricing'
    )
    const link = within(dialog).getByRole('textbox', { name: 'Link' })
    await user.type(link, '/pricing')
    expect(link).not.toHaveAttribute('aria-invalid', 'true')

    await chooseOpenMode(user, dialog, 'Embedded page (iframe)')

    expect(await within(dialog).findByText(URL_ERROR)).toBeInTheDocument()
    expect(link).toHaveAttribute('aria-invalid', 'true')
  })

  it('never lists or re-saves a stored link with an unsafe scheme', async () => {
    const { put, user } = await renderSection({
      customItems: [{ ...statusItem, href: 'javascript:alert(1)' }, guideItem],
    })

    const table = screen.getByRole('table')
    expect(within(table).queryByText('Status page')).not.toBeInTheDocument()
    expect(within(table).getByText('Pricing guide')).toBeInTheDocument()

    await user.click(screen.getByRole('switch', { name: 'About' }))
    await user.click(screen.getByRole('button', { name: 'Save navigation' }))

    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(savedNavigation(put).customItems).toEqual([guideItem])
  })

  it('disables Add once the item limit is reached', async () => {
    const items = Array.from({ length: CUSTOM_NAV_MAX_ITEMS }, (_, index) => ({
      id: `custom-item-${index}`,
      title: `Item ${index}`,
      href: `/page-${index}`,
      openMode: 'internal',
      requireAuth: false,
    }))
    await renderSection({ customItems: items })

    expect(
      screen.getByText(
        `${CUSTOM_NAV_MAX_ITEMS} of ${CUSTOM_NAV_MAX_ITEMS} items used`
      )
    ).toBeInTheDocument()
    expect(screen.getByRole('button', { name: 'Add item' })).toBeDisabled()
  })

  it('resets custom items with the other defaults but keeps the typed docs link', async () => {
    const { put, user } = await renderSection(
      { docs: false, customItems: [statusItem] },
      'https://docs.example.com'
    )
    expect(screen.getByRole('switch', { name: 'Docs' })).not.toBeChecked()

    await user.click(screen.getByRole('button', { name: 'Reset to default' }))

    expect(
      within(screen.getByRole('table')).queryByText('Status page')
    ).not.toBeInTheDocument()
    expect(screen.getByRole('switch', { name: 'Docs' })).toBeChecked()
    expect(
      screen.getByRole('textbox', { name: 'Documentation Link' })
    ).toHaveValue('https://docs.example.com')
    expect(put).not.toHaveBeenCalled()

    await user.click(screen.getByRole('button', { name: 'Save navigation' }))

    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(savedNavigation(put)).toMatchObject({ docs: true, customItems: [] })
  })
})

describe('documentation link', () => {
  it('shows the stored link and saves a changed one through its own option', async () => {
    const { put, user } = await renderSection({}, 'https://docs.example.com')
    const input = screen.getByRole('textbox', { name: 'Documentation Link' })
    expect(input).toHaveValue('https://docs.example.com')

    await user.clear(input)
    await user.type(input, '  https://help.example.com/guide  ')
    await user.click(screen.getByRole('button', { name: 'Save navigation' }))

    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(put).toHaveBeenCalledWith('/api/option/', {
      key: 'general_setting.docs_link',
      value: 'https://help.example.com/guide',
    })
  })

  it('leaves the link option alone when only the navigation changed', async () => {
    const { put, user } = await renderSection({}, 'https://docs.example.com')

    await user.click(screen.getByRole('switch', { name: 'About' }))
    await user.click(screen.getByRole('button', { name: 'Save navigation' }))

    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(savedCall(put, 'general_setting.docs_link')).toBeUndefined()
    expect(savedNavigation(put).about).toBe(false)
  })

  it('saves nothing when nothing changed', async () => {
    const { put, user } = await renderSection(
      { customItems: [statusItem] },
      'https://docs.example.com'
    )

    await user.click(screen.getByRole('button', { name: 'Save navigation' }))

    await waitFor(() =>
      expect(
        screen.getByRole('button', { name: 'Save navigation' })
      ).toBeEnabled()
    )
    expect(put).not.toHaveBeenCalled()
  })

  it.each([
    'javascript:alert(1)',
    'ftp://files.example.com',
    'docs.example.com',
  ])('refuses %s and saves nothing', async (link) => {
    const { put, user } = await renderSection()
    const input = screen.getByRole('textbox', { name: 'Documentation Link' })

    await user.type(input, link)
    await user.click(screen.getByRole('button', { name: 'Save navigation' }))

    expect(await screen.findByText(URL_ERROR)).toBeInTheDocument()
    expect(input).toHaveAttribute('aria-invalid', 'true')
    expect(put).not.toHaveBeenCalled()
  })

  it('can be cleared to fall back to the default documentation', async () => {
    const { put, user } = await renderSection({}, 'https://docs.example.com')

    await user.clear(
      screen.getByRole('textbox', { name: 'Documentation Link' })
    )
    await user.click(screen.getByRole('button', { name: 'Save navigation' }))

    await waitFor(() => expect(put).toHaveBeenCalledTimes(1))
    expect(put).toHaveBeenCalledWith('/api/option/', {
      key: 'general_setting.docs_link',
      value: '',
    })
  })

  it('saves the navigation first and then the link when both changed', async () => {
    const { put, user } = await renderSection({}, 'https://docs.example.com')

    await user.click(screen.getByRole('switch', { name: 'About' }))
    const input = screen.getByRole('textbox', { name: 'Documentation Link' })
    await user.clear(input)
    await user.type(input, 'https://help.example.com')
    await user.click(screen.getByRole('button', { name: 'Save navigation' }))

    await waitFor(() => expect(put).toHaveBeenCalledTimes(2))
    expect(savedBodies(put).map((body) => body.key)).toEqual([
      'HeaderNavModules',
      'general_setting.docs_link',
    ])
  })
})
