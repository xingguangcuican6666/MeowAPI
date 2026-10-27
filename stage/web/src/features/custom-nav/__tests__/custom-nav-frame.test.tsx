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
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

import type { CustomNavItem } from '@/lib/nav-modules'

import { CustomNavFrame } from '../components/custom-nav-frame'

const BASE_SANDBOX = [
  'allow-forms',
  'allow-popups',
  'allow-popups-to-escape-sandbox',
  'allow-scripts',
]

function itemFor(href: string): CustomNavItem {
  return {
    id: 'portal',
    title: 'Partner portal',
    href,
    requireAuth: false,
    openMode: 'iframe',
  }
}

function sandboxTokens() {
  const sandbox = screen.getByTitle('Partner portal').getAttribute('sandbox')
  return (sandbox ?? '').split(' ').sort()
}

describe('CustomNavFrame sandbox', () => {
  it('lets cross-origin content keep its own origin', () => {
    render(<CustomNavFrame item={itemFor('https://docs.example.com/guide')} />)
    expect(sandboxTokens()).toEqual(
      [...BASE_SANDBOX, 'allow-same-origin'].sort()
    )
  })

  it('withholds allow-same-origin from same-origin content', () => {
    render(
      <CustomNavFrame
        item={itemFor(`${window.location.origin}/static/page.html?x=1#top`)}
      />
    )
    expect(sandboxTokens()).toEqual([...BASE_SANDBOX].sort())
  })

  it.each([
    [
      'another scheme',
      `${window.location.protocol === 'https:' ? 'http:' : 'https:'}//${window.location.host}/`,
    ],
    [
      'another port',
      `${window.location.protocol}//${window.location.hostname}:65000/`,
    ],
  ])('treats %s on the same host as cross-origin', (_label, href) => {
    render(<CustomNavFrame item={itemFor(href)} />)
    expect(sandboxTokens()).toContain('allow-same-origin')
  })
})

describe('CustomNavFrame frame', () => {
  it('loads the URL in a frame named after the item with a referrer policy', () => {
    render(<CustomNavFrame item={itemFor('https://docs.example.com/guide')} />)
    const frame = screen.getByTitle('Partner portal')
    expect(frame.tagName).toBe('IFRAME')
    expect(frame).toHaveAttribute('src', 'https://docs.example.com/guide')
    expect(frame).toHaveAttribute(
      'referrerpolicy',
      'strict-origin-when-cross-origin'
    )
  })

  it.each([
    'javascript:alert(1)',
    'data:text/html,hello',
    '//example.com/page',
    '/relative/page',
  ])('renders neither a frame nor a link for %s', (href) => {
    const { container } = render(<CustomNavFrame item={itemFor(href)} />)
    expect(container.querySelector('iframe')).toBeNull()
    expect(screen.queryByRole('link')).not.toBeInTheDocument()
  })
})

describe('CustomNavFrame fallback link', () => {
  it('opens the same URL in a new tab without leaking the opener', () => {
    render(<CustomNavFrame item={itemFor('https://docs.example.com/guide')} />)
    const link = screen.getByRole('link', { name: 'Open in new tab' })
    expect(link).toHaveAttribute('href', 'https://docs.example.com/guide')
    expect(link).toHaveAttribute('target', '_blank')
    expect(link).toHaveAttribute('rel', 'noopener noreferrer')
  })

  it('is reachable from the keyboard before the frame', async () => {
    const user = userEvent.setup()
    render(<CustomNavFrame item={itemFor('https://docs.example.com/guide')} />)
    await user.tab()
    expect(screen.getByRole('link', { name: 'Open in new tab' })).toHaveFocus()
  })
})
