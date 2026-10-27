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

import { LinkSquare01Icon } from '@hugeicons/core-free-icons'
import { HugeiconsIcon } from '@hugeicons/react'
import { useTranslation } from 'react-i18next'

import { ErrorState } from '@/components/error-state'
import { Button } from '@/components/ui/button'
import { isValidCustomNavHref, type CustomNavItem } from '@/lib/nav-modules'

// Deliberately without allow-top-navigation: the framed site stays in its frame.
const FRAME_SANDBOX =
  'allow-forms allow-popups allow-popups-to-escape-sandbox allow-scripts'

type CustomNavFrameProps = {
  item: CustomNavItem
}

/**
 * Sandboxed iframe for an admin-defined top-nav item. Sits below the fixed
 * public header and keeps an "Open in new tab" link in reach, because sites that
 * send X-Frame-Options or CSP frame-ancestors render blank inside a frame.
 */
export function CustomNavFrame(props: CustomNavFrameProps) {
  const { t } = useTranslation()

  // Second line of defence behind the route guard: a non-http(s) href never
  // reaches the iframe or the link.
  const href = props.item.href.trim()
  const frameUrl = isValidCustomNavHref(href, 'iframe') ? new URL(href) : null

  if (!frameUrl) {
    return (
      <main className='flex h-svh flex-col pt-16'>
        <ErrorState />
      </main>
    )
  }

  // Cross-origin content keeps its own origin so the site can use its storage.
  // Same-origin content must not get allow-same-origin: together with
  // allow-scripts it lets the page remove its own sandbox.
  const sandbox =
    frameUrl.origin === window.location.origin
      ? FRAME_SANDBOX
      : `${FRAME_SANDBOX} allow-same-origin`

  return (
    <main className='flex h-svh flex-col pt-16'>
      <div className='flex items-center justify-between gap-3 border-b px-4 py-1.5'>
        <h1 className='min-w-0 truncate text-sm font-medium'>
          {props.item.title}
        </h1>
        <Button
          role='link'
          variant='ghost'
          size='sm'
          className='shrink-0'
          render={
            <a href={frameUrl.href} target='_blank' rel='noopener noreferrer' />
          }
        >
          <HugeiconsIcon icon={LinkSquare01Icon} aria-hidden='true' />
          {t('Open in new tab')}
        </Button>
      </div>
      <iframe
        src={frameUrl.href}
        title={props.item.title}
        sandbox={sandbox}
        referrerPolicy='strict-origin-when-cross-origin'
        className='min-h-0 w-full flex-1 border-0'
      />
    </main>
  )
}
