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

import { Link } from '@tanstack/react-router'
import { Home, Mail, ShieldOff } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { FadeIn } from '@/components/page-transition'
import { Button } from '@/components/ui/button'
import {
  Item,
  ItemContent,
  ItemDescription,
  ItemGroup,
  ItemMedia,
  ItemTitle,
} from '@/components/ui/item'
import { Skeleton } from '@/components/ui/skeleton'
import { useSystemConfig } from '@/hooks/use-system-config'

/**
 * Full-page account state shown to a banned user.
 *
 * Serves both entry points with one composition: a user who is refused at
 * sign-in and a user whose account is disabled while they are using the
 * dashboard. The page is public — a banned user holds no usable session, so it
 * must not live behind the authenticated layout, and it deliberately offers no
 * way to retry the same credentials: that attempt is certain to fail again.
 *
 * The look follows the editorial style of the project's own `anthropic` theme
 * preset (warm cream canvas, ink serif headline, clay accent), scoped to this
 * page via `data-theme-preset` so it holds even when the site runs a different
 * preset. The preset block only redefines CSS custom properties, and those
 * inherit into every element below this root, so `bg-background` /
 * `text-primary` / `font-serif` resolve to the preset values without touching
 * global state or the visitor's own theme choice.
 *
 * Branding comes from the site's configured logo and system name: a banned
 * visitor still needs to know which site is refusing them.
 */
export function AccountSuspendedError() {
  const { t } = useTranslation()
  const { systemName, logo, loading } = useSystemConfig()

  return (
    <main
      data-theme-preset='anthropic'
      className='bg-background text-foreground flex min-h-svh w-full flex-col'
    >
      <header className='flex items-center justify-between gap-3 px-4 py-4 sm:px-8 sm:py-5'>
        <Link to='/' className='flex min-w-0 items-center gap-2.5'>
          {loading ? (
            <Skeleton className='size-7 shrink-0 rounded-full' />
          ) : (
            <img
              src={logo}
              alt=''
              aria-hidden='true'
              className='size-7 shrink-0 rounded-full object-cover'
            />
          )}
          {loading ? (
            <Skeleton className='h-5 w-24' />
          ) : (
            <span className='truncate text-base font-medium'>{systemName}</span>
          )}
        </Link>
        <span className='text-primary bg-primary/10 inline-flex shrink-0 items-center gap-1.5 rounded-lg px-2.5 py-1.5 text-[11px] font-semibold tracking-wide uppercase'>
          <ShieldOff className='size-3.5' aria-hidden='true' />
          {t('Account status')}
        </span>
      </header>

      <FadeIn className='flex w-full flex-1 justify-center px-4 pt-8 pb-20 sm:px-6'>
        <div className='flex w-full max-w-xl flex-col items-center'>
          <span
            aria-hidden='true'
            className='bg-muted text-muted-foreground flex size-12 items-center justify-center rounded-xl'
          >
            <ShieldOff className='size-5' />
          </span>

          {/* Same wording the backend returns in `auth.user_banned`, so a user
              who arrives here from a refused sign-in reads one message rather
              than two different phrasings of the same verdict. A real heading,
              not `EmptyTitle`: this is a full-page verdict, so the document
              outline needs it. */}
          <h1 className='font-serif mt-7 text-center text-[1.7rem] leading-snug font-semibold text-balance sm:text-[2.1rem]'>
            {t('Your account has been suspend!')}
          </h1>

          <p className='text-muted-foreground mt-5 text-center text-[0.95rem] leading-relaxed text-balance'>
            {t(
              'Your access has been suspended by an administrator. All login sessions and API keys for this account were revoked, and it can no longer sign in or place requests.'
            )}
          </p>

          <ol className='text-muted-foreground mt-6 w-full list-decimal space-y-3 ps-5 text-sm leading-relaxed marker:text-muted-foreground/70'>
            <li>
              {t(
                'An administrator set this account to disabled, so authentication is refused on every path.'
              )}
            </li>
            <li>
              {t(
                'Login sessions, access tokens and API keys belonging to this account stopped working at the moment it was disabled.'
              )}
            </li>
            <li>
              {t(
                'Only an administrator can re-enable the account. Retrying the sign-in form will keep failing until that happens.'
              )}
            </li>
          </ol>

          <Button
            size='lg'
            className='bg-foreground text-background hover:bg-foreground/85 mt-9 h-10 w-full rounded-xl sm:w-auto sm:px-7'
            render={<Link to='/sign-in' />}
          >
            {t('Sign in with another account')}
          </Button>

          <h2 className='mt-14 w-full text-left text-sm font-semibold'>
            {t('What you can do:')}
          </h2>
          <ItemGroup className='mt-3 w-full gap-2.5'>
            <Item variant='outline' className='rounded-xl px-4 py-3'>
              <ItemMedia variant='icon' className='text-muted-foreground'>
                <Mail aria-hidden='true' />
              </ItemMedia>
              <ItemContent>
                <ItemTitle>{t('Contact your administrator')}</ItemTitle>
                <ItemDescription className='line-clamp-none'>
                  {t(
                    'Ask the administrator of this site why the account was disabled and what is needed to restore it.'
                  )}
                </ItemDescription>
              </ItemContent>
            </Item>
            <Item
              variant='outline'
              className='rounded-xl px-4 py-3'
              render={<Link to='/' />}
            >
              <ItemMedia variant='icon' className='text-muted-foreground'>
                <Home aria-hidden='true' />
              </ItemMedia>
              <ItemContent>
                <ItemTitle>{t('Back to Home')}</ItemTitle>
                <ItemDescription className='line-clamp-none'>
                  {t('Return to the site homepage.')}
                </ItemDescription>
              </ItemContent>
            </Item>
          </ItemGroup>
        </div>
      </FadeIn>
    </main>
  )
}
