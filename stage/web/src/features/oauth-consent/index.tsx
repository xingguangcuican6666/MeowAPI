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

import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, AppWindow, Check, Loader2, X } from 'lucide-react'
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'

import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { handleServerError } from '@/lib/handle-server-error'
import { requireServerSuccess } from '@/lib/server-error-message'
import { cn } from '@/lib/utils'

import {
  approveOAuthConsent,
  denyOAuthConsent,
  getOAuthConsentContext,
} from './api'

/** Logos and homepages are rendered in the UI, so restrict them to http(s). */
function isHttpUrl(value: string): boolean {
  try {
    const { protocol } = new URL(value.trim())
    return protocol === 'http:' || protocol === 'https:'
  } catch {
    return false
  }
}

function ConsentShell({ children }: { children: ReactNode }) {
  return (
    <div className='flex min-h-full items-center justify-center p-4'>
      <Card className='w-full max-w-md gap-5 p-6 sm:p-8'>{children}</Card>
    </div>
  )
}

function ConsentStatus({ label }: { label: string }) {
  return (
    <div
      role='status'
      className='flex flex-col items-center justify-center gap-3 py-8 text-center'
    >
      <Loader2 className='text-muted-foreground size-8 animate-spin' />
      <p className='text-muted-foreground text-sm'>{label}</p>
    </div>
  )
}

function ConsentError({
  title,
  description,
  onRetry,
  retrying,
}: {
  title: string
  description: string
  onRetry?: () => void
  retrying?: boolean
}) {
  const { t } = useTranslation()
  return (
    <div
      role='alert'
      className='flex flex-col items-center gap-3 py-4 text-center'
    >
      <div className='bg-destructive/10 text-destructive flex size-12 items-center justify-center rounded-full'>
        <X className='size-6' />
      </div>
      <div className='space-y-1'>
        <h2 className='text-base font-semibold'>{title}</h2>
        <p className='text-muted-foreground text-sm'>{description}</p>
      </div>
      {onRetry ? (
        <Button
          type='button'
          variant='outline'
          disabled={retrying}
          onClick={onRetry}
        >
          {t('Retry')}
        </Button>
      ) : null}
    </div>
  )
}

export function OAuthConsent({ request }: { request: string }) {
  const { t } = useTranslation()
  const hasRequest = request.trim() !== ''
  const [pendingAction, setPendingAction] = useState<'approve' | 'deny' | null>(
    null
  )
  const autoApprovedRef = useRef(false)

  const { data, isPending, isError, isFetching, refetch } = useQuery({
    queryKey: ['oauth-server', 'authorize-context', request],
    queryFn: async () =>
      requireServerSuccess(await getOAuthConsentContext(request)),
    enabled: hasRequest,
    retry: false,
    meta: { errorToast: false },
  })

  const context = data?.data

  const submit = useCallback(
    async (decision: 'approve' | 'deny') => {
      setPendingAction(decision)
      try {
        const result =
          decision === 'approve'
            ? await approveOAuthConsent(request)
            : await denyOAuthConsent(request)
        if (result.success && result.data?.redirect_uri) {
          // The redirect target is the external client's registered URI; leave
          // the SPA entirely rather than navigating within the router.
          window.location.href = result.data.redirect_uri
          return
        }
        handleServerError(result, t('Failed to complete authorization'))
        setPendingAction(null)
      } catch (error) {
        handleServerError(error, t('An unexpected error occurred'))
        setPendingAction(null)
      }
    },
    [request, t]
  )

  // Skip the prompt when the user already granted these scopes to this client.
  useEffect(() => {
    if (context?.already_authorized && !autoApprovedRef.current) {
      autoApprovedRef.current = true
      void submit('approve')
    }
  }, [context, submit])

  if (!hasRequest) {
    return (
      <ConsentShell>
        <ConsentError
          title={t('Missing authorization request')}
          description={t('This authorization link is invalid or has expired.')}
        />
      </ConsentShell>
    )
  }

  if (isPending) {
    return (
      <ConsentShell>
        <ConsentStatus label={t('Loading authorization request...')} />
      </ConsentShell>
    )
  }

  if (isError || !context) {
    return (
      <ConsentShell>
        <ConsentError
          title={t('Unable to load authorization request')}
          description={t('This authorization link is invalid or has expired.')}
          onRetry={() => void refetch()}
          retrying={isFetching}
        />
      </ConsentShell>
    )
  }

  if (context.already_authorized || pendingAction !== null) {
    return (
      <ConsentShell>
        <ConsentStatus
          label={t('Redirecting you back to the application...')}
        />
      </ConsentShell>
    )
  }

  const client = context.client
  const showLogo = Boolean(client.logo) && isHttpUrl(client.logo)
  const showHomepage = Boolean(client.homepage) && isHttpUrl(client.homepage)
  const hasSensitiveScope = context.scopes.some((scope) => scope.sensitive)

  return (
    <ConsentShell>
      <div className='flex flex-col items-center gap-3 text-center'>
        {showLogo ? (
          <img
            src={client.logo}
            alt=''
            className='size-14 rounded-xl border object-contain'
          />
        ) : (
          <div className='bg-muted text-muted-foreground flex size-14 items-center justify-center rounded-xl border'>
            <AppWindow className='size-7' />
          </div>
        )}
        <div className='space-y-1'>
          <h1 className='text-lg font-semibold break-words'>
            {t('Authorize {{name}}', { name: client.name })}
          </h1>
          <p className='text-muted-foreground text-sm'>
            {t('{{name}} wants to sign you in with your new-api account.', {
              name: client.name,
            })}
          </p>
        </div>
      </div>

      {client.description ? (
        <p className='text-muted-foreground border-t pt-4 text-center text-sm'>
          {client.description}
        </p>
      ) : null}

      <div className='space-y-3'>
        <p className='text-sm font-medium'>
          {t('This will allow the application to:')}
        </p>
        {hasSensitiveScope ? (
          <div
            role='alert'
            className='flex items-start gap-2.5 rounded-lg border border-amber-300 bg-amber-50 p-3 text-amber-900 dark:border-amber-800 dark:bg-amber-950/40 dark:text-amber-100'
          >
            <AlertTriangle className='mt-0.5 size-4 shrink-0 text-amber-600 dark:text-amber-400' />
            <p className='text-sm'>
              {t(
                'This application is requesting sensitive permissions. Only continue if you trust it.'
              )}
            </p>
          </div>
        ) : null}
        <ul className='space-y-2.5'>
          {context.scopes.map((scope) => {
            const ScopeIcon = scope.sensitive ? AlertTriangle : Check
            return (
              <li key={scope.name} className='flex items-start gap-2.5'>
                <ScopeIcon
                  className={cn(
                    'mt-0.5 size-4 shrink-0',
                    scope.sensitive
                      ? 'text-amber-600 dark:text-amber-400'
                      : 'text-primary'
                  )}
                />
                <div className='min-w-0 space-y-0.5'>
                  <p
                    className={cn(
                      'text-sm font-medium',
                      scope.sensitive && 'text-amber-700 dark:text-amber-400'
                    )}
                  >
                    {t(scope.title || scope.name, {
                      defaultValue: scope.title || scope.name,
                    })}
                  </p>
                  {scope.description ? (
                    <p className='text-muted-foreground text-xs'>
                      {t(scope.description, {
                        defaultValue: scope.description,
                      })}
                    </p>
                  ) : null}
                </div>
              </li>
            )
          })}
        </ul>
      </div>

      {showHomepage ? (
        <a
          href={client.homepage}
          target='_blank'
          rel='noopener noreferrer'
          className='text-primary text-center text-xs hover:underline'
        >
          {t('Learn more about this application')}
        </a>
      ) : null}

      <div className='flex flex-col gap-2 pt-1 sm:flex-row-reverse'>
        <Button
          type='button'
          className='w-full sm:flex-1'
          disabled={pendingAction !== null}
          onClick={() => void submit('approve')}
        >
          {t('Authorize')}
        </Button>
        <Button
          type='button'
          variant='outline'
          className='w-full sm:flex-1'
          disabled={pendingAction !== null}
          onClick={() => void submit('deny')}
        >
          {t('Cancel')}
        </Button>
      </div>
    </ConsentShell>
  )
}
