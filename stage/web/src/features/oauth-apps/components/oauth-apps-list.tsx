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
import {
  AppWindow,
  Pencil,
  Power,
  PowerOff,
  RefreshCcw,
  Trash2,
} from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'

import { CopyButton } from '@/components/copy-button'
import { DataTableRowActionMenu } from '@/components/data-table/core/row-action-menu'
import { StatusBadge } from '@/components/status-badge'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import {
  DropdownMenuItem,
  DropdownMenuSeparator,
  DropdownMenuShortcut,
} from '@/components/ui/dropdown-menu'
import {
  Empty,
  EmptyDescription,
  EmptyHeader,
  EmptyMedia,
  EmptyTitle,
} from '@/components/ui/empty'
import { Skeleton } from '@/components/ui/skeleton'
import { handleServerError } from '@/lib/handle-server-error'
import { requireServerSuccess } from '@/lib/server-error-message'

import { getOAuthClients, updateOAuthClient } from '../api'
import {
  ERROR_MESSAGES,
  OAUTH_APP_STATUS,
  OAUTH_APP_STATUSES,
  OAUTH_CLIENTS_QUERY_KEY,
  SUCCESS_MESSAGES,
} from '../constants'
import {
  isHttpUrl,
  transformClientToFormDefaults,
  transformFormToPayload,
} from '../lib'
import type { OAuthClient } from '../types'
import { useOAuthApps } from './oauth-apps-provider'

const OAUTH_APPS_SKELETON_IDS = Array.from(
  { length: 3 },
  (_, index) => `oauth-app-skeleton-${index + 1}`
)

function OAuthAppCard({ client }: { client: OAuthClient }) {
  const { t } = useTranslation()
  const { setOpen, setCurrentRow, triggerRefresh } = useOAuthApps()
  const [isTogglingStatus, setIsTogglingStatus] = useState(false)

  const statusConfig = OAUTH_APP_STATUSES[client.status]
  const isEnabled = client.status === OAUTH_APP_STATUS.ENABLED
  const logo = client.logo ?? ''
  const showLogo = Boolean(logo) && isHttpUrl(logo)
  const scopes = client.scopes ?? []

  const handleToggleStatus = async () => {
    const newStatus = isEnabled
      ? OAUTH_APP_STATUS.DISABLED
      : OAUTH_APP_STATUS.ENABLED

    setIsTogglingStatus(true)
    try {
      const payload = transformFormToPayload({
        ...transformClientToFormDefaults(client),
        status: newStatus,
      })
      const result = await updateOAuthClient(client.id, payload)
      if (result.success) {
        toast.success(
          t(
            isEnabled
              ? SUCCESS_MESSAGES.OAUTH_APP_DISABLED
              : SUCCESS_MESSAGES.OAUTH_APP_ENABLED
          )
        )
        triggerRefresh()
      } else {
        handleServerError(result, t(ERROR_MESSAGES.UPDATE_FAILED))
      }
    } catch (error) {
      handleServerError(error, t(ERROR_MESSAGES.UNEXPECTED))
    } finally {
      setIsTogglingStatus(false)
    }
  }

  return (
    <Card data-card-hover='false' className='gap-3 p-4'>
      <div className='flex items-start justify-between gap-3'>
        <div className='flex min-w-0 items-start gap-3'>
          {showLogo ? (
            <img
              src={logo}
              alt=''
              className='size-10 shrink-0 rounded-md border object-contain'
            />
          ) : (
            <div className='bg-muted text-muted-foreground flex size-10 shrink-0 items-center justify-center rounded-md border'>
              <AppWindow className='size-5' />
            </div>
          )}
          <div className='min-w-0 space-y-1'>
            <h4 className='truncate text-sm font-semibold'>{client.name}</h4>
            <div className='flex items-center gap-1'>
              <span className='text-muted-foreground font-mono text-xs break-all'>
                {client.client_id}
              </span>
              <CopyButton
                value={client.client_id}
                size='icon'
                variant='ghost'
                tooltip={t('Copy client ID')}
                aria-label={t('Copy client ID')}
              />
            </div>
          </div>
        </div>
        <div className='flex shrink-0 items-center gap-2'>
          {statusConfig && (
            <StatusBadge
              label={t(statusConfig.label)}
              variant={statusConfig.variant}
              copyable={false}
            />
          )}
          <DataTableRowActionMenu
            ariaLabel={t('Open menu')}
            contentClassName='w-[200px]'
            modal={false}
          >
            <DropdownMenuItem
              onClick={() => {
                setCurrentRow(client)
                setOpen('update')
              }}
            >
              {t('Edit')}
              <DropdownMenuShortcut>
                <Pencil size={16} />
              </DropdownMenuShortcut>
            </DropdownMenuItem>
            <DropdownMenuItem
              disabled={isTogglingStatus}
              onClick={() => void handleToggleStatus()}
            >
              {isEnabled ? t('Disable') : t('Enable')}
              <DropdownMenuShortcut>
                {isEnabled ? <PowerOff size={16} /> : <Power size={16} />}
              </DropdownMenuShortcut>
            </DropdownMenuItem>
            {!client.is_public && (
              <DropdownMenuItem
                onClick={() => {
                  setCurrentRow(client)
                  setOpen('rotate')
                }}
              >
                {t('Regenerate secret')}
                <DropdownMenuShortcut>
                  <RefreshCcw size={16} />
                </DropdownMenuShortcut>
              </DropdownMenuItem>
            )}
            <DropdownMenuSeparator />
            <DropdownMenuItem
              onClick={() => {
                setCurrentRow(client)
                setOpen('delete')
              }}
              className='text-destructive focus:text-destructive'
            >
              {t('Delete')}
              <DropdownMenuShortcut>
                <Trash2 size={16} />
              </DropdownMenuShortcut>
            </DropdownMenuItem>
          </DataTableRowActionMenu>
        </div>
      </div>
      {client.description ? (
        <p className='text-muted-foreground line-clamp-2 text-xs'>
          {client.description}
        </p>
      ) : null}

      <div className='flex flex-wrap items-center gap-1.5'>
        <Badge variant={client.is_public ? 'secondary' : 'outline'}>
          {client.is_public ? t('Public client') : t('Confidential client')}
        </Badge>
        {scopes.map((scope) => (
          <Badge key={scope} variant='outline' className='font-mono'>
            {scope}
          </Badge>
        ))}
      </div>
    </Card>
  )
}

export function OAuthAppsList() {
  const { t } = useTranslation()
  const { data, isPending, isError, isFetching, refetch } = useQuery({
    queryKey: OAUTH_CLIENTS_QUERY_KEY,
    queryFn: async () => requireServerSuccess(await getOAuthClients()),
  })

  if (isPending) {
    return (
      <div
        role='status'
        aria-label={t('Loading...')}
        className='grid gap-4 sm:grid-cols-2 xl:grid-cols-3'
      >
        {OAUTH_APPS_SKELETON_IDS.map((id) => (
          <Skeleton key={id} className='h-40 w-full rounded-xl' />
        ))}
      </div>
    )
  }

  if (isError) {
    return (
      <div
        role='alert'
        className='flex flex-col items-center justify-center gap-3 py-12'
      >
        <span className='text-destructive text-sm'>
          {t(ERROR_MESSAGES.LOAD_FAILED)}
        </span>
        <Button
          type='button'
          variant='outline'
          disabled={isFetching}
          onClick={() => void refetch()}
        >
          {t('Retry')}
        </Button>
      </div>
    )
  }

  const clients = data.data ?? []

  if (!clients.length) {
    return (
      <Empty>
        <EmptyHeader>
          <EmptyMedia variant='icon'>
            <AppWindow className='size-6' />
          </EmptyMedia>
          <EmptyTitle>{t('No OAuth applications yet')}</EmptyTitle>
          <EmptyDescription>
            {t(
              'Register a third-party application to let users sign in with their new-api account.'
            )}
          </EmptyDescription>
        </EmptyHeader>
      </Empty>
    )
  }

  return (
    <div className='grid gap-4 sm:grid-cols-2 xl:grid-cols-3'>
      {clients.map((client) => (
        <OAuthAppCard key={client.id} client={client} />
      ))}
    </div>
  )
}
