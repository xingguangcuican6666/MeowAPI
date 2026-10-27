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

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import { AppWindow } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { Button } from '@/components/ui/button'
import { Card } from '@/components/ui/card'
import { Separator } from '@/components/ui/separator'
import {
  getOAuthAuthorizations,
  revokeOAuthAuthorization,
} from '@/features/profile/api'
import type { OAuthAuthorization } from '@/features/profile/types'
import dayjs from '@/lib/dayjs'
import { handleServerError } from '@/lib/handle-server-error'
import { createServerError } from '@/lib/server-error-message'

const authorizationsQueryKey = ['security', 'oauth-authorizations'] as const

/** Logos are rendered as <img>, so only allow http(s) sources. */
function isHttpUrl(value: string): boolean {
  try {
    const { protocol } = new URL(value.trim())
    return protocol === 'http:' || protocol === 'https:'
  } catch {
    return false
  }
}

export function AuthorizedApplicationsCard() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [revokeTarget, setRevokeTarget] = useState<OAuthAuthorization | null>(
    null
  )

  const query = useQuery({
    queryKey: authorizationsQueryKey,
    queryFn: async () => {
      const response = await getOAuthAuthorizations()
      if (!response.success) {
        throw createServerError(
          response,
          t('Failed to load connected applications')
        )
      }
      return response.data ?? []
    },
    // Additive card: never surface a toast for a section the user cannot see.
    meta: { errorToast: false },
  })

  const revokeMutation = useMutation({
    mutationFn: async (clientId: string) => {
      const response = await revokeOAuthAuthorization(clientId)
      if (!response.success) {
        throw createServerError(response, t('Failed to disconnect application'))
      }
    },
    onSuccess: async () => {
      setRevokeTarget(null)
      toast.success(t('Application disconnected and its API keys removed'))
      await queryClient.invalidateQueries({ queryKey: authorizationsQueryKey })
    },
    onError: (error: Error) => handleServerError(error),
  })

  const authorizations = query.data ?? []
  // Stay invisible unless the user actually has connected applications.
  if (query.isPending || query.isError || authorizations.length === 0) {
    return null
  }

  return (
    <>
      <Card data-card-hover='false' className='gap-3 p-3 sm:p-4'>
        <div className='space-y-1'>
          <h4 className='text-sm font-semibold'>
            {t('Connected applications')}
          </h4>
          <p className='text-muted-foreground text-xs'>
            {t(
              'Third-party applications you have allowed to sign in with your new-api account.'
            )}
          </p>
        </div>
        <div className='flex flex-col'>
          {authorizations.map((authorization, index) => {
            const scopeSummary = authorization.scope_details
              .map((scope) => scope.title || scope.name)
              .join(', ')
            return (
              <div key={authorization.client_id}>
                {index > 0 && <Separator className='my-3' />}
                <div className='flex items-start gap-3'>
                  {isHttpUrl(authorization.client.logo) ? (
                    <img
                      src={authorization.client.logo}
                      alt=''
                      className='size-9 shrink-0 rounded-lg border object-contain'
                    />
                  ) : (
                    <div className='bg-muted text-muted-foreground flex size-9 shrink-0 items-center justify-center rounded-lg border'>
                      <AppWindow className='size-5' aria-hidden='true' />
                    </div>
                  )}
                  <div className='min-w-0 flex-1 space-y-1'>
                    <div className='flex flex-wrap items-center justify-between gap-2'>
                      <p className='truncate text-sm font-medium'>
                        {authorization.client.name}
                      </p>
                      <Button
                        size='sm'
                        variant='outline'
                        className='text-destructive hover:text-destructive'
                        disabled={revokeMutation.isPending}
                        onClick={() => setRevokeTarget(authorization)}
                      >
                        {t('Disconnect')}
                      </Button>
                    </div>
                    {scopeSummary ? (
                      <p className='text-muted-foreground text-xs'>
                        {t('Access: {{scopes}}', { scopes: scopeSummary })}
                      </p>
                    ) : null}
                    <p className='text-muted-foreground text-xs'>
                      {t('Authorized on {{date}}', {
                        date: dayjs
                          .unix(authorization.created_at)
                          .format('YYYY-MM-DD HH:mm'),
                      })}
                    </p>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      </Card>

      <ConfirmDialog
        open={revokeTarget !== null}
        onOpenChange={(open) => {
          if (!open && !revokeMutation.isPending) setRevokeTarget(null)
        }}
        title={t('Disconnect application?')}
        desc={t(
          'Disconnecting {{name}} immediately revokes its access and deletes any API keys it created for you. The gateway removes those keys itself, not the application. You can reconnect it later by authorizing again.',
          { name: revokeTarget?.client.name ?? '' }
        )}
        confirmText={t('Disconnect')}
        destructive
        isLoading={revokeMutation.isPending}
        handleConfirm={() => {
          if (revokeTarget) revokeMutation.mutate(revokeTarget.client_id)
        }}
      />
    </>
  )
}
