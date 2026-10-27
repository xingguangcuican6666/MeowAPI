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

import { useState } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { handleServerError } from '@/lib/handle-server-error'

import { rotateOAuthClientSecret } from '../api'
import { ERROR_MESSAGES, SUCCESS_MESSAGES } from '../constants'
import { OAuthAppsDeleteDialog } from './oauth-apps-delete-dialog'
import { OAuthAppsMutateDrawer } from './oauth-apps-mutate-drawer'
import { useOAuthApps } from './oauth-apps-provider'
import { OAuthClientSecretDialog } from './oauth-client-secret-dialog'

export function OAuthAppsDialogs() {
  const { t } = useTranslation()
  const { open, setOpen, currentRow, triggerRefresh, setRevealedSecret } =
    useOAuthApps()
  const [isRotating, setIsRotating] = useState(false)

  const handleRotate = async () => {
    if (!currentRow) return

    setIsRotating(true)
    try {
      const result = await rotateOAuthClientSecret(currentRow.id)
      if (result.success && result.data) {
        toast.success(t(SUCCESS_MESSAGES.SECRET_ROTATED))
        setRevealedSecret({
          clientId: result.data.client.client_id,
          secret: result.data.secret,
        })
        setOpen('secret')
        triggerRefresh()
      } else {
        handleServerError(result, t(ERROR_MESSAGES.ROTATE_FAILED))
      }
    } catch (error) {
      handleServerError(error, t(ERROR_MESSAGES.UNEXPECTED))
    } finally {
      setIsRotating(false)
    }
  }

  return (
    <>
      <OAuthAppsMutateDrawer
        open={open === 'create' || open === 'update'}
        onOpenChange={(isOpen) => !isOpen && setOpen(null)}
        currentRow={open === 'update' ? currentRow : null}
      />
      <OAuthAppsDeleteDialog />
      <OAuthClientSecretDialog />
      <ConfirmDialog
        open={open === 'rotate'}
        onOpenChange={(isOpen) => {
          if (!isOpen && !isRotating) setOpen(null)
        }}
        title={t('Regenerate client secret?')}
        desc={t(
          'This immediately invalidates the current client secret. Update the application with the new secret before it can authenticate again.'
        )}
        confirmText={t('Regenerate secret')}
        destructive
        isLoading={isRotating}
        handleConfirm={() => void handleRotate()}
      />
    </>
  )
}
