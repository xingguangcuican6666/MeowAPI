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

import { useTranslation } from 'react-i18next'

import { CopyButton } from '@/components/copy-button'
import { Dialog } from '@/components/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'

import { useOAuthApps } from './oauth-apps-provider'

export function OAuthClientSecretDialog() {
  const { t } = useTranslation()
  const { open, setOpen, revealedSecret, setRevealedSecret } = useOAuthApps()

  if (open !== 'secret' || !revealedSecret) return null

  const handleClose = () => {
    setRevealedSecret(null)
    setOpen(null)
  }

  return (
    <Dialog
      open
      onOpenChange={(isOpen) => {
        if (!isOpen) handleClose()
      }}
      title={t('Client secret')}
      description={t(
        "Save this client secret now. You won't be able to view it again after closing this dialog."
      )}
      contentClassName='sm:max-w-md'
      contentHeight='auto'
      footer={<Button onClick={handleClose}>{t('Close')}</Button>}
    >
      <div className='space-y-4 py-2'>
        <div className='space-y-2'>
          <Label htmlFor='oauth-client-id'>{t('Client ID')}</Label>
          <div className='flex gap-2'>
            <Input
              id='oauth-client-id'
              value={revealedSecret.clientId}
              readOnly
              autoComplete='off'
              className='font-mono text-xs'
            />
            <CopyButton
              value={revealedSecret.clientId}
              variant='outline'
              tooltip={t('Copy client ID')}
              aria-label={t('Copy client ID')}
            />
          </div>
        </div>
        <div className='space-y-2'>
          <Label htmlFor='oauth-client-secret'>{t('Client secret')}</Label>
          <div className='flex gap-2'>
            <Input
              id='oauth-client-secret'
              value={revealedSecret.secret}
              readOnly
              autoComplete='off'
              className='font-mono text-xs'
            />
            <CopyButton
              value={revealedSecret.secret}
              variant='outline'
              tooltip={t('Copy client secret')}
              aria-label={t('Copy client secret')}
            />
          </div>
        </div>
      </div>
    </Dialog>
  )
}
