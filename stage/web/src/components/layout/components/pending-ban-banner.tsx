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

import { AlertTriangle } from 'lucide-react'
import { useTranslation } from 'react-i18next'

import { Dialog } from '@/components/dialog'
import { useProfile } from '@/features/profile/hooks/use-profile'

export function PendingBanBanner() {
  const { t } = useTranslation('translation')
  const { profile } = useProfile()

  if (!profile?.pending_ban_reason || !profile.pending_ban_deadline) {
    return null
  }

  const deadline = new Date(
    profile.pending_ban_deadline * 1000
  ).toLocaleString()
  const summary = `${t('Your account is scheduled to be banned')}: ${t(
    'Pending fix:'
  )} ${profile.pending_ban_reason}`

  return (
    <div
      role='alert'
      className='relative z-20 w-full border-b border-amber-300 bg-amber-50 text-amber-950 dark:border-amber-800 dark:bg-amber-950/50 dark:text-amber-100'
    >
      <Dialog
        title={t('Your account is scheduled to be banned')}
        showCloseButton
        trigger={
          <button
            type='button'
            className='flex h-9 w-full items-center gap-2 px-4 text-left text-sm hover:bg-amber-100 focus-visible:ring-2 focus-visible:ring-amber-600 focus-visible:outline-none focus-visible:ring-inset dark:hover:bg-amber-900/50'
          >
            <AlertTriangle className='size-4 shrink-0' aria-hidden='true' />
            <span className='min-w-0 flex-1 truncate'>{summary}</span>
            <span className='shrink-0 font-medium' aria-hidden='true'>
              -&gt;
            </span>
          </button>
        }
      >
        <div className='space-y-3 text-sm'>
          <p>
            <span className='font-medium'>{t('Pending fix:')}</span>{' '}
            {profile.pending_ban_reason}
          </p>
          <p>
            <span className='font-medium'>{t('Deadline:')}</span> {deadline}
          </p>
          <p>
            {t('If the issue is not fixed before')} {deadline}
            {t(
              ', the account will be banned automatically. The pending ban is lifted automatically once the issue is fixed.'
            )}
          </p>
        </div>
      </Dialog>
    </div>
  )
}
