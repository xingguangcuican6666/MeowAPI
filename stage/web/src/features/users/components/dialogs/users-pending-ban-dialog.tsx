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

import { Dialog } from '@/components/dialog'
import { Button } from '@/components/ui/button'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import { handleServerError } from '@/lib/handle-server-error'
import { cn } from '@/lib/utils'

import { manageUser } from '../../api'

interface UsersPendingBanDialogProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  userId: number
  username: string
  onSuccess: () => void
}

const MAX_GRACE_HOURS = 24 * 30

export function UsersPendingBanDialog(props: UsersPendingBanDialogProps) {
  const { t } = useTranslation()
  const [reasonKind, setReasonKind] = useState<'email_invalid' | 'custom'>(
    'email_invalid'
  )
  const [customReason, setCustomReason] = useState('')
  const [hours, setHours] = useState('24')
  const [loading, setLoading] = useState(false)

  const graceHours = Math.min(Math.max(Number.parseInt(hours, 10) || 24, 1), MAX_GRACE_HOURS)
  const reason = reasonKind === 'custom' ? customReason.trim() : reasonKind

  const handleConfirm = async () => {
    if (!reason) return

    setLoading(true)
    try {
      const result = await manageUser(props.userId, 'pending_ban', {
        reason,
        hours: graceHours,
      })
      if (result.success) {
        toast.success(t('Delayed ban scheduled for {{username}}', { username: props.username }))
        setCustomReason('')
        setHours('24')
        setReasonKind('email_invalid')
        props.onOpenChange(false)
        props.onSuccess()
      } else {
        handleServerError(result, t('Failed to schedule the delayed ban'))
      }
    } catch (error) {
      handleServerError(error, t('Failed to schedule the delayed ban'))
    } finally {
      setLoading(false)
    }
  }

  const reasonOptions = [
    {
      value: 'email_invalid' as const,
      label: t('Invalid email (auto-lifted once the email is fixed)'),
    },
    { value: 'custom' as const, label: t('Custom reason (manual lift only)') },
  ]

  return (
    <Dialog
      open={props.open}
      onOpenChange={props.onOpenChange}
      title={t('Delayed Ban')}
      description={t(
        'The account keeps working for the grace period. It is banned automatically when the deadline passes without a fix, and the pending ban is lifted automatically once the issue is fixed.'
      )}
      contentHeight='auto'
      bodyClassName='space-y-4'
      footer={
        <>
          <Button
            variant='outline'
            onClick={() => props.onOpenChange(false)}
            disabled={loading}
          >
            {t('Cancel')}
          </Button>
          <Button onClick={handleConfirm} disabled={loading || !reason}>
            {t('Delayed Ban')}
          </Button>
        </>
      }
    >
      <div className='grid gap-2'>
        <Label>{t('Reason')}</Label>
        {reasonOptions.map((option) => (
          <button
            key={option.value}
            type='button'
            onClick={() => setReasonKind(option.value)}
            className={cn(
              'border-border hover:bg-muted/50 flex items-start gap-2 rounded-md border p-3 text-left text-sm transition-colors',
              reasonKind === option.value && 'border-primary bg-primary/5'
            )}
          >
            <span
              className={cn(
                'border-primary mt-0.5 size-3.5 shrink-0 rounded-full border-2',
                reasonKind === option.value && 'bg-primary'
              )}
            />
            <span>{option.label}</span>
          </button>
        ))}
      </div>

      {reasonKind === 'custom' && (
        <div className='grid gap-2'>
          <Label htmlFor='pending-ban-reason'>{t('Custom reason')}</Label>
          <Input
            id='pending-ban-reason'
            value={customReason}
            onChange={(event) => setCustomReason(event.target.value)}
            placeholder={t('Describe what the user must fix')}
            maxLength={200}
          />
        </div>
      )}

      <div className='grid gap-2'>
        <Label htmlFor='pending-ban-hours'>{t('Grace period (hours)')}</Label>
        <Input
          id='pending-ban-hours'
          type='number'
          min={1}
          max={MAX_GRACE_HOURS}
          value={hours}
          onChange={(event) => setHours(event.target.value)}
        />
        <p className='text-muted-foreground text-xs'>
          {t('Between 1 and 720 hours. Default is 24 hours.')}
        </p>
      </div>
    </Dialog>
  )
}
