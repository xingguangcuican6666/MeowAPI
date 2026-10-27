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

import { useQueryClient } from '@tanstack/react-query'
import { Loader2 } from 'lucide-react'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { Dialog } from '@/components/dialog'
import { Button } from '@/components/ui/button'
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Textarea } from '@/components/ui/textarea'

import { handleConvertChannelToMultiKey } from '../../lib'
import type { Channel } from '../../types'

type ConvertMultiKeyDialogProps = {
  channel: Channel
  open: boolean
  onOpenChange: (open: boolean) => void
}

export function ConvertMultiKeyDialog({
  channel,
  open,
  onOpenChange,
}: ConvertMultiKeyDialogProps) {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [keys, setKeys] = useState('')
  const [mode, setMode] = useState<'random' | 'polling'>('polling')
  const [submitting, setSubmitting] = useState(false)

  const keyCount = keys
    .split('\n')
    .filter((key) => key.trim() !== '').length

  const handleConfirm = async () => {
    if (submitting || keyCount === 0) return
    setSubmitting(true)
    try {
      await handleConvertChannelToMultiKey(
        channel.id,
        { keys, multi_key_mode: mode },
        queryClient,
        () => {
          setKeys('')
          onOpenChange(false)
        }
      )
    } finally {
      setSubmitting(false)
    }
  }

  return (
    <Dialog
      open={open}
      onOpenChange={onOpenChange}
      title={t('Convert to Multi-Key Channel')}
      description={t(
        'Append keys to "{{name}}" and enable multi-key mode. The existing key is kept.',
        { name: channel.name }
      )}
      footer={
        <>
          <Button
            variant='outline'
            onClick={() => onOpenChange(false)}
            disabled={submitting}
          >
            {t('Cancel')}
          </Button>
          <Button onClick={handleConfirm} disabled={submitting || keyCount === 0}>
            {submitting ? (
              <Loader2 className='mr-2 h-4 w-4 animate-spin' />
            ) : null}
            {t('Convert')}
          </Button>
        </>
      }
    >
      <div className='space-y-4'>
        <div className='space-y-2'>
          <span className='text-muted-foreground text-xs font-medium'>
            {t('Additional Keys')}
          </span>
          <Textarea
            value={keys}
            onChange={(e) => setKeys(e.target.value)}
            placeholder={t('Enter API keys, one per line')}
            rows={6}
          />
          <p className='text-muted-foreground text-xs'>
            {t('{{count}} new keys will be appended', { count: keyCount })}
          </p>
        </div>

        <div className='space-y-2'>
          <span className='text-muted-foreground text-xs font-medium'>
            {t('Multi-Key Strategy')}
          </span>
          <Select
            items={[
              { value: 'random', label: t('Random') },
              { value: 'polling', label: t('Polling') },
            ]}
            value={mode}
            onValueChange={(v) => {
              if (v === 'random' || v === 'polling') setMode(v)
            }}
          >
            <SelectTrigger>
              <SelectValue />
            </SelectTrigger>
            <SelectContent alignItemWithTrigger={false}>
              <SelectGroup>
                <SelectItem value='random'>{t('Random')}</SelectItem>
                <SelectItem value='polling'>{t('Polling')}</SelectItem>
              </SelectGroup>
            </SelectContent>
          </Select>
          <p className='text-muted-foreground text-xs'>
            {mode === 'polling'
              ? t(
                  'Polling mode requires Redis and memory cache, otherwise performance will be significantly degraded'
                )
              : t('Randomly select a key from the pool for each request')}
          </p>
        </div>
      </div>
    </Dialog>
  )
}
