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

import { Loader2, SlidersHorizontal } from 'lucide-react'
import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'

import { Dialog } from '@/components/dialog'
import { StatusBadge, type StatusVariant } from '@/components/status-badge'
import { Button } from '@/components/ui/button'

import { testChannelRatioProbe } from '../../api'
import {
  RATIO_PROBE_STATUS_COMPLIANT,
  RATIO_PROBE_STATUS_ERROR,
  RATIO_PROBE_STATUS_REJECTED,
  RATIO_PROBE_STATUS_UNCONFIGURED,
} from '../../constants'
import type {
  ChannelRatioProbeResponse,
  ChannelRatioProbeResult,
} from '../../types'
import { useChannels } from '../channels-provider'

type RatioProbeDialogProps = {
  open: boolean
  onOpenChange: (open: boolean) => void
}

const RATIO_PROBE_STATUS_LABELS: Record<string, string> = {
  [RATIO_PROBE_STATUS_COMPLIANT]: 'Compliant',
  [RATIO_PROBE_STATUS_REJECTED]: 'Rejected',
  [RATIO_PROBE_STATUS_ERROR]: 'Probe failed',
  [RATIO_PROBE_STATUS_UNCONFIGURED]: 'Not configured',
}

function getStatusVariant(status: string): StatusVariant {
  if (status === RATIO_PROBE_STATUS_COMPLIANT) return 'success'
  if (status === RATIO_PROBE_STATUS_UNCONFIGURED) return 'neutral'
  return 'danger'
}

function formatRatio(ratio: number | undefined): string {
  if (typeof ratio !== 'number' || !Number.isFinite(ratio)) return '—'
  return `${ratio}x`
}

function getResultLabel(
  result: ChannelRatioProbeResult,
  translate: (key: string, options?: Record<string, unknown>) => string
): string {
  if (result.key_index == null) return translate('Channel')
  return `${translate('Key')} ${result.key_index}`
}

function RatioProbeResults({
  data,
  translate,
}: {
  data: NonNullable<ChannelRatioProbeResponse['data']>
  translate: (key: string, options?: Record<string, unknown>) => string
}) {
  if (data.results.length === 0) {
    return (
      <p className='text-muted-foreground py-8 text-center text-sm'>
        {translate('No data')}
      </p>
    )
  }

  return (
    <div className='divide-border divide-y overflow-hidden rounded-lg border'>
      {data.results.map((result) => {
        const statusLabel =
          RATIO_PROBE_STATUS_LABELS[result.status] ||
          RATIO_PROBE_STATUS_LABELS.error

        return (
          <div
            key={
              result.key_index == null ? 'channel' : `key-${result.key_index}`
            }
            className='flex items-start justify-between gap-4 p-3'
          >
            <div className='min-w-0 space-y-1'>
              <div className='flex flex-wrap items-center gap-2'>
                <span className='text-sm font-medium'>
                  {getResultLabel(result, translate)}
                </span>
                <StatusBadge
                  label={translate(statusLabel)}
                  variant={getStatusVariant(result.status)}
                  copyable={false}
                />
              </div>
              {result.message && (
                <p className='text-muted-foreground text-xs break-words'>
                  {result.message}
                </p>
              )}
            </div>
            <div className='shrink-0 text-end'>
              <div className='text-muted-foreground text-xs'>
                {translate('Group ratio')}
              </div>
              <div className='font-mono text-sm font-medium'>
                {formatRatio(result.ratio)}
              </div>
            </div>
          </div>
        )
      })}
    </div>
  )
}

export function RatioProbeDialog(props: RatioProbeDialogProps) {
  const { t } = useTranslation()
  const { currentRow } = useChannels()
  const [isTesting, setIsTesting] = useState(false)
  const [testData, setTestData] = useState<NonNullable<
    ChannelRatioProbeResponse['data']
  > | null>(null)
  const requestIdRef = useRef(0)
  const autoTestChannelIdRef = useRef<number | null>(null)
  const channelId = currentRow?.id

  const runProbe = useCallback(async () => {
    if (channelId == null) return

    const requestId = ++requestIdRef.current
    setIsTesting(true)
    setTestData(null)
    try {
      const response = await testChannelRatioProbe(channelId)
      if (requestId !== requestIdRef.current) return
      if (!response.success || !response.data) {
        toast.error(response.message || t('Failed to test channel'))
        return
      }
      setTestData(response.data)
    } catch (error: unknown) {
      if (requestId !== requestIdRef.current) return
      toast.error(
        error instanceof Error ? error.message : t('Failed to test channel')
      )
    } finally {
      if (requestId === requestIdRef.current) {
        setIsTesting(false)
      }
    }
  }, [channelId, t])

  useEffect(() => {
    if (!props.open || channelId == null) {
      autoTestChannelIdRef.current = null
      return
    }
    if (autoTestChannelIdRef.current === channelId) return

    autoTestChannelIdRef.current = channelId
    void runProbe()
  }, [channelId, props.open, runProbe])

  const handleClose = () => {
    requestIdRef.current += 1
    autoTestChannelIdRef.current = null
    setIsTesting(false)
    setTestData(null)
    props.onOpenChange(false)
  }

  let dialogContent: ReactNode
  if (isTesting) {
    dialogContent = (
      <div className='flex items-center justify-center py-12'>
        <Loader2 className='text-muted-foreground size-8 animate-spin' />
      </div>
    )
  } else if (testData) {
    dialogContent = (
      <div className='space-y-4'>
        <div className='bg-muted/50 flex items-center justify-between gap-3 rounded-lg border p-4'>
          <div className='min-w-0'>
            <div className='text-muted-foreground text-xs'>{t('Group')}</div>
            <div className='truncate font-mono text-sm font-medium'>
              {testData.group}
            </div>
          </div>
          {!testData.configured && (
            <StatusBadge
              label={t('Not configured')}
              variant='neutral'
              copyable={false}
            />
          )}
        </div>
        <RatioProbeResults data={testData} translate={t} />
      </div>
    )
  } else {
    dialogContent = (
      <p className='text-muted-foreground py-8 text-center text-sm'>
        {t('No data')}
      </p>
    )
  }

  if (!currentRow) return null

  return (
    <Dialog
      open={props.open}
      onOpenChange={(open) => {
        if (!open) handleClose()
      }}
      title={t('Upstream Ratio Probe Test')}
      description={
        <>
          {t('Channel')}: <strong>{currentRow.name}</strong>
        </>
      }
      contentClassName='sm:max-w-xl'
      bodyClassName='space-y-4'
      footer={
        <>
          <Button variant='outline' onClick={handleClose}>
            {t('Close')}
          </Button>
          <Button onClick={() => void runProbe()} disabled={isTesting}>
            {isTesting ? (
              <Loader2 className='me-2 size-4 animate-spin' />
            ) : (
              <SlidersHorizontal className='me-2 size-4' />
            )}
            {isTesting ? t('Testing...') : t('Test')}
          </Button>
        </>
      }
    >
      {dialogContent}
    </Dialog>
  )
}
