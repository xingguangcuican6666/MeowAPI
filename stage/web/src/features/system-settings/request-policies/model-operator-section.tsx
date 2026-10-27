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

import { Braces, ListFilter, Plus, Trash2 } from 'lucide-react'
import { useMemo, useState } from 'react'
import { useFormContext, useWatch } from 'react-hook-form'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'

import { ConfirmDialog } from '@/components/confirm-dialog'
import { StaticDataTable } from '@/components/data-table'
import { EmptyState } from '@/components/empty-state'
import { JsonCodeEditor } from '@/components/json-code-editor'
import { StatusBadge } from '@/components/status-badge'
import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import { Combobox } from '@/components/ui/combobox'
import { FormField } from '@/components/ui/form'
import { Label } from '@/components/ui/label'
import { Separator } from '@/components/ui/separator'
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs'

import { CHANNEL_STATUS } from '../../channels/constants'
import { SettingsCard } from '../components/settings-card'
import { SettingsSwitchField } from '../components/settings-form-layout'
import type { RoutingPolicyFormValues } from './routing-form'
import { useOperatorChannels, useOperatorModels } from './use-operator-options'

type OperatorRow = {
  model: string
  channelId: number
}

// Rows are the editable view of the stored object map; the JSON tab edits the
// very same string, so both modes share one draft.
function parseOperatorRows(json: string): OperatorRow[] {
  let parsed: unknown
  try {
    parsed = JSON.parse(json)
  } catch {
    return []
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return []
  }
  const rows: OperatorRow[] = []
  for (const [model, channelId] of Object.entries(parsed)) {
    // A row whose model is still blank is one the user is filling, so it stays
    // visible until the schema refuses the save. A malformed id on a named
    // model is left to the JSON tab and the schema instead of becoming an
    // unusable row here.
    if (
      model.trim() === '' ||
      (typeof channelId === 'number' &&
        Number.isInteger(channelId) &&
        channelId > 0)
    ) {
      rows.push({
        model,
        channelId: typeof channelId === 'number' ? channelId : 0,
      })
    }
  }
  return rows
}

function serializeOperatorRows(rows: OperatorRow[]): string {
  const map: Record<string, number> = {}
  for (const row of rows) {
    // A model designates one operator, so a later row replaces an earlier one.
    // A row that is still being filled keeps its blank key so the form schema
    // refuses the save instead of the row silently disappearing.
    map[row.model.trim()] = row.channelId
  }
  return JSON.stringify(map, null, 2)
}

export function ModelOperatorSection(props: {
  mapJson: string
  onMapChange: (value: string) => void
}) {
  const { t } = useTranslation()
  const form = useFormContext<RoutingPolicyFormValues>()
  const enabled = useWatch({
    control: form.control,
    name: 'model_operator_setting.enabled',
  })
  const [editMode, setEditMode] = useState<'visual' | 'json'>('visual')
  const [deletingIndex, setDeletingIndex] = useState<number | null>(null)
  const rows = useMemo(() => parseOperatorRows(props.mapJson), [props.mapJson])
  const channelsQuery = useOperatorChannels()
  const modelsQuery = useOperatorModels()
  const channelNames = useMemo(() => {
    const names = new Map<number, string>()
    for (const channel of channelsQuery.data ?? []) {
      names.set(channel.id, channel.name)
    }
    return names
  }, [channelsQuery.data])

  const emitRows = (next: OperatorRow[]) => {
    props.onMapChange(serializeOperatorRows(next))
  }

  const switchToVisualMode = () => {
    let parsed: unknown
    try {
      parsed = JSON.parse(props.mapJson)
    } catch {
      toast.error(t('Invalid JSON format'))
      return
    }
    if (
      typeof parsed !== 'object' ||
      parsed === null ||
      Array.isArray(parsed)
    ) {
      toast.error(t('Model operator map must be a JSON object'))
      return
    }
    setEditMode('visual')
  }

  const channelOptions = useMemo(() => {
    const options: {
      value: string
      label: string
      disabled: boolean
      description?: string
    }[] = (channelsQuery.data ?? []).map((channel) => ({
      value: String(channel.id),
      label: `#${channel.id} ${channel.name}`,
      disabled: channel.status !== CHANNEL_STATUS.ENABLED,
      description:
        channel.status === CHANNEL_STATUS.ENABLED
          ? undefined
          : t('Unavailable'),
    }))
    // A mapped channel that the list does not contain (deleted, or outside the
    // paged list) stays selectable so its mapping can be corrected in place.
    const known = new Set(options.map((option) => option.value))
    for (const row of rows) {
      const value = String(row.channelId)
      if (known.has(value)) continue
      known.add(value)
      options.push({
        value,
        label: `#${row.channelId}`,
        disabled: true,
        description: t('Not found'),
      })
    }
    return options
  }, [channelsQuery.data, rows, t])

  const deletingRow = deletingIndex === null ? null : rows[deletingIndex]

  return (
    <SettingsCard
      title={t('Sole operator routing')}
      description={t(
        'Pin a model to one channel. Requests try that channel first and reach the other channels only while it is unavailable; models without a mapping keep the default routing.'
      )}
      className='shadow-none'
    >
      <FormField
        control={form.control}
        name='model_operator_setting.enabled'
        render={({ field }) => (
          <SettingsSwitchField
            controlId='model_operator_setting.enabled'
            checked={field.value}
            onCheckedChange={field.onChange}
            label={t('Enable sole operator routing')}
            description={t(
              'Turn off to keep every model on the default routing logic.'
            )}
          />
        )}
      />
      <section
        aria-label={t('Sole operator mappings')}
        className='mt-4 min-w-0'
      >
        <Tabs
          value={editMode}
          onValueChange={(value) => {
            if (value === 'visual') switchToVisualMode()
            else setEditMode('json')
          }}
          className='gap-0'
        >
          <div className='flex flex-wrap items-center justify-between gap-3 pb-3'>
            <TabsList aria-label={t('Operator editor mode')}>
              <TabsTrigger value='visual' className='px-3'>
                <ListFilter aria-hidden='true' />
                {t('Visual')}
              </TabsTrigger>
              <TabsTrigger value='json' className='px-3'>
                <Braces aria-hidden='true' />
                JSON
              </TabsTrigger>
            </TabsList>
            <Button
              variant='outline'
              size='sm'
              disabled={!enabled}
              onClick={() =>
                emitRows([
                  ...rows,
                  { model: '', channelId: channelsQuery.data?.[0]?.id ?? 0 },
                ])
              }
            >
              <Plus aria-hidden='true' data-icon='inline-start' />
              {t('Add Model')}
            </Button>
          </div>
          <Separator />
          <TabsContent value='visual' className='min-w-0'>
            {rows.length === 0 ? (
              <EmptyState
                icon={ListFilter}
                title={t('No models pinned yet')}
                description={t('Add a model to route it through one channel.')}
                className='min-h-56'
              />
            ) : (
              <StaticDataTable
                containerProps={{
                  role: 'region',
                  'aria-label': t('Sole operator table'),
                  tabIndex: 0,
                }}
                tableProps={{ withContainer: false }}
                tableClassName='min-w-[640px] [&_td]:px-4 [&_td]:py-3'
                headerRowClassName='bg-muted/35 hover:bg-muted/35'
                data={rows}
                getRowKey={(_row, index) => index}
                columns={[
                  {
                    id: 'model',
                    header: t('Model'),
                    cell: (row, index) => (
                      <Combobox
                        className='min-w-0'
                        options={(modelsQuery.data ?? []).map((model) => ({
                          value: model,
                          label: model,
                        }))}
                        // A mapping may name a model no channel currently
                        // offers, so custom values keep it editable instead of
                        // forcing it back into the known list.
                        allowCustomValue
                        aria-label={t('Model')}
                        placeholder={t('Model name')}
                        value={row.model}
                        onValueChange={(value) =>
                          emitRows(
                            rows.map((item, itemIndex) =>
                              itemIndex === index
                                ? { ...item, model: value ?? '' }
                                : item
                            )
                          )
                        }
                      />
                    ),
                  },
                  {
                    id: 'channel',
                    header: t('Operator channel'),
                    cell: (row, index) => (
                      <div className='flex min-w-0 items-center gap-2'>
                        <Combobox
                          className='min-w-0'
                          options={channelOptions}
                          aria-label={t('Operator channel')}
                          placeholder={t('Channel')}
                          value={String(row.channelId)}
                          onValueChange={(value) => {
                            const channelId = Number(value)
                            if (
                              !Number.isInteger(channelId) ||
                              channelId <= 0
                            ) {
                              return
                            }
                            emitRows(
                              rows.map((item, itemIndex) =>
                                itemIndex === index
                                  ? { ...item, channelId }
                                  : item
                              )
                            )
                          }}
                        />
                        <StatusBadge
                          variant={
                            channelNames.has(row.channelId)
                              ? 'success'
                              : 'danger'
                          }
                          copyable={false}
                        >
                          {channelNames.get(row.channelId) ??
                            `#${row.channelId}`}
                        </StatusBadge>
                      </div>
                    ),
                  },
                  {
                    id: 'actions',
                    header: t('Actions'),
                    className: 'w-[120px]',
                    cell: (_row, index) => (
                      <div className='flex justify-end'>
                        <Button
                          variant='ghost'
                          size='icon-sm'
                          aria-label={t('Delete Model')}
                          onClick={() => setDeletingIndex(index)}
                        >
                          <Trash2 />
                        </Button>
                      </div>
                    ),
                  },
                ]}
              />
            )}
          </TabsContent>
          <TabsContent value='json' className='min-w-0'>
            <div className='grid gap-2 pt-4'>
              <Label htmlFor='model-operator-map-json'>
                {t('Model operator map JSON')}
              </Label>
              <p className='text-muted-foreground text-xs'>
                {t('Maps a model name to its operator channel id.')}
              </p>
              <JsonCodeEditor
                id='model-operator-map-json'
                value={props.mapJson}
                onChange={props.onMapChange}
                heightClassName='h-[240px] min-h-[240px] max-h-[240px]'
              />
            </div>
          </TabsContent>
        </Tabs>
      </section>
      <div className='text-muted-foreground flex items-center gap-2 pt-3 text-xs'>
        <Badge variant='secondary' className='tabular-nums'>
          {rows.length}
        </Badge>
        <span>
          {rows.length === 1 ? t('model pinned') : t('models pinned')}
        </span>
        {channelsQuery.isPending ? <span>{t('Loading...')}</span> : null}
        {channelsQuery.isError ? (
          <span>{t('Channel list unavailable')}</span>
        ) : null}
        {modelsQuery.isError ? (
          <span>{t('Model list unavailable')}</span>
        ) : null}
      </div>
      {deletingRow !== null && (
        <ConfirmDialog
          open
          onOpenChange={(open) => !open && setDeletingIndex(null)}
          title={t('Delete Model Mapping')}
          desc={t(
            'Delete the operator mapping for “{{model}}”? Save your changes to apply the removal.',
            { model: deletingRow.model }
          )}
          confirmText={t('Delete')}
          handleConfirm={() => {
            emitRows(rows.filter((_row, index) => index !== deletingIndex))
            setDeletingIndex(null)
          }}
          destructive
        />
      )}
    </SettingsCard>
  )
}
