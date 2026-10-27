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

import { zodResolver } from '@hookform/resolvers/zod'
import { useEffect, useMemo, useRef } from 'react'
import { useForm } from 'react-hook-form'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'
import * as z from 'zod'

import { Alert, AlertDescription } from '@/components/ui/alert'
import {
  Form,
  FormControl,
  FormDescription,
  FormField,
  FormItem,
  FormLabel,
  FormMessage,
} from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { Switch } from '@/components/ui/switch'

import {
  SettingsForm,
  SettingsSwitchContent,
  SettingsSwitchItem,
} from '../components/settings-form-layout'
import { SettingsPageFormActions } from '../components/settings-page-context'
import { SettingsSection } from '../components/settings-section'
import { useUpdateOption } from '../hooks/use-update-option'
import { safeNumberFieldProps } from '../utils/numeric-field'

/**
 * IMPORTANT: react-hook-form 7 interprets dotted `name` strings as nested
 * paths. We model the form internally with a nested object and only flatten
 * back to the server-side `data_capture_setting.*` key format right before
 * persisting, so form state stays in sync with what zod validates and saves.
 */
const dataCaptureSchema = z.object({
  data_capture_setting: z.object({
    enabled: z.boolean(),
    max_body_kb: z.coerce.number().min(1),
    dir: z.string(),
  }),
})

type DataCaptureFormInput = z.input<typeof dataCaptureSchema>
type DataCaptureFormValues = z.output<typeof dataCaptureSchema>

type FlatDataCaptureDefaults = {
  'data_capture_setting.enabled': boolean
  'data_capture_setting.max_body_kb': number
  'data_capture_setting.dir': string
}

const buildFormDefaults = (
  defaults: FlatDataCaptureDefaults
): DataCaptureFormInput => ({
  data_capture_setting: {
    enabled: defaults['data_capture_setting.enabled'],
    max_body_kb: defaults['data_capture_setting.max_body_kb'],
    dir: defaults['data_capture_setting.dir'] ?? '',
  },
})

const normalizeFormValues = (
  values: DataCaptureFormValues
): FlatDataCaptureDefaults => ({
  'data_capture_setting.enabled': values.data_capture_setting.enabled,
  'data_capture_setting.max_body_kb': values.data_capture_setting.max_body_kb,
  'data_capture_setting.dir': values.data_capture_setting.dir ?? '',
})

type DataCaptureSectionProps = {
  defaultValues: FlatDataCaptureDefaults
}

export function DataCaptureSection({ defaultValues }: DataCaptureSectionProps) {
  const { t } = useTranslation()
  const updateOption = useUpdateOption()

  const formDefaults = useMemo(
    () => buildFormDefaults(defaultValues),
    [defaultValues]
  )

  const form = useForm<DataCaptureFormInput, unknown, DataCaptureFormValues>({
    resolver: zodResolver(dataCaptureSchema),
    defaultValues: formDefaults,
  })

  const baselineRef = useRef<FlatDataCaptureDefaults>(defaultValues)
  const baselineSerializedRef = useRef<string>(JSON.stringify(defaultValues))

  useEffect(() => {
    const serialized = JSON.stringify(defaultValues)
    if (serialized === baselineSerializedRef.current) return
    baselineRef.current = defaultValues
    baselineSerializedRef.current = serialized
    form.reset(buildFormDefaults(defaultValues))
  }, [defaultValues, form])

  const onSubmit = async (values: DataCaptureFormValues) => {
    const normalized = normalizeFormValues(values)
    const changedKeys = (
      Object.keys(normalized) as Array<keyof FlatDataCaptureDefaults>
    ).filter((key) => normalized[key] !== baselineRef.current[key])

    if (changedKeys.length === 0) {
      toast.info(t('No changes to save'))
      return
    }

    for (const key of changedKeys) {
      await updateOption.mutateAsync({ key, value: normalized[key] })
    }

    baselineRef.current = normalized
    baselineSerializedRef.current = JSON.stringify(normalized)
    form.reset(buildFormDefaults(normalized))
  }

  return (
    <SettingsSection title={t('Conversation Data Capture')}>
      <Form {...form}>
        <SettingsForm onSubmit={form.handleSubmit(onSubmit)}>
          <SettingsPageFormActions
            onSave={form.handleSubmit(onSubmit)}
            isSaving={updateOption.isPending}
          />

          <Alert>
            <AlertDescription>
              {t(
                'Saves the raw request and response bodies of chat conversations passing through the gateway as JSONL files, for offline training data collection. The captured data contains user prompts and model replies in plaintext.'
              )}
            </AlertDescription>
          </Alert>

          <FormField
            control={form.control}
            name='data_capture_setting.enabled'
            render={({ field }) => (
              <SettingsSwitchItem>
                <SettingsSwitchContent>
                  <FormLabel>{t('Enable Conversation Data Capture')}</FormLabel>
                  <FormDescription>
                    {t(
                      'When enabled, chat/completions-style requests and their responses are written to JSONL files'
                    )}
                  </FormDescription>
                </SettingsSwitchContent>
                <FormControl>
                  <Switch
                    checked={field.value}
                    onCheckedChange={field.onChange}
                  />
                </FormControl>
              </SettingsSwitchItem>
            )}
          />

          <FormField
            control={form.control}
            name='data_capture_setting.max_body_kb'
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('Max body size (KB)')}</FormLabel>
                <FormControl>
                  <Input
                    type='number'
                    min={1}
                    className='max-w-xs'
                    {...safeNumberFieldProps(field)}
                  />
                </FormControl>
                <FormDescription>
                  {t(
                    'Upper limit for each captured request/response body; content beyond this is truncated'
                  )}
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />

          <FormField
            control={form.control}
            name='data_capture_setting.dir'
            render={({ field }) => (
              <FormItem>
                <FormLabel>{t('Output directory')}</FormLabel>
                <FormControl>
                  <Input
                    className='max-w-xl'
                    placeholder={t('Leave empty to use <log dir>/captures')}
                    {...field}
                  />
                </FormControl>
                <FormDescription>
                  {t(
                    'Directory where JSONL capture files are written, rotated daily as captures-YYYY-MM-DD.jsonl'
                  )}
                </FormDescription>
                <FormMessage />
              </FormItem>
            )}
          />
        </SettingsForm>
      </Form>
    </SettingsSection>
  )
}
