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
import { useMemo } from 'react'
import { useForm, useWatch } from 'react-hook-form'
import { useTranslation } from 'react-i18next'

import { Dialog } from '@/components/dialog'
import { Button } from '@/components/ui/button'
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
import {
  Select,
  SelectContent,
  SelectGroup,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { Switch } from '@/components/ui/switch'
import type { CustomNavItem, CustomNavOpenMode } from '@/lib/nav-modules'

import {
  SettingsSwitchContent,
  SettingsSwitchItem,
} from '../components/settings-form-layout'
import {
  CUSTOM_NAV_ITEM_FORM_DEFAULT_VALUES,
  customNavItemSchema,
  getCustomNavItemFormSchema,
  type CustomNavItemFormValues,
} from './custom-nav-item-schema'

const CUSTOM_NAV_ITEM_FORM_ID = 'custom-nav-item-form'

type CustomNavItemFormProps = {
  item: CustomNavItem | null
  openModeLabels: Record<CustomNavOpenMode, string>
  onSubmit: (values: CustomNavItemFormValues) => void
}

function CustomNavItemForm(props: CustomNavItemFormProps) {
  const { t } = useTranslation()
  const schema = useMemo(() => getCustomNavItemFormSchema(t), [t])
  const form = useForm<CustomNavItemFormValues>({
    resolver: zodResolver(schema),
    defaultValues: props.item
      ? {
          title: props.item.title,
          href: props.item.href,
          openMode: props.item.openMode,
          requireAuth: props.item.requireAuth,
        }
      : CUSTOM_NAV_ITEM_FORM_DEFAULT_VALUES,
  })
  const openMode = useWatch({ control: form.control, name: 'openMode' })

  const openModeItems = customNavItemSchema.shape.openMode.options.map(
    (mode) => ({ value: mode, label: props.openModeLabels[mode] })
  )
  const linkHints: Record<CustomNavOpenMode, string> = {
    internal: t(
      'An app path such as /pricing, or an http(s) URL. Opens in the same tab.'
    ),
    iframe: t(
      'An http(s) page embedded inside the app. The site must allow being framed.'
    ),
    external: t('An http(s) URL that opens in a new browser tab.'),
  }
  const linkPlaceholders: Record<CustomNavOpenMode, string> = {
    internal: '/pricing',
    iframe: 'https://example.com/embed',
    external: 'https://example.com',
  }

  return (
    <Form {...form}>
      <form
        id={CUSTOM_NAV_ITEM_FORM_ID}
        onSubmit={form.handleSubmit(props.onSubmit)}
        className='space-y-4'
      >
        <FormField
          control={form.control}
          name='title'
          render={({ field }) => (
            <FormItem>
              <FormLabel>{t('Title')}</FormLabel>
              <FormControl>
                <Input
                  placeholder={t('Status page')}
                  autoComplete='off'
                  {...field}
                />
              </FormControl>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name='openMode'
          render={({ field }) => (
            <FormItem>
              <FormLabel>{t('Open mode')}</FormLabel>
              <Select
                items={openModeItems}
                value={field.value}
                onValueChange={(value) => {
                  field.onChange(value)
                  // The link rules depend on the mode, so re-check a link
                  // that was already typed instead of leaving a stale verdict.
                  if (form.getValues('href') !== '') void form.trigger('href')
                }}
              >
                <FormControl>
                  <SelectTrigger className='w-full'>
                    <SelectValue />
                  </SelectTrigger>
                </FormControl>
                <SelectContent alignItemWithTrigger={false}>
                  <SelectGroup>
                    {openModeItems.map((item) => (
                      <SelectItem key={item.value} value={item.value}>
                        {item.label}
                      </SelectItem>
                    ))}
                  </SelectGroup>
                </SelectContent>
              </Select>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name='href'
          render={({ field }) => (
            <FormItem>
              <FormLabel>{t('Link')}</FormLabel>
              <FormControl>
                <Input
                  placeholder={linkPlaceholders[openMode]}
                  autoComplete='off'
                  {...field}
                />
              </FormControl>
              <FormDescription>{linkHints[openMode]}</FormDescription>
              <FormMessage />
            </FormItem>
          )}
        />
        <FormField
          control={form.control}
          name='requireAuth'
          render={({ field }) => (
            <SettingsSwitchItem className='py-0'>
              <SettingsSwitchContent>
                <FormLabel>{t('Require sign-in')}</FormLabel>
                <FormDescription>
                  {t('Visitors must sign in to open this link.')}
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
      </form>
    </Form>
  )
}

type CustomNavItemDialogProps = {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** The item being edited, or `null` when adding a new one. */
  item: CustomNavItem | null
  openModeLabels: Record<CustomNavOpenMode, string>
  onSubmit: (values: CustomNavItemFormValues) => void
}

export function CustomNavItemDialog(props: CustomNavItemDialogProps) {
  const { t } = useTranslation()
  const isEditing = props.item !== null

  return (
    <Dialog
      open={props.open}
      onOpenChange={props.onOpenChange}
      title={isEditing ? t('Edit navigation item') : t('Add navigation item')}
      description={t('Choose where the link goes and how it opens.')}
      contentClassName='max-w-xl'
      footer={
        <>
          <Button
            type='button'
            variant='outline'
            onClick={() => props.onOpenChange(false)}
          >
            {t('Cancel')}
          </Button>
          <Button type='submit' form={CUSTOM_NAV_ITEM_FORM_ID}>
            {isEditing ? t('Update') : t('Add')}
          </Button>
        </>
      }
    >
      {/* Remounted per target so each open starts from that item's values. */}
      <CustomNavItemForm
        key={props.item?.id ?? 'new'}
        item={props.item}
        openModeLabels={props.openModeLabels}
        onSubmit={props.onSubmit}
      />
    </Dialog>
  )
}
