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
import { useQuery } from '@tanstack/react-query'
import { Boxes, KeyRound, ShieldAlert, ShieldCheck } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { useForm, type SubmitErrorHandler } from 'react-hook-form'
import { useTranslation } from 'react-i18next'
import { toast } from 'sonner'

import {
  SideDrawerSection,
  SideDrawerSectionHeader,
  sideDrawerContentClassName,
  sideDrawerFooterClassName,
  sideDrawerFormClassName,
  sideDrawerHeaderClassName,
  sideDrawerSwitchItemClassName,
} from '@/components/drawer-layout'
import { MultiSelect } from '@/components/multi-select'
import { TagInput } from '@/components/tag-input'
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
  Sheet,
  SheetClose,
  SheetContent,
  SheetDescription,
  SheetFooter,
  SheetHeader,
  SheetTitle,
} from '@/components/ui/sheet'
import { Switch } from '@/components/ui/switch'
import { Textarea } from '@/components/ui/textarea'
import { handleServerError } from '@/lib/handle-server-error'
import { ROLE } from '@/lib/roles'
import { requireServerSuccess } from '@/lib/server-error-message'
import { useAuthStore } from '@/stores/auth-store'

import {
  createOAuthClient,
  getOAuthServerScopes,
  updateOAuthClient,
} from '../api'
import {
  ERROR_MESSAGES,
  OAUTH_APP_STATUS,
  SUCCESS_MESSAGES,
} from '../constants'
import {
  getOAuthClientFormSchema,
  type OAuthClientFormValues,
  OAUTH_CLIENT_FORM_DEFAULT_VALUES,
  transformClientToFormDefaults,
  transformFormToPayload,
} from '../lib'
import type { OAuthClient } from '../types'
import { useOAuthApps } from './oauth-apps-provider'

type OAuthAppsMutateDrawerProps = {
  open: boolean
  onOpenChange: (open: boolean) => void
  currentRow?: OAuthClient | null
}

export function OAuthAppsMutateDrawer(props: OAuthAppsMutateDrawerProps) {
  const { t } = useTranslation()
  const currentRow = props.currentRow
  const isUpdate = !!currentRow
  const { triggerRefresh, setOpen, setRevealedSecret } = useOAuthApps()
  const [isSubmitting, setIsSubmitting] = useState(false)
  // The Trusted flag gates the sensitive scopes and is administrator-only; the
  // server ignores it for common callers, so we only surface the toggle to admins.
  const isAdmin = useAuthStore(
    (s) => (s.auth.user?.role ?? ROLE.GUEST) >= ROLE.ADMIN
  )

  const { data: scopesData } = useQuery({
    queryKey: ['oauth-server', 'scopes'],
    queryFn: async () => requireServerSuccess(await getOAuthServerScopes()),
    enabled: props.open,
    staleTime: 5 * 60 * 1000,
  })

  const scopeOptions = useMemo(
    () =>
      (scopesData?.data ?? []).map((scope) => {
        const description = t(scope.description, {
          defaultValue: scope.description,
        })
        return {
          value: scope.name,
          label: t(scope.title || scope.name, {
            defaultValue: scope.title || scope.name,
          }),
          // Flag sensitive scopes both visually (amber shield) and in the
          // accessible hint, so an admin sees the elevated request before granting.
          hint: scope.sensitive
            ? `${description} · ${t('Sensitive')}`
            : description,
          icon: scope.sensitive ? (
            <ShieldAlert className='size-3 text-amber-500' aria-hidden='true' />
          ) : undefined,
        }
      }),
    [scopesData, t]
  )

  const schema = useMemo(() => getOAuthClientFormSchema(t), [t])

  const form = useForm<OAuthClientFormValues>({
    resolver: zodResolver(schema),
    defaultValues: OAUTH_CLIENT_FORM_DEFAULT_VALUES,
  })

  useEffect(() => {
    if (!props.open) return
    form.reset(
      isUpdate && currentRow
        ? transformClientToFormDefaults(currentRow)
        : OAUTH_CLIENT_FORM_DEFAULT_VALUES
    )
  }, [props.open, isUpdate, currentRow, form])

  const onSubmit = async (data: OAuthClientFormValues) => {
    setIsSubmitting(true)
    try {
      const payload = transformFormToPayload(data)
      if (isUpdate && currentRow) {
        const result = await updateOAuthClient(currentRow.id, payload)
        if (result.success) {
          toast.success(t(SUCCESS_MESSAGES.OAUTH_APP_UPDATED))
          props.onOpenChange(false)
          triggerRefresh()
        } else {
          handleServerError(result, t(ERROR_MESSAGES.UPDATE_FAILED))
        }
        return
      }

      const result = await createOAuthClient(payload)
      if (!result.success || !result.data) {
        handleServerError(result, t(ERROR_MESSAGES.CREATE_FAILED))
        return
      }
      toast.success(t(SUCCESS_MESSAGES.OAUTH_APP_CREATED))
      triggerRefresh()
      // Confidential clients receive a secret shown exactly once; hand it off to
      // the reveal dialog. Public clients get an empty secret and just close.
      if (result.data.secret) {
        setRevealedSecret({
          clientId: result.data.client.client_id,
          secret: result.data.secret,
        })
        setOpen('secret')
      } else {
        props.onOpenChange(false)
      }
    } catch (error) {
      handleServerError(error, t(ERROR_MESSAGES.UNEXPECTED))
    } finally {
      setIsSubmitting(false)
    }
  }

  const onInvalid: SubmitErrorHandler<OAuthClientFormValues> = () => {
    toast.error(t('Please fix the highlighted fields before saving'))
  }

  return (
    <Sheet
      open={props.open}
      onOpenChange={(v) => {
        props.onOpenChange(v)
        if (!v) form.reset()
      }}
    >
      <SheetContent
        className={sideDrawerContentClassName('max-w-none sm:!max-w-[620px]')}
      >
        <SheetHeader className={sideDrawerHeaderClassName()}>
          <SheetTitle>
            {isUpdate ? t('Update application') : t('Register application')}
          </SheetTitle>
          <SheetDescription>
            {isUpdate
              ? t(
                  'Update how this application appears and what it may request.'
                )
              : t(
                  'Register a third-party application so users can sign in with their new-api account.'
                )}
          </SheetDescription>
        </SheetHeader>
        <Form {...form}>
          <form
            id='oauth-client-form'
            onSubmit={form.handleSubmit(onSubmit, onInvalid)}
            className={sideDrawerFormClassName('gap-5')}
          >
            <SideDrawerSection>
              <SideDrawerSectionHeader
                title={t('Basic Information')}
                description={t(
                  'How the application appears on the consent screen'
                )}
                icon={<Boxes className='size-4' />}
                iconTone='info'
              />
              <FormField
                control={form.control}
                name='name'
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('Name')}</FormLabel>
                    <FormControl>
                      <Input {...field} placeholder={t('Enter a name')} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name='description'
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('Description')}</FormLabel>
                    <FormControl>
                      <Textarea
                        {...field}
                        rows={3}
                        className='min-h-20 resize-none'
                        placeholder={t('Shown to users on the consent screen')}
                      />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name='logo'
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('Logo URL')}</FormLabel>
                    <FormControl>
                      <Input
                        {...field}
                        inputMode='url'
                        placeholder='https://'
                      />
                    </FormControl>
                    <FormDescription>
                      {t('Optional. An https link to the application logo.')}
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name='homepage'
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('Homepage URL')}</FormLabel>
                    <FormControl>
                      <Input
                        {...field}
                        inputMode='url'
                        placeholder='https://'
                      />
                    </FormControl>
                    <FormDescription>
                      {t(
                        'Optional. Where users can learn more about the application.'
                      )}
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </SideDrawerSection>
            <SideDrawerSection>
              <SideDrawerSectionHeader
                title={t('Redirect & Permissions')}
                description={t(
                  'Where users return after authorizing and what the application may access'
                )}
                icon={<ShieldCheck className='size-4' />}
                iconTone='success'
              />
              <FormField
                control={form.control}
                name='redirect_uris'
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('Redirect URIs')}</FormLabel>
                    <FormControl>
                      <TagInput
                        value={field.value}
                        onChange={field.onChange}
                        placeholder={t('Add a redirect URI and press Enter')}
                      />
                    </FormControl>
                    <FormDescription>
                      {t(
                        'Users are only redirected to an exact match of one of these URIs.'
                      )}
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
              <FormField
                control={form.control}
                name='scopes'
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>{t('Allowed scopes')}</FormLabel>
                    <FormControl>
                      <MultiSelect
                        options={scopeOptions}
                        selected={field.value}
                        onChange={field.onChange}
                        placeholder={t(
                          'Select the scopes this application may request'
                        )}
                      />
                    </FormControl>
                    <FormDescription>
                      {t(
                        'The application may request these scopes; users approve them on the consent screen.'
                      )}
                    </FormDescription>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </SideDrawerSection>
            <SideDrawerSection>
              <SideDrawerSectionHeader
                title={t('Client Type & Status')}
                description={t(
                  'Confidential clients keep a secret; public clients rely on PKCE'
                )}
                icon={<KeyRound className='size-4' />}
                iconTone='primary'
              />
              <FormField
                control={form.control}
                name='is_public'
                render={({ field }) => (
                  <FormItem className={sideDrawerSwitchItemClassName()}>
                    <div className='flex flex-col gap-0.5 pr-4'>
                      <FormLabel className='text-sm'>
                        {t('Public client')}
                      </FormLabel>
                      <FormDescription className='text-xs'>
                        {t(
                          'For apps that cannot keep a secret (SPAs, mobile). PKCE is required and no client secret is issued.'
                        )}
                      </FormDescription>
                    </div>
                    <FormControl>
                      <Switch
                        checked={field.value}
                        onCheckedChange={field.onChange}
                      />
                    </FormControl>
                  </FormItem>
                )}
              />
              {isAdmin && (
                <FormField
                  control={form.control}
                  name='trusted'
                  render={({ field }) => (
                    <FormItem className={sideDrawerSwitchItemClassName()}>
                      <div className='flex flex-col gap-0.5 pr-4'>
                        <FormLabel className='text-sm'>
                          {t('Trusted application')}
                        </FormLabel>
                        <FormDescription className='text-xs'>
                          {t(
                            'Administrator only. Required before this application may request sensitive scopes such as wallet top-up or API key management.'
                          )}
                        </FormDescription>
                      </div>
                      <FormControl>
                        <Switch
                          checked={field.value}
                          onCheckedChange={field.onChange}
                        />
                      </FormControl>
                    </FormItem>
                  )}
                />
              )}
              <FormField
                control={form.control}
                name='status'
                render={({ field }) => (
                  <FormItem className={sideDrawerSwitchItemClassName()}>
                    <div className='flex flex-col gap-0.5 pr-4'>
                      <FormLabel className='text-sm'>{t('Enabled')}</FormLabel>
                      <FormDescription className='text-xs'>
                        {t(
                          'Disabled applications cannot start new authorization flows.'
                        )}
                      </FormDescription>
                    </div>
                    <FormControl>
                      <Switch
                        checked={field.value === OAUTH_APP_STATUS.ENABLED}
                        onCheckedChange={(checked) =>
                          field.onChange(
                            checked
                              ? OAUTH_APP_STATUS.ENABLED
                              : OAUTH_APP_STATUS.DISABLED
                          )
                        }
                      />
                    </FormControl>
                  </FormItem>
                )}
              />
            </SideDrawerSection>
          </form>
        </Form>
        <SheetFooter className={sideDrawerFooterClassName()}>
          <SheetClose
            render={<Button variant='outline' className='w-full sm:w-auto' />}
          >
            {t('Close')}
          </SheetClose>
          <Button
            type='button'
            onClick={form.handleSubmit(onSubmit, onInvalid)}
            disabled={isSubmitting}
            className='w-full sm:w-auto'
          >
            {isSubmitting ? t('Saving...') : t('Save changes')}
          </Button>
        </SheetFooter>
      </SheetContent>
    </Sheet>
  )
}
