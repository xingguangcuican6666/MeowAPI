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

import { SectionPageLayout } from '@/components/layout'

import { OAuthAppsDialogs } from './components/oauth-apps-dialogs'
import { OAuthAppsList } from './components/oauth-apps-list'
import { OAuthAppsPrimaryButtons } from './components/oauth-apps-primary-buttons'
import { OAuthAppsProvider } from './components/oauth-apps-provider'

export function OAuthApps() {
  const { t } = useTranslation()
  return (
    <OAuthAppsProvider>
      <SectionPageLayout fixedContent>
        <SectionPageLayout.Title>
          {t('OAuth Applications')}
        </SectionPageLayout.Title>
        <SectionPageLayout.Actions>
          <OAuthAppsPrimaryButtons />
        </SectionPageLayout.Actions>
        <SectionPageLayout.Content>
          <OAuthAppsList />
        </SectionPageLayout.Content>
      </SectionPageLayout>

      <OAuthAppsDialogs />
    </OAuthAppsProvider>
  )
}
