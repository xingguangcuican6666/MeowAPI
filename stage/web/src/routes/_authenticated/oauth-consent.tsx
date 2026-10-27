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

import { createFileRoute } from '@tanstack/react-router'
import { z } from 'zod'

import { OAuthConsent } from '@/features/oauth-consent'

const oauthConsentSearchSchema = z.object({
  req: z.string().optional().catch(''),
})

export const Route = createFileRoute('/_authenticated/oauth-consent')({
  validateSearch: oauthConsentSearchSchema,
  component: OAuthConsentPage,
})

function OAuthConsentPage() {
  const { req } = Route.useSearch()
  return <OAuthConsent request={req ?? ''} />
}
