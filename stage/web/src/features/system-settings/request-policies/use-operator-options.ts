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

import { useQuery } from '@tanstack/react-query'

import { getChannels, getEnabledModels } from '@/features/channels/api'
import { channelsQueryKeys } from '@/features/channels/lib/channel-actions'
import type { Channel } from '@/features/channels/types'
import { requireServerSuccess } from '@/lib/server-error-message'

// The channel list endpoint caps page_size at 100 on the server, so the
// operator channel picker walks the pages itself instead of showing a
// truncated list that could hide a configured channel.
const OPERATOR_CHANNEL_PAGE_SIZE = 100

const operatorChannelPageKey = {
  id_sort: true,
  page_size: OPERATOR_CHANNEL_PAGE_SIZE,
} as const

async function fetchAllOperatorChannels(): Promise<Channel[]> {
  const first = requireServerSuccess(
    await getChannels({ ...operatorChannelPageKey, p: 1 })
  )
  const items = [...(first.data?.items ?? [])]
  const total = first.data?.total ?? items.length
  for (let page = 2; items.length < total; page += 1) {
    const next = requireServerSuccess(
      await getChannels({ ...operatorChannelPageKey, p: page })
    )
    const pageItems = next.data?.items ?? []
    if (pageItems.length === 0) break
    items.push(...pageItems)
  }
  return items
}

/** Model names offered by the operator picker. Models absent from the list are
 * still accepted: the picker allows custom values so a mapping survives a
 * model that is not currently enabled on any channel. */
export function useOperatorModels() {
  return useQuery({
    queryKey: ['enabled-models'],
    // An unsuccessful response carries no model list, so it is raised like a
    // failed request instead of looking like an empty list of models.
    queryFn: async () =>
      requireServerSuccess(await getEnabledModels()).data ?? [],
  })
}

/** Every channel that can be designated as a model's sole operator. */
export function useOperatorChannels() {
  return useQuery({
    queryKey: channelsQueryKeys.list({ ...operatorChannelPageKey, all: true }),
    queryFn: fetchAllOperatorChannels,
  })
}
