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
import React, { useCallback, useState } from 'react'

import useDialogState from '@/hooks/use-dialog'

import { OAUTH_CLIENTS_QUERY_KEY } from '../constants'
import type { OAuthAppsDialogType, OAuthClient } from '../types'

type RevealedSecret = {
  clientId: string
  secret: string
}

type OAuthAppsContextType = {
  open: OAuthAppsDialogType | null
  setOpen: (value: OAuthAppsDialogType | null) => void
  currentRow: OAuthClient | null
  setCurrentRow: React.Dispatch<React.SetStateAction<OAuthClient | null>>
  triggerRefresh: () => void
  revealedSecret: RevealedSecret | null
  setRevealedSecret: React.Dispatch<React.SetStateAction<RevealedSecret | null>>
}

const OAuthAppsContext = React.createContext<OAuthAppsContextType | null>(null)

export function OAuthAppsProvider({ children }: { children: React.ReactNode }) {
  const queryClient = useQueryClient()
  const [open, setOpen] = useDialogState<OAuthAppsDialogType>(null)
  const [currentRow, setCurrentRow] = useState<OAuthClient | null>(null)
  const [revealedSecret, setRevealedSecret] = useState<RevealedSecret | null>(
    null
  )

  const triggerRefresh = useCallback(() => {
    void queryClient.invalidateQueries({ queryKey: OAUTH_CLIENTS_QUERY_KEY })
  }, [queryClient])

  return (
    <OAuthAppsContext
      value={{
        open,
        setOpen,
        currentRow,
        setCurrentRow,
        triggerRefresh,
        revealedSecret,
        setRevealedSecret,
      }}
    >
      {children}
    </OAuthAppsContext>
  )
}

// eslint-disable-next-line react-refresh/only-export-components
export const useOAuthApps = () => {
  const context = React.useContext(OAuthAppsContext)

  if (!context) {
    throw new Error('useOAuthApps has to be used within <OAuthAppsContext>')
  }

  return context
}
