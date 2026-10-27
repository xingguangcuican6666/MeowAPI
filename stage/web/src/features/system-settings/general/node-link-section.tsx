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

import { useQuery, useQueryClient } from '@tanstack/react-query'
import { useState } from 'react'
import { useTranslation } from 'react-i18next'

import { Badge } from '@/components/ui/badge'
import { Button } from '@/components/ui/button'
import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from '@/components/ui/card'
import { Input } from '@/components/ui/input'
import { Label } from '@/components/ui/label'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { api } from '@/lib/api'
import { handleServerError } from '@/lib/handle-server-error'
import { requireServerSuccess } from '@/lib/server-error-message'

type ChildLinkState = {
  master_url: string
  master_name: string
  db_mode: string
  node_name: string
  listen_port: number
  connected: boolean
  connected_at: number
  has_local: boolean
}

type ChildRecord = {
  name: string
  db_mode: string
  version: string
  hostname: string
  registered_at: number
  last_seen_at: number
}

type NodeLinkStatus = {
  role: 'none' | 'child' | 'master'
  node_name: string
  version: string
  child?: ChildLinkState
  master?: { children: ChildRecord[]; tokens: string[] }
}

function formatTimestamp(value: number): string {
  if (!value) return '-'
  return new Date(value * 1000).toLocaleString()
}

export function NodeLinkSection() {
  const { t } = useTranslation()
  const queryClient = useQueryClient()
  const [mode, setMode] = useState<'child' | 'master'>('child')
  const [masterURL, setMasterURL] = useState('')
  const [pairingToken, setPairingToken] = useState('')
  const [nodeName, setNodeName] = useState('')
  const [dbMode, setDbMode] = useState<'overwrite' | 'merge'>('overwrite')
  const [busy, setBusy] = useState(false)
  const [adoptURL, setAdoptURL] = useState('')
  const [adoptToken, setAdoptToken] = useState('')

  const statusQuery = useQuery({
    queryKey: ['node-link'],
    queryFn: async () =>
      requireServerSuccess((await api.get('/api/node_link/')).data),
    refetchInterval: 30_000,
  })
  const status: NodeLinkStatus | undefined = statusQuery.data?.data

  const refresh = () =>
    queryClient.invalidateQueries({ queryKey: ['node-link'] })

  const run = async (action: () => Promise<unknown>) => {
    setBusy(true)
    try {
      await action()
      await refresh()
    } catch (error) {
      handleServerError(error, t('Node link operation failed'))
    } finally {
      setBusy(false)
    }
  }

  const child = status?.child
  const master = status?.master
  const children = master?.children ?? []
  const tokens = master?.tokens ?? []

  return (
    <div className='space-y-4'>
      <Card>
        <CardHeader>
          <CardTitle className='flex items-center gap-2'>
            {t('Node Link')}
            <Badge variant='outline'>{status?.role ?? '...'}</Badge>
          </CardTitle>
          <CardDescription>
            {t(
              'Link new-api instances over the network. The node without a public IP should use child mode and dial out to the master; the master shares its database with accepted children.'
            )}
          </CardDescription>
        </CardHeader>
        <CardContent className='space-y-2 text-sm'>
          <div className='flex flex-wrap gap-2'>
            <Badge variant='secondary'>
              {t('This node')}: {status?.node_name ?? '-'}
            </Badge>
            <Badge variant='secondary'>
              {t('Version')}: {status?.version ?? '-'}
            </Badge>
          </div>
        </CardContent>
      </Card>

      {status?.role === 'child' && child && (
        <Card>
          <CardHeader>
            <CardTitle>{t('Child link')}</CardTitle>
            <CardDescription>
              {t(
                'Database traffic is tunnelled to the master over an outbound-only connection; restart this node to resume the link after downtime.'
              )}
            </CardDescription>
          </CardHeader>
          <CardContent className='space-y-3 text-sm'>
            <div className='grid gap-2 sm:grid-cols-2'>
              <div>
                <Label>{t('Master')}</Label>
                <div>{child.master_name || child.master_url}</div>
              </div>
              <div>
                <Label>{t('Database Retention')}</Label>
                <div>{child.db_mode}</div>
              </div>
              <div>
                <Label>{t('Local tunnel port')}</Label>
                <div>127.0.0.1:{child.listen_port}</div>
              </div>
              <div>
                <Label>{t('Status')}</Label>
                <Badge variant={child.connected ? 'secondary' : 'destructive'}>
                  {child.connected ? t('Connected') : t('Disconnected')}
                </Badge>
              </div>
            </div>
            <Button
              variant='destructive'
              disabled={busy}
              onClick={() =>
                run(async () => {
                  await api.post('/api/node_link/disconnect')
                })
              }
            >
              {t('Disconnect')}
            </Button>
            <p className='text-muted-foreground text-xs'>
              {t(
                'Disconnecting restores the local database connection. Data already written to the master stays on the master.'
              )}
            </p>
          </CardContent>
        </Card>
      )}

      {status?.role === 'master' && master && (
        <>
          <Card>
            <CardHeader>
              <CardTitle>{t('Registered child nodes')}</CardTitle>
              <CardDescription>
                {t(
                  'Children dial out to this node and share its database; removing one revokes its tunnel access.'
                )}
              </CardDescription>
            </CardHeader>
            <CardContent className='space-y-3'>
              {children.length === 0 ? (
                <div className='text-muted-foreground text-sm'>
                  {t('No child nodes registered yet.')}
                </div>
              ) : (
                <div className='space-y-2'>
                  {children.map((entry) => (
                    <div
                      key={entry.name}
                      className='flex flex-wrap items-center justify-between gap-2 rounded-md border p-2 text-sm'
                    >
                      <div className='space-y-0.5'>
                        <div className='font-medium'>{entry.name}</div>
                        <div className='text-muted-foreground text-xs'>
                          {entry.db_mode} · {entry.version || '-'} ·{' '}
                          {t('Last seen')}:{' '}
                          {formatTimestamp(entry.last_seen_at)}
                        </div>
                      </div>
                      <Button
                        variant='destructive'
                        size='sm'
                        disabled={busy}
                        onClick={() =>
                          run(async () => {
                            await api.delete(
                              `/api/node_link/children/${encodeURIComponent(entry.name)}`
                            )
                          })
                        }
                      >
                        {t('Remove')}
                      </Button>
                    </div>
                  ))}
                </div>
              )}
              <div className='space-y-2 rounded-md border border-dashed p-3'>
                <div className='text-sm font-medium'>
                  {t('Adopt a reachable node as child')}
                </div>
                <div className='grid gap-2 sm:grid-cols-2'>
                  <div className='space-y-1'>
                    <Label>{t('Remote URL')}</Label>
                    <Input
                      value={adoptURL}
                      onChange={(e) => setAdoptURL(e.target.value)}
                      placeholder='https://child.example.com'
                    />
                  </div>
                  <div className='space-y-1'>
                    <Label>{t('Remote root access token')}</Label>
                    <Input
                      value={adoptToken}
                      onChange={(e) => setAdoptToken(e.target.value)}
                      type='password'
                    />
                  </div>
                </div>
                <Button
                  variant='outline'
                  size='sm'
                  disabled={busy || !adoptURL || !adoptToken}
                  onClick={() =>
                    run(async () => {
                      await api.post('/api/node_link/push-adopt', {
                        remote_url: adoptURL,
                        remote_access_token: adoptToken,
                        name: adoptURL.replace(/^https?:\/\//, ''),
                        db_mode: 'overwrite',
                        master_url: window.location.origin,
                      })
                      setAdoptURL('')
                      setAdoptToken('')
                    })
                  }
                >
                  {t('Adopt node')}
                </Button>
                <p className='text-muted-foreground text-xs'>
                  {t(
                    'The remote must be reachable once; afterwards it keeps the tunnel alive with outbound-only connections. Override the database mode by reconnecting from the remote side.'
                  )}
                </p>
              </div>
            </CardContent>
          </Card>
          <Card>
            <CardHeader>
              <CardTitle>{t('Pairing Tokens')}</CardTitle>
              <CardDescription>
                {t(
                  'Paste a token on a child node to let it dial this master and share its database.'
                )}
              </CardDescription>
            </CardHeader>
            <CardContent className='space-y-2'>
              <Button
                variant='outline'
                size='sm'
                disabled={busy}
                onClick={() =>
                  run(async () => {
                    await api.post('/api/node_link/token')
                  })
                }
              >
                {t('Generate Pairing Token')}
              </Button>
              {tokens.map((token) => (
                <div
                  key={token}
                  className='bg-muted/40 rounded-md border p-2 font-mono text-xs break-all'
                >
                  {token}
                </div>
              ))}
            </CardContent>
          </Card>
        </>
      )}

      {status && status.role === 'none' && (
        <Card>
          <CardHeader>
            <CardTitle>{t('Connection Mode')}</CardTitle>
            <CardDescription>
              {t(
                'Child mode dials out to an existing master (no public IP needed). Master mode listens for children and shares this node database, so it requires a public IP. SQLite masters cannot share their database.'
              )}
            </CardDescription>
          </CardHeader>
          <CardContent className='space-y-4'>
            <div className='space-y-2'>
              <Label>{t('Connection Mode')}</Label>
              <Select
                value={mode}
                onValueChange={(value) => setMode(value as 'child' | 'master')}
              >
                <SelectTrigger className='w-64'>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value='child'>{t('Child Mode')}</SelectItem>
                  <SelectItem value='master'>{t('Master Mode')}</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {mode === 'child' ? (
              <div className='space-y-3'>
                <div className='grid gap-2 sm:grid-cols-2'>
                  <div className='space-y-1'>
                    <Label>{t('Master URL')}</Label>
                    <Input
                      value={masterURL}
                      onChange={(e) => setMasterURL(e.target.value)}
                      placeholder='https://master.example.com'
                    />
                  </div>
                  <div className='space-y-1'>
                    <Label>{t('Pairing Token')}</Label>
                    <Input
                      value={pairingToken}
                      onChange={(e) => setPairingToken(e.target.value)}
                      placeholder='nlk-...'
                    />
                  </div>
                  <div className='space-y-1'>
                    <Label>{t('Node Name')}</Label>
                    <Input
                      value={nodeName}
                      onChange={(e) => setNodeName(e.target.value)}
                      placeholder={status.node_name}
                    />
                  </div>
                  <div className='space-y-1'>
                    <Label>{t('Database Retention')}</Label>
                    <Select
                      value={dbMode}
                      onValueChange={(value) =>
                        setDbMode(value as 'overwrite' | 'merge')
                      }
                    >
                      <SelectTrigger>
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value='overwrite'>
                          {t('Overwrite sync (discard local database)')}
                        </SelectItem>
                        <SelectItem value='merge'>
                          {t('Merge sync (merge local data into the master)')}
                        </SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>
                <p className='text-muted-foreground text-xs'>
                  {dbMode === 'overwrite'
                    ? t(
                        'Overwrite sync accepts the master database and abandons the local one; the local database stays on disk but is no longer used.'
                      )
                    : t(
                        'Merge sync imports local users, tokens, channels and options into the master database (re-keyed to avoid collisions; identity conflicts resolve in the master favour), then switches over. Logs and other telemetry tables are not merged.'
                      )}
                </p>
                <Button
                  disabled={
                    busy || !masterURL || !pairingToken || !nodeName || !dbMode
                  }
                  onClick={() =>
                    run(async () => {
                      await api.post('/api/node_link/connect', {
                        master_url: masterURL,
                        token: pairingToken,
                        name: nodeName,
                        db_mode: dbMode,
                      })
                    })
                  }
                >
                  {t('Connect')}
                </Button>
              </div>
            ) : (
              <div className='space-y-3'>
                <div className='flex flex-wrap items-center gap-2'>
                  <Button
                    variant='outline'
                    size='sm'
                    disabled={busy}
                    onClick={() =>
                      run(async () => {
                        await api.post('/api/node_link/token')
                      })
                    }
                  >
                    {t('Generate Pairing Token')}
                  </Button>
                  <Badge variant='secondary'>
                    {t('Master URL')}: {window.location.origin}
                  </Badge>
                </div>
                {tokens.length > 0 && (
                  <div className='space-y-1'>
                    {tokens.map((token) => (
                      <div
                        key={token}
                        className='bg-muted/40 rounded-md border p-2 font-mono text-xs break-all'
                      >
                        {token}
                      </div>
                    ))}
                  </div>
                )}
                <p className='text-muted-foreground text-xs'>
                  {t(
                    'This node keeps using its own database as the cluster database. Children register with a token and reach it through outbound-only tunnels.'
                  )}
                </p>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  )
}
