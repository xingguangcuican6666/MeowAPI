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

import { Plus } from 'lucide-react'
import { useId, useState } from 'react'
import { useTranslation } from 'react-i18next'

import { ConfirmDialog } from '@/components/confirm-dialog'
import {
  StaticDataTable,
  StaticRowActions,
  type StaticDataTableColumn,
} from '@/components/data-table'
import { Button } from '@/components/ui/button'
import {
  CUSTOM_NAV_MAX_ITEMS,
  type CustomNavItem,
  type CustomNavOpenMode,
} from '@/lib/nav-modules'

import { CustomNavItemDialog } from './custom-nav-item-dialog'
import type { CustomNavItemFormValues } from './custom-nav-item-schema'

type CustomNavItemsEditorProps = {
  items: CustomNavItem[]
  onChange: (items: CustomNavItem[]) => void
}

/**
 * Manages the custom top-navigation items. It only edits the list it is given;
 * saving stays with the parent form. Render it outside that form: its dialog
 * owns a `<form>` of its own, and submit events bubble through React portals.
 */
export function CustomNavItemsEditor(props: CustomNavItemsEditorProps) {
  const { t } = useTranslation()
  const headingId = useId()
  const [dialogOpen, setDialogOpen] = useState(false)
  const [deleteOpen, setDeleteOpen] = useState(false)
  const [selected, setSelected] = useState<CustomNavItem | null>(null)
  const isFull = props.items.length >= CUSTOM_NAV_MAX_ITEMS

  const openModeLabels: Record<CustomNavOpenMode, string> = {
    internal: t('Internal route'),
    iframe: t('Embedded page (iframe)'),
    external: t('New tab'),
  }

  const handleAdd = () => {
    setSelected(null)
    setDialogOpen(true)
  }

  const handleEdit = (item: CustomNavItem) => {
    setSelected(item)
    setDialogOpen(true)
  }

  const handleDelete = (item: CustomNavItem) => {
    setSelected(item)
    setDeleteOpen(true)
  }

  const handleSubmit = (values: CustomNavItemFormValues) => {
    if (selected) {
      props.onChange(
        props.items.map((item) =>
          item.id === selected.id ? { ...item, ...values } : item
        )
      )
    } else if (!isFull) {
      const id = `custom-${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 8)}`
      props.onChange([...props.items, { id, ...values }])
    }
    setDialogOpen(false)
  }

  const handleConfirmDelete = () => {
    if (selected) {
      props.onChange(props.items.filter((item) => item.id !== selected.id))
    }
    setDeleteOpen(false)
  }

  const columns: StaticDataTableColumn<CustomNavItem>[] = [
    {
      id: 'title',
      header: t('Title'),
      cellClassName: 'max-w-48 font-medium',
      cell: (item) => item.title,
    },
    {
      id: 'href',
      header: t('Link'),
      cellClassName: 'text-muted-foreground max-w-64',
      cell: (item) => item.href,
    },
    {
      id: 'openMode',
      header: t('Open mode'),
      cell: (item) => openModeLabels[item.openMode],
    },
    {
      id: 'requireAuth',
      header: t('Requires sign-in'),
      cell: (item) => (item.requireAuth ? t('Yes') : t('No')),
    },
    {
      id: 'actions',
      header: t('Actions'),
      cell: (item) => (
        <StaticRowActions
          editLabel={t('Edit {{title}}', { title: item.title })}
          deleteLabel={t('Delete')}
          menuLabel={t('Open menu for {{title}}', { title: item.title })}
          onEdit={() => handleEdit(item)}
          onDelete={() => handleDelete(item)}
        />
      ),
    },
  ]

  return (
    <>
      <section aria-labelledby={headingId} className='flex flex-col gap-3'>
        <div className='flex flex-wrap items-start justify-between gap-2'>
          <div className='min-w-0 space-y-0.5'>
            <h4 id={headingId} className='text-sm font-medium'>
              {t('Custom navigation items')}
            </h4>
            <p className='text-muted-foreground text-xs'>
              {t(
                'Add your own links to the top navigation bar. Changes are saved with the rest of the navigation settings.'
              )}
            </p>
            <p className='text-muted-foreground text-xs'>
              {t('{{used}} of {{max}} items used', {
                used: props.items.length,
                max: CUSTOM_NAV_MAX_ITEMS,
              })}
            </p>
          </div>
          <Button type='button' size='sm' onClick={handleAdd} disabled={isFull}>
            <Plus data-icon='inline-start' />
            {t('Add item')}
          </Button>
        </div>
        <StaticDataTable
          data={props.items}
          columns={columns}
          getRowKey={(item) => item.id}
          emptyContent={t(
            'No custom navigation items yet. Click "Add item" to create one.'
          )}
        />
      </section>

      <CustomNavItemDialog
        open={dialogOpen}
        onOpenChange={setDialogOpen}
        item={selected}
        openModeLabels={openModeLabels}
        onSubmit={handleSubmit}
      />

      <ConfirmDialog
        open={deleteOpen}
        onOpenChange={setDeleteOpen}
        destructive
        title={t('Delete navigation item?')}
        desc={t(
          '"{{title}}" will be removed from the top navigation once you save.',
          { title: selected?.title ?? '' }
        )}
        confirmText={t('Delete')}
        handleConfirm={handleConfirmDelete}
      />
    </>
  )
}
