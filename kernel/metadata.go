/*
Copyright (C) 2026 xingguangcuican6666

This file is part of MeowAPI, which is licensed under the GNU Affero General
Public License v3.0.

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

package kernel

import "sync"

// metadataKey scopes a metadata entry to its owner. Entries owned by pid 0 are
// kernel-published and readable by any context holding metadata:read; entries
// owned by a module are readable only by that module and by a context holding
// metadata:write.
//
// This is deliberately stricter than the prototype, where a single global store
// was readable by every plugin and therefore leaked one plugin's state to all the
// others. Scoping by owner is what makes the store usable for per-module
// configuration at all.
type metadataKey struct {
	owner PID
	key   string
}

// metadataStore is the kernel key-value store. It owns its lock rather than
// sharing the process table's, because reading a key must not serialize against
// spawning a context. All access is mediated by check(); there is no path that
// bypasses it.
type metadataStore struct {
	mu      sync.RWMutex
	entries map[metadataKey]any
}

var kmeta = &metadataStore{entries: make(map[metadataKey]any)}

func (s *metadataStore) write(ctx *sContext, key string, value any) error {
	if err := check(ctx, OpMetadataWrite); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[metadataKey{owner: ctx.pid, key: key}] = value
	return nil
}

func (s *metadataStore) read(ctx *sContext, key string) (any, error) {
	if err := check(ctx, OpMetadataRead); err != nil {
		return nil, err
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if own, ok := s.entries[metadataKey{owner: ctx.pid, key: key}]; ok {
		return own, nil
	}
	// Kernel-published entries (owner pid 0) are readable by any context that
	// holds metadata:read.
	if published, ok := s.entries[metadataKey{owner: 0, key: key}]; ok {
		return published, nil
	}
	// A context holding metadata:write (the kernel and init only) may read any
	// owner's entry, so it can inspect what modules published. No module reaches
	// this branch, because metadata:write is not grantable to the plugin domain.
	if Allowed(ctx.dom, OpMetadataWrite) {
		for k, v := range s.entries {
			if k.key == key {
				return v, nil
			}
		}
	}
	return nil, nil
}

// publish writes an entry owned by pid 0, bypassing the syscall path. Only
// Kernel.Publish calls it, from the bootloader, which holds no context. It is
// not reachable from a module: it is unexported and takes no context to check.
func (s *metadataStore) publish(key string, value any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries[metadataKey{owner: 0, key: key}] = value
}

// MetadataSnapshot returns a copy of the published metadata (owner pid 0) for
// diagnostics. It never exposes a module's private entries, so a dump cannot leak
// per-module state.
func MetadataSnapshot() map[string]any {
	kmeta.mu.RLock()
	defer kmeta.mu.RUnlock()
	out := make(map[string]any)
	for k, v := range kmeta.entries {
		if k.owner == 0 {
			out[k.key] = v
		}
	}
	return out
}

// reset clears the store for a fresh boot. Called only from resetKernel.
func (s *metadataStore) reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = make(map[metadataKey]any)
}

// SyscallMeta is the metadata half of the syscall surface.
type SyscallMeta interface {
	// SyscallMetadataGet reads a key. Requires metadata:read. A module sees its
	// own entries and kernel-published ones, never another module's.
	SyscallMetadataGet(key string) (any, error)
	// SyscallMetadataSet writes a key. Requires metadata:write, which no module
	// domain holds.
	SyscallMetadataSet(key string, value any) error
}

func (c *sContext) SyscallMetadataGet(key string) (any, error) {
	if err := c.syscall(OpMetadataRead); err != nil {
		return nil, err
	}
	if err := SeccompAllow(c, OpMetadataRead, key); err != nil {
		return nil, err
	}
	return kmeta.read(c, key)
}

func (c *sContext) SyscallMetadataSet(key string, value any) error {
	if err := c.syscall(OpMetadataWrite); err != nil {
		return err
	}
	if err := SeccompAllow(c, OpMetadataWrite, key); err != nil {
		return err
	}
	return kmeta.write(c, key, value)
}
