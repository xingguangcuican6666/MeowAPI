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

// Package main is the example console component: the shape a .so dropped into
// root/bin takes.
//
// The clause is `main` because -buildmode=plugin requires it. A plugin is a main
// package that exports symbols instead of running; the stub main below is only here
// so that `go build ./...` keeps compiling this file.
//
// It imports abi and nothing else, and that is the point of the component rather
// than an incidental fact. A component that imported the kernel would be invalidated
// by every kernel change - plugin.Open refuses a .so built against different source
// of any package it imports, down to one added unexported function - so the only
// thing a component may import is the package that exists to be stable.
//
// Build it with:
//
//	go build -buildmode=plugin -o root/bin/example.so ./plugins/example
//
// and the running console picks it up on `reload`.
package main

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/xingguangcuican6666/MeowAPI/abi"
)

// main is never called. It exists because -buildmode=plugin requires the package
// clause to be `main`, and a `main` package without a `main` function fails
// `go build ./...` - which would take this file out of the build and out of vet,
// and a component nobody compiles is a component that rots until the operator who
// drops it in discovers that at load time instead.
//
// Running the compiled binary rather than the .so is a mistake, so it says so
// rather than pretending to start something.
func main() {
	fmt.Fprintln(os.Stderr,
		"this package is a plugin: build it with\n"+
			"  go build -buildmode=plugin -o root/bin/example.so ./plugins/example\n"+
			"and let the console load it")
	os.Exit(2)
}

// MeowAPIManifest is the component's declaration. The host looks up this symbol by
// name and hands the value to the kernel, which validates it before any of this
// component's code runs.
//
// It is a pointer because plugin.Lookup returns a symbol address, and a value
// symbol's type assertion across a plugin boundary is easy to get subtly wrong.
//
// Require lists what the commands below actually use. log:write is needed by the
// `say` command, which logs through the kernel rather than printing straight to the
// session - printing to the session would bypass the console record entirely, and
// a component whose actions leave no audit trail is a component nobody can
// investigate afterwards.
var MeowAPIManifest = abi.Manifest{
	Name:         "example",
	Version:      "0.1.0",
	MinKernelAPI: abi.KernelAPI,
	MaxKernelAPI: abi.KernelAPI,
	Require:      []abi.Op{abi.OpLogWrite, abi.OpMetadataRead, abi.OpCPUTimeRead},
}

// loaded is set by the kernel's OnLoad, through the command that reports it. It is
// package state in a component, which is a thing AGENT.md warns against for a
// context - and the distinction is worth stating rather than leaving implicit. What
// must never be stashed here is the SContext, because a retained context is an
// authority that outlives the load that granted it. A timestamp is not an authority.
var loaded = time.Time{}

// MeowAPICommands is the table this component contributes. Same lookup mechanism,
// same reason for the pointer.
var MeowAPICommands = []abi.Command{
	{
		Name: "example",
		Help: "say hello from a loaded component",
		Run: func(ctx abi.SContext, args []string) (string, error) {
			return fmt.Sprintf("hello from %q, pid %d, domain %s\n",
				ctx.Name(), ctx.PID(), ctx.Domain()), nil
		},
	},
	{
		Name:     "say",
		Help:     "log a line through the kernel console: say <words>",
		Requires: abi.OpLogWrite,
		Run: func(ctx abi.SContext, args []string) (string, error) {
			if len(args) == 0 {
				return "", fmt.Errorf("usage: say <words>")
			}
			msg := strings.Join(args, " ")
			if err := ctx.SyscallLog(abi.LogInfo, msg); err != nil {
				return "", err
			}
			return "logged; `log` will show it\n", nil
		},
	},
	{
		Name: "boot-id",
		Help: "read the kernel-published boot id",
		Run: func(ctx abi.SContext, args []string) (string, error) {
			v, err := ctx.SyscallMetadataGet("kernel.boot.id")
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("kernel.boot.id = %v\n", v), nil
		},
	},
	{
		Name: "cpu",
		Help: "this pid's supervised-work accounting",
		Run: func(ctx abi.SContext, args []string) (string, error) {
			stat, err := ctx.SyscallCPUStat()
			if err != nil {
				return "", err
			}
			return fmt.Sprintf("pid %d: calls=%d, cpu~%d ns, budget=%d ns, exhausted=%t\n",
				ctx.PID(), stat.Calls, stat.CPUNanos, stat.Budget, stat.Exhausted), nil
		},
	},
	{
		Name: "selftest",
		Help: "prove the component is live: print its own build facts",
		Run: func(ctx abi.SContext, args []string) (string, error) {
			loaded = time.Now().UTC()
			return fmt.Sprintf("component %q v%s, go %s, %s/%s, first command at %s\n",
				MeowAPIManifest.Name, MeowAPIManifest.Version,
				runtime.Version(), runtime.GOOS, runtime.GOARCH,
				loaded.Format(time.RFC3339)), nil
		},
	},
}
