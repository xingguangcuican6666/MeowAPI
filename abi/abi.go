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

// Package abi is the interface between the kernel and the code it loads.
//
// It exists because of how Go plugins work. A plugin is compiled against the exact
// source of every package it imports: change one of those packages and every .so
// built against the old version refuses to load, with "plugin was built with a
// different version of package". Measured, not assumed - adding a single
// unexported function to an imported package is enough to invalidate a plugin.
//
// The kernel is the package every module would otherwise import, and it is the one
// package that changes constantly. So the types a module needs live here instead,
// in a package with no dependencies beyond the standard library and a version
// number that only moves when something here breaks compatibility. The kernel
// imports this package and aliases its types (type PID = abi.PID), which is why
// kernel internals can be rewritten without invalidating a single plugin.
//
// What must never appear here:
//
//   - Anything the kernel enforces. The policy table, the grant sets and the
//     domain rules stay in kernel: a copy of a rule in a package a module
//     compiles against is a copy a module can read and reason about.
//   - Anything with kernel state behind it. A type here is data or a declaration;
//     if it has behaviour beyond pure computation over its own fields, that
//     behaviour belongs in the kernel and takes the data as an argument.
//   - Unexported helpers that kernel code happens to share. They are not part of
//     what a module sees, and moving them here would make this package a dumping
//     ground instead of a contract.
//
// What must appear here: every type in a module's signature, every constant it has
// to name, and every method it has to call. The kernel's build is the check on the
// first two - a name missing here is an undefined identifier there, since the kernel
// aliases every type it uses rather than declaring its own. tests/abi covers the
// properties the compiler cannot see: that nothing here imports anything but the
// standard library, that nothing here reaches into the kernel, and that a name
// declared here is aliased in the kernel rather than re-declared beside it with a
// body that could drift from this one.
package abi
