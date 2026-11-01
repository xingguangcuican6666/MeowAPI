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

package abi_test

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestABIImportsNothingButTheStandardLibrary is the property the whole plugin scheme
// rests on, and it is checked rather than promised. A Go plugin is compiled against
// the exact source of every package it imports, and refuses to load once any of them
// changes - measured, down to adding one unexported function. abi is the package a
// module compiles against, so it must not import the kernel, and it must not pick up
// a third-party dependency either: the moment it does, every plugin inherits that
// version constraint and a dependency bump invalidates every .so.
func TestABIImportsNothingButTheStandardLibrary(t *testing.T) {
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no source files beside this test; the glob is wrong")
	}

	fset := token.NewFileSet()
	var checked int
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		checked++
		for _, imp := range af.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			// A standard-library import has no dot in its first path segment.
			first := strings.SplitN(path, "/", 2)[0]
			if strings.Contains(first, ".") {
				t.Errorf("%s imports %q: abi must depend on the standard library alone, "+
					"or every plugin inherits that dependency's version constraint", f, path)
			}
			if strings.Contains(path, "MeowAPI/kernel") {
				t.Errorf("%s imports the kernel: that is the dependency this package exists "+
					"to break, because a kernel change would invalidate every plugin", f)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no non-test source files were checked")
	}
}

// TestABIIsTheKernelsUpstream pins the direction of the dependency. The kernel may
// alias an abi type; abi may never mention a kernel type. A cycle would be a compile
// error, but the interesting failure is silent: someone adds a field to an abi type
// whose value only the kernel can produce, and the type stops being data.
func TestABIIsTheKernelsUpstream(t *testing.T) {
	files, _ := filepath.Glob("*.go")
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(b), "MeowAPI/kernel") {
			t.Errorf("%s refers to the kernel package", f)
		}
	}
}
