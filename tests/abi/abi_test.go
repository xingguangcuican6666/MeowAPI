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

package abi

import (
	"go/ast"
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
	files, err := filepath.Glob("../../abi/*.go")
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
	files, _ := filepath.Glob("../../abi/*.go")
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

// TestKernelAliasesEveryABIType pins the half of the split the compiler cannot see.
//
// The migration works by alias: each moved type is declared in abi and the kernel
// writes `type X = abi.X`, which is the SAME type on both sides. If someone later
// re-declares one of those names with a body in the kernel - a plausible thing to do
// while fixing a bug, since the kernel is where the behaviour lives - the kernel and a
// module then hold two distinct types that happen to share a name. Nothing fails to
// compile: the kernel's own code adapts around the duplicate, and the only symptom is
// a module whose values do not type-check against the kernel's API, or, worse where a
// conversion is legal, a value silently copied between two definitions that can now
// drift apart.
//
// So: every type and constant declared in abi must appear in package kernel either
// aliased to the abi name or not at all. A same-named definition in kernel is a
// failure, and the message names which one.
func TestKernelAliasesEveryABIType(t *testing.T) {
	abiTypes, abiConsts := exportedDecls(t, "../../abi")

	if len(abiTypes) == 0 || len(abiConsts) == 0 {
		t.Fatalf("found %d types and %d constants in abi; the walk is wrong",
			len(abiTypes), len(abiConsts))
	}

	kernelTypes, kernelConsts := kernelDecls(t, "../../kernel")

	var bad []string
	for name, aliased := range kernelTypes {
		if _, inABI := abiTypes[name]; !inABI {
			continue
		}
		if !aliased {
			bad = append(bad, "type "+name+" is declared in abi and re-declared with a body in"+
				" kernel; it must be `type "+name+" = abi."+name+"` or not declared at all")
		}
	}
	for name, aliased := range kernelConsts {
		if _, inABI := abiConsts[name]; !inABI {
			continue
		}
		if !aliased {
			bad = append(bad, "constant "+name+" is declared in abi and re-declared with a value"+
				" in kernel; it must be `"+name+" = abi."+name+"` so the two cannot drift")
		}
	}
	for _, b := range bad {
		t.Error(b)
	}
}

// exportedDecls returns the exported type names and constant names declared in package
// abi's non-test files, as sets used only for membership.
func exportedDecls(t *testing.T, dir string) (map[string]struct{}, map[string]struct{}) {
	t.Helper()
	types := map[string]struct{}{}
	consts := map[string]struct{}{}
	for _, f := range parseDir(t, dir) {
		for _, d := range f.Decls {
			switch d := d.(type) {
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					switch spec := spec.(type) {
					case *ast.TypeSpec:
						if spec.Name.IsExported() {
							types[spec.Name.Name] = struct{}{}
						}
					case *ast.ValueSpec:
						if d.Tok != token.CONST {
							continue
						}
						for _, n := range spec.Names {
							if n.IsExported() {
								consts[n.Name] = struct{}{}
							}
						}
					}
				}
			}
		}
	}
	return types, consts
}

// kernelDecls returns every type and constant name declared in package kernel, mapped
// to whether its declaration is an alias of the same name in abi.
//
// An alias is `type X = abi.X`, whose TypeSpec.Assign is set and whose Type is a
// SelectorExpr on the imported abi package. A constant is an alias in the sense that
// matters here when its value is that same selector, which is what a re-export
// (`OpFoo = abi.OpFoo`) is.
func kernelDecls(t *testing.T, dir string) (map[string]bool, map[string]bool) {
	t.Helper()
	types := map[string]bool{}
	consts := map[string]bool{}
	for _, f := range parseDir(t, dir) {
		imported := map[string]string{}
		for _, imp := range f.Imports {
			path := strings.Trim(imp.Path.Value, `"`)
			name := filepath.Base(path)
			if imp.Name != nil {
				name = imp.Name.Name
			}
			imported[name] = path
		}
		for _, d := range f.Decls {
			gd, ok := d.(*ast.GenDecl)
			if !ok {
				continue
			}
			for _, spec := range gd.Specs {
				switch spec := spec.(type) {
				case *ast.TypeSpec:
					if !spec.Name.IsExported() {
						continue
					}
					types[spec.Name.Name] = spec.Assign.IsValid() &&
						isABISelector(spec.Type, spec.Name.Name, imported)
				case *ast.ValueSpec:
					if gd.Tok != token.CONST {
						continue
					}
					for i, n := range spec.Names {
						if !n.IsExported() {
							continue
						}
						// A grouped `const ( A = abi.A; B = abi.B )` may omit the
						// value on a later line and inherit the previous one's
						// expression; ast leaves Values short in that case, and a
						// short Values is not a re-declaration with a body.
						if i >= len(spec.Values) {
							continue
						}
						consts[n.Name] = isABISelector(spec.Values[i], n.Name, imported)
					}
				}
			}
		}
	}
	return types, consts
}

// isABISelector reports whether e is a reference to name inside the imported abi
// package, i.e. abi.<name>.
func isABISelector(e ast.Expr, name string, imported map[string]string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel.Name != name {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	if !ok {
		return false
	}
	path, ok := imported[pkg.Name]
	return ok && strings.HasSuffix(path, "/abi")
}

// parseDir parses every non-test Go file in dir.
func parseDir(t *testing.T, dir string) []*ast.File {
	t.Helper()
	files, err := filepath.Glob(filepath.Join(dir, "*.go"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatalf("no Go files under %s; the glob is wrong", dir)
	}
	fset := token.NewFileSet()
	var out []*ast.File
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		af, err := parser.ParseFile(fset, f, nil, 0)
		if err != nil {
			t.Fatalf("%s: %v", f, err)
		}
		out = append(out, af)
	}
	if len(out) == 0 {
		t.Fatalf("only test files under %s", dir)
	}
	return out
}
