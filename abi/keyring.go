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

// Custody by use. A module names an alias and gets a result, never a credential.

// SecretResult is what a module receives. No field of it is, or can be turned into,
// the credential.
type SecretResult struct {
	// Alias echoes the alias the request named, so a caller doing several uses in a
	// row can match results to requests.
	Alias string `json:"alias"`
	// Action echoes the action performed.
	Action SecretAction `json:"action"`
	// FD is a handle to the sealed header value, for SecretActionHeader only. It is
	// valid only inside this pid's table, and only the kernel can open it.
	FD FD `json:"fd,omitempty"`
	// Header names the header the sealed value belongs in, for SecretActionHeader
	// only. The name is not a secret; the value is.
	Header string `json:"header,omitempty"`
	// MAC is the keyed digest, for SecretActionSign only. It is omitted from JSON
	// because a rendered result belongs on the wire, not in a log line.
	MAC []byte `json:"-"`
	// Match is the comparison verdict, for SecretActionMatch only.
	Match bool `json:"match,omitempty"`
}

// SecretSpec describes one credential handed to the keyring. It is the only shape in
// which a secret enters the kernel, so every field a reviewer needs to see is named
// rather than inferred from a string.
type SecretSpec struct {
	// Alias names the credential. Modules ask for it by this name and never by
	// value. It must fall inside the prefixes the asking module declared.
	Alias string
	// Header is the HTTP header the credential belongs in, for example
	// "Authorization" or "x-api-key". Empty means "Authorization". The module does
	// not choose this: which header a credential goes into is part of the
	// credential's own definition, and letting a caller pick it would let a module
	// put a bearer token into a header an upstream logs.
	Header string
	// Scheme is prepended to the credential when rendering the header value, for
	// example "Bearer ". Empty renders the credential bare, which is what an
	// x-api-key style header requires.
	Scheme string
	// Value is the credential. The keyring copies it and then zeroes the caller's
	// slice, so ownership transfers on return. See InstallSecret.
	Value []byte
}
