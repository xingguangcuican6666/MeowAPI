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

// A detached signature and the key id that selects its verifier.

// Signature is a detached signature plus the metadata needed to select a
// verification key. The key id is a digest of the public key rather than the key,
// so a signature can be routed to the right root without carrying key material.
type Signature struct {
	// Algo is the signing algorithm. Only ed25519 is implemented.
	Algo string `json:"algo"`
	// KeyID identifies the verification key as a short digest of it.
	KeyID string `json:"key_id"`
	// Bytes is the raw signature.
	Bytes []byte `json:"bytes"`
}
