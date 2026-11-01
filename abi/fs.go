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

// The stat result of a confined path.

// FSInfo is what FSStat reports: the two facts a module needs and no more. It
// deliberately omits timestamps and permissions, which a module has no use for and
// which would render host-side details the boundary was meant to keep out.
type FSInfo struct {
	Size  int64 `json:"size"`
	IsDir bool  `json:"is_dir"`
}
