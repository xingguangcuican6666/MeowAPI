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

// Pipe registry state as a module sees it.

// PipeInfo describes an open pipe for the dump. It reports byte counts, never
// content, because a pipe carries prompts and completions.
type PipeInfo struct {
	FD       FD     `json:"fd"`
	Name     string `json:"name"`
	Owner    PID    `json:"owner"`
	Peer     PID    `json:"peer"`
	Cap      int    `json:"capacity"`
	Buffered int    `json:"buffered"`
	Queued   int    `json:"queued"`
	Written  int64  `json:"written"`
	Read     int64  `json:"read"`
	Dropped  int64  `json:"dropped"`
	Closed   bool   `json:"closed"`
	Aborted  bool   `json:"aborted"`
}
