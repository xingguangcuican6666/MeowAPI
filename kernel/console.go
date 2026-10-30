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

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"
)

// Level is the severity of a kernel console record.
type Level string

const (
	LogDebug Level = "debug"
	LogInfo  Level = "info"
	LogWarn  Level = "warn"
	LogError Level = "error"
	// LogFault is reserved for kernel-detected violations: policy denials,
	// caller-trap faults, boot panics. Faults are the audit trail.
	LogFault Level = "fault"
)

// Record is one kernel console line. It is always emitted as a single JSON
// object so that faults stay greppable and machine-readable.
type Record struct {
	Time   time.Time      `json:"time"`
	Level  Level          `json:"level"`
	Pid    PID            `json:"pid"`
	Domain Domain         `json:"domain,omitempty"`
	Msg    string         `json:"msg"`
	Fields map[string]any `json:"fields,omitempty"`
}

// Console is the kernel UART. It is the only output channel the kernel itself
// owns; modules write to it through the log:write operation, never directly.
//
// Console retention is bounded and drops the oldest records. The process table in
// proc.go is the unbounded append-only record of what ran; the console is a
// diagnostic stream and must not become a memory leak.
type Console struct {
	mu      sync.Mutex
	out     io.Writer
	buf     []Record
	limit   int
	dropped int64
	format  Format
	minimum Level
}

// Format selects how a record is rendered on the sink.
type Format string

const (
	// FormatJSON emits one JSON object per line. This is the default and the
	// right choice for anything machine-read: shipped logs, CI artifacts,
	// anything that gets parsed after the fact.
	FormatJSON Format = "json"
	// FormatText emits an aligned human-readable line. It is for a terminal
	// during development. It is lossy about structure, so do not point a log
	// pipeline at it.
	FormatText Format = "text"
)

var levelRank = map[Level]int{
	LogDebug: 0, LogInfo: 1, LogWarn: 2, LogError: 3, LogFault: 4,
}

var kconsole = &Console{out: os.Stderr, limit: 4096, format: FormatJSON, minimum: LogDebug}

// KernelConsole returns the kernel console.
func KernelConsole() *Console { return kconsole }

// SetOutput redirects the console. It exists for tests and for an operator that
// wants kernel output somewhere other than stderr. It is not a module
// capability: only code holding the *Console can call it, and the console is
// reachable only from package kernel and the bootloader.
//
// A nil writer restores stderr, which is what makes "redirect for this test,
// then undo it" safe.
func (c *Console) SetOutput(w io.Writer) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if w == nil {
		w = os.Stderr
	}
	c.out = w
}

// SetFormat switches between JSON and text rendering. An unrecognized format is
// ignored rather than silently changing output shape, because a log parser
// pointed at the wrong format looks like a broken kernel.
func (c *Console) SetFormat(f Format) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if f == FormatJSON || f == FormatText {
		c.format = f
	}
}

// SetLevel drops records below a severity. Faults are always retained in
// History() regardless of this setting, so filtering the sink cannot filter the
// audit trail; it only stops the noise reaching a terminal.
func (c *Console) SetLevel(l Level) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, ok := levelRank[l]; ok {
		c.minimum = l
	}
}

// Format reports the current rendering format.
func (c *Console) Format() Format {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.format
}

// Level reports the current minimum sink severity.
func (c *Console) Level() Level {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.minimum
}

// SetLimit caps retained records. Zero or negative keeps the current limit.
func (c *Console) SetLimit(n int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if n > 0 {
		c.limit = n
		c.trimLocked()
	}
}

// Emit writes one record to the sink and retains it. Retention is unconditional;
// the level filter and the format apply only to what reaches the sink.
func (c *Console) Emit(level Level, pid PID, dom Domain, msg string, fields map[string]any) {
	rec := Record{
		Time:   time.Now().UTC(),
		Level:  level,
		Pid:    pid,
		Domain: dom,
		Msg:    msg,
		Fields: fields,
	}

	c.mu.Lock()
	c.buf = append(c.buf, rec)
	c.trimLocked()
	out := c.out
	format := c.format
	filtered := levelRank[level] < levelRank[c.minimum]
	c.mu.Unlock()

	if out == nil || filtered {
		return
	}
	// Rendering outside the lock: a slow sink must not serialize the kernel.
	line := render(rec, format)
	if !strings.HasSuffix(line, "\n") {
		line += "\n"
	}
	_, _ = io.WriteString(out, line)
}

// render turns one record into a line. Split out from Emit so the two formats
// are testable without a live kernel and without the retention path.
func render(r Record, format Format) string {
	if format == FormatText {
		return renderText(r)
	}
	line, err := json.Marshal(r)
	if err != nil {
		return fmt.Sprintf(`{"level":%q,"msg":%q,"encode_error":%q}`, r.Level, r.Msg, err.Error())
	}
	return string(line)
}

// levelTag is a fixed-width severity label so text columns line up. Fault is
// marked distinctly because it is the line a human scrolls back for.
func levelTag(l Level) string {
	switch l {
	case LogDebug:
		return "DEBUG"
	case LogInfo:
		return "INFO "
	case LogWarn:
		return "WARN "
	case LogError:
		return "ERROR"
	case LogFault:
		return "FAULT"
	}
	return strings.ToUpper(string(l))
}

func renderText(r Record) string {
	var b strings.Builder
	// RFC3339 with millisecond precision: full nanosecond timestamps make the
	// message column wander and are not readable by eye.
	b.WriteString(r.Time.Format("15:04:05.000"))
	b.WriteByte(' ')
	b.WriteString(levelTag(r.Level))
	b.WriteByte(' ')

	if r.Domain != "" {
		b.WriteByte('[')
		b.WriteString(string(r.Domain))
		b.WriteByte(' ')
		b.WriteString(fmt.Sprintf("pid=%d", r.Pid))
		b.WriteByte(']')
		b.WriteByte(' ')
	} else {
		b.WriteString(fmt.Sprintf("[pid=%d]", r.Pid))
		b.WriteByte(' ')
	}

	b.WriteString(r.Msg)

	if len(r.Fields) > 0 {
		// Marshal the fields rather than formatting the map directly, so nested
		// values and quoting stay unambiguous.
		if f, err := json.Marshal(r.Fields); err == nil {
			b.WriteByte(' ')
			b.Write(f)
		}
	}
	return b.String()
}

// History returns a copy of the retained records, oldest first.
func (c *Console) History() []Record {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]Record, len(c.buf))
	copy(out, c.buf)
	return out
}

// Dropped reports how many records were evicted by the retention limit.
func (c *Console) Dropped() int64 {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.dropped
}

// reset clears retained records and the drop counter. Called by Boot and
// Shutdown under the boot guard. The sink is preserved, so a redirected console
// survives a restart.
func (c *Console) reset() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buf = nil
	c.dropped = 0
}

func (c *Console) trimLocked() {
	if len(c.buf) <= c.limit {
		return
	}
	c.dropped += int64(len(c.buf) - c.limit)
	c.buf = append([]Record(nil), c.buf[len(c.buf)-c.limit:]...)
}

// fault records a kernel-detected violation. Every fault emitter in the kernel
// goes through here so the shape of a fault line never drifts.
//
// A nil ctx is legal: some faults are detected before any context exists, or
// against a context the kernel refuses to name.
func fault(ctx *sContext, msg string, fields map[string]any) {
	var pid PID
	var dom Domain
	if ctx != nil {
		pid = ctx.pid
		dom = ctx.dom
	}
	kconsole.Emit(LogFault, pid, dom, msg, fields)
}

// SyscallLog is the console half of the syscall surface.
type SyscallLog interface {
	// SyscallLog writes to the kernel console. Requires log:write. A context
	// outside the kernel and init domains may not emit fault records, because
	// the fault stream is the kernel's own audit trail.
	SyscallLog(level Level, msg string) error
}

func (c *sContext) SyscallLog(level Level, msg string) error {
	if err := c.syscall(OpLogWrite); err != nil {
		return err
	}
	// Fault records are evidence. Letting a module emit them would let it forge
	// a record of its own good behavior or bury a real denial in noise.
	if level == LogFault && c.dom != DomainKernel && c.dom != DomainInit {
		fault(c, "attempt to emit fault record from unprivileged domain", map[string]any{"msg": msg})
		kaudit.record(AuditEscalation, c, "denied fault-record emission", map[string]any{"msg": msg})
		return &DeniedError{Op: OpLogWrite, Ctx: c, Reason: "fault level reserved for the kernel"}
	}
	kconsole.Emit(level, c.pid, c.dom, msg, nil)
	return nil
}
