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

package console

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"time"
)

// The singleton. Exactly one daemon owns one kernel, and the socket is what
// enforces it rather than a pid file, a lock or a "is it running?" probe.
//
// A unix-domain listen on a path that another process is already listening on
// fails with EADDRINUSE - measured, not assumed - so two daemons racing to start
// produce one winner and one refusal, with no window in which both believe they
// own the kernel. A pid file has such a window (write, then crash, then the file
// lies) and needs staleness heuristics to recover from it. The socket has neither
// problem because the kernel's own socket table is the ledger.
//
// The one case the socket cannot answer by itself is a stale path: a daemon that
// was killed leaves the file behind, and bind then fails even though nothing is
// listening. That is why the path is probed with a real connect before it is
// trusted - a connect that is refused proves no one is there, and then the stale
// path is removed and the bind retried.

// SocketPath is where the daemon listens by default, and the record of who is
// allowed to talk to it.
//
// It lives under the user's runtime directory when the platform provides one,
// because that directory is per-user and already has the right mode; otherwise it
// falls back to the state directory. /tmp is deliberately not the default: a
// world-writable directory means the socket's own mode is the only thing standing
// between the kernel and any local user, and a fixed name there is a name another
// user can pre-create.
func SocketPath(root string) string {
	if root != "" {
		return filepath.Join(root, "console.sock")
	}
	if d := os.Getenv("XDG_RUNTIME_DIR"); d != "" {
		return filepath.Join(d, "meowapi", "console.sock")
	}
	if d, err := os.UserHomeDir(); err == nil {
		return filepath.Join(d, ".local", "state", "meowapi", "console.sock")
	}
	return filepath.Join(os.TempDir(), "meowapi-console.sock")
}

// ErrNoDaemon is returned by a probe that found nobody listening.
var ErrNoDaemon = errors.New("console: nothing is listening on the socket")

// Probe connects to path and immediately closes. It returns nil when a daemon is
// accepting connections there, and ErrNoDaemon when it is not.
//
// Nil means "running" because the callers decide between two branches - attach or
// start - and the branch that needs the error is the unusual one. A probe that
// returned an error on success would have every caller writing `if err == ErrRunning`,
// which is the kind of inverted check that reads right and is wrong.
//
// ECONNREFUSED means the path exists but nothing is bound - a stale socket from a
// killed process. Any other failure means there is nothing usable there, which is
// the same answer as "not running" for a caller deciding what to do next.
func Probe(path string) error {
	c, err := net.DialTimeout("unix", path, 750*time.Millisecond)
	if err != nil {
		if errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, os.ErrNotExist) {
			return ErrNoDaemon
		}
		return fmt.Errorf("%w: %v", ErrNoDaemon, err)
	}
	_ = c.Close()
	return nil
}

// Listen binds the socket, creating its directory 0700 and the socket itself 0600
// so that the filesystem mode matches the credential record's.
//
// The ownership and mode are set explicitly after bind rather than left to the
// umask: a socket created under a permissive umask is reachable by every local
// user, and the mode on a unix socket is exactly what the kernel checks on connect.
func Listen(path string) (net.Listener, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("creating %s: %w", dir, err)
	}

	// One retry, and only for a stale path. Any other error is reported as it is,
	// because guessing at the cause of a bind failure is how a second daemon ends
	// up running quietly beside the first.
	ln, err := net.Listen("unix", path)
	if err != nil && errors.Is(err, syscall.EADDRINUSE) {
		if perr := Probe(path); errors.Is(perr, ErrNoDaemon) {
			if rerr := os.Remove(path); rerr == nil {
				ln, err = net.Listen("unix", path)
			}
		}
	}
	if err != nil {
		return nil, fmt.Errorf("listening on %s: %w", path, err)
	}

	if err := os.Chmod(path, 0o600); err != nil {
		_ = ln.Close()
		_ = os.Remove(path)
		return nil, fmt.Errorf("setting the socket's mode: %w", err)
	}
	return ln, nil
}

// Listener is a bound socket plus the path it owns, so Close can remove the file.
//
// An unlinked path and a closed listener are not the same thing: the listener
// holds the inode and stops accepting, but the path stays on disk and would make
// the next start look like a stale socket, which it would then have to remove.
// Removing it here is one line and removes that whole class of confusion.
type Listener struct {
	net.Listener
	path string
	once sync.Once
}

// Close stops accepting and unlinks the path, in that order.
func (l *Listener) Close() error {
	var err error
	l.once.Do(func() {
		err = l.Listener.Close()
		_ = os.Remove(l.path)
	})
	return err
}

// boundedReader reads newline-delimited protocol messages with a hard cap.
//
// bufio cannot be used directly because its ReadString grows without a limit
// until it finds a newline: a client that opens a connection and sends 4 GiB of
// bytes with no newline would be a client that grows the daemon's heap by 4 GiB.
// This reads at most maxLineBytes and reports a line that exceeded it as a
// protocol error, which closes that session and leaves the rest alone.
//
// The invariant is that len(buf) == end and pos <= end. Every read appends to buf
// rather than writing into spare capacity, because writing into capacity does not
// change the slice's length - the first version of this did that, and the scan
// below then indexed a zero-length slice with an end that had already advanced,
// which is the panic that produced "index out of range [0] with length 0".
type boundedReader struct {
	r   io.Reader
	buf []byte
	pos int
	scr []byte
}

// readChunk is how much one Read asks for.
const readChunk = 4096

func newBoundedReader(r io.Reader) *boundedReader {
	return &boundedReader{r: r, scr: make([]byte, readChunk)}
}

// ReadLine returns one line without its terminating newline. A line is returned
// with ok == false only when the stream ended or failed; the error is reported
// through err so the caller can tell a clean close from a broken one.
func (b *boundedReader) ReadLine() (line string, err error) {
	for {
		// A complete line already buffered?
		for i := b.pos; i < len(b.buf); i++ {
			if b.buf[i] == '\n' {
				line = string(b.buf[b.pos:i])
				b.pos = i + 1
				// Strip a trailing \r so a terminal in raw-ish mode works too.
				if n := len(line); n > 0 && line[n-1] == '\r' {
					line = line[:n-1]
				}
				return line, nil
			}
		}
		// Compact before growing, so consumed bytes are dropped rather than
		// accumulated: a session that runs a thousand commands must not carry
		// their whole transcript in one buffer.
		if b.pos > 0 {
			b.buf = append(b.buf[:0], b.buf[b.pos:]...)
			b.pos = 0
		}
		if len(b.buf) >= maxLineBytes {
			return "", fmt.Errorf("a protocol line exceeded %d bytes", maxLineBytes)
		}
		n, err := b.r.Read(b.scr)
		if n > 0 {
			b.buf = append(b.buf, b.scr[:n]...)
		}
		if err != nil {
			if err == io.EOF && len(b.buf) > b.pos {
				// A final line with no trailing newline still counts: a client that
				// writes one command and closes the stream is a normal way to drive
				// this protocol from a script.
				line = string(b.buf[b.pos:])
				b.pos = len(b.buf)
				return line, nil
			}
			return "", err
		}
		if n == 0 {
			// A reader that returns nothing and no error is not progress. Rather
			// than spin on it, treat it as the end of the stream: a reader that
			// behaves this way is closed or broken, and a busy loop in a session
			// goroutine is worse than a closed session.
			if len(b.buf) > b.pos {
				line = string(b.buf[b.pos:])
				b.pos = len(b.buf)
				return line, nil
			}
			return "", io.EOF
		}
	}
}
