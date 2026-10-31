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

package evidence

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/tests/harness"
)

// These tests drive ktty through the surface a module and the host actually get:
// tty:open through the init context, the privileged acts through the host-installed
// credential, and the denials through a loaded probe.
//
// The credential is a []byte the test owns, and every helper hands the kernel a COPY,
// because ownership of the bytes transfers on every call - the kernel wipes what it is
// given. A test that passed its own slice twice would observe the second call fail, and
// that failure would be the contract working rather than a bug.

// ttyCounter keeps console lines and module names unique per test, so one test cannot
// observe another's evidence through the process-wide console and audit chain.
var ttyCounter = &ttySequence{}

type ttySequence struct {
	mu sync.Mutex
	n  int
}

func (c *ttySequence) next(prefix string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.n++
	return prefix + "-" + harness.Itoa(c.n)
}

// ttyCredential builds a credential of the given length from a fixed pattern. It is
// deterministic on purpose: a random credential would make a failure irreproducible, and
// nothing here tests the credential's unpredictability - that is the host's job.
func ttyCredential(n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = byte('a' + i%26)
	}
	return out
}

// installCredential installs a copy and returns the credential so the test can present
// it later. The kernel wipes the slice it is given, which is why this returns a second
// copy rather than the one it handed over.
func installCredential(t *testing.T, k *kernel.Kernel, n int) []byte {
	t.Helper()
	cred := ttyCredential(n)
	require.NoError(t, k.InstallConsoleCredential(append([]byte(nil), cred...)),
		"installing a console credential is a host capability")
	return cred
}

// ---------------------------------------------------------------------------
// The grant and its denial counterpart.

// TestTTYOpenRequiresInitDomain pins the existing policy fact as runtime behaviour: the
// console is an operator surface, so init can open one and a module cannot.
func TestTTYOpenRequiresInitDomain(t *testing.T) {
	buf := harness.QuietConsole(t)
	k := harness.BootOne(t)

	fd, err := kernel.TTYOpen(k.InitContext())
	require.NoError(t, err, "init holds tty:open")
	assert.NotEqual(t, kernel.FD(0), fd)

	var moduleErr error
	name := ttyCounter.next("tty-probe")
	probe := &harness.Probe{Load: func(ctx kernel.SContext) error {
		_, moduleErr = kernel.TTYOpen(ctx)
		return nil
	}}
	harness.RegisterProbe(t, name, probe)
	pid, err := k.Load(kernel.Manifest{
		Name: name, Version: "1", MinKernelAPI: kernel.KernelAPI, MaxKernelAPI: kernel.KernelAPI,
		Require: []kernel.Op{kernel.OpLogWrite},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Unload(pid) })

	require.Error(t, moduleErr, "the plugin domain must not hold tty:open")
	assert.True(t, kernel.IsDenied(moduleErr), "want a policy denial, got %v", moduleErr)

	var sawDenial bool
	for _, r := range harness.Faults(buf) {
		if strings.Contains(r.Msg, "avc: denied { tty:open }") &&
			strings.Contains(r.Msg, string(kernel.DomainPlugin)) {
			sawDenial = true
		}
	}
	assert.True(t, sawDenial, "the canonical avc line must name the refusing domain")
	assert.False(t, kernel.Allowed(kernel.DomainPlugin, kernel.OpTTYOpen),
		"and the ceiling itself must keep refusing tty:open to the plugin domain")
}

// TestTTYHandleIsKindChecked pins the house kind-check contract. A console handle is not
// interchangeable with any other resource, and passing one where the other is expected
// fails with the exact house format rather than being reinterpreted.
func TestTTYHandleIsKindChecked(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)
	cred := installCredential(t, k, 32)

	ttyFD, err := kernel.TTYOpen(k.InitContext())
	require.NoError(t, err)

	// A timer handle is the other kind to compare against: init holds sched:timer, so
	// this is a real fd-table resource of a genuinely different kind rather than a
	// receipt the kernel would refuse to open in the first place.
	timerFD, err := kernel.SchedTimer(k.InitContext(), kernel.TimerSpec{
		Label: ttyCounter.next("tty-timer"), DelayMillis: 60000,
		Fn: func(kernel.SContext, <-chan struct{}) {},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.InitContext().SyscallClose(timerFD) })

	_, err = kernel.TTYRead(k.InitContext(), timerFD, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a tty",
		"another subsystem's handle must not be reinterpreted as a console handle")

	// And the console handle is reported as what it is.
	var saw bool
	for _, info := range kernel.FDList(k.InitContext().PID()) {
		if info.FD == ttyFD {
			saw = true
			assert.Equal(t, "tty", info.Kind)
		}
	}
	assert.True(t, saw, "the console handle must be in the fd table as kind tty")

	// A credential presented through the wrong kind of handle is refused, so the
	// credential cannot be used as an oracle through a handle the caller does not own.
	_, err = kernel.TTYProcessTable(k.InitContext(), timerFD, append([]byte(nil), cred...))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not a tty")
}

// TestTTYHandleReclamationDropsTheRegistryEntry pins that closing a console handle frees
// the registry slot. Without it a load-and-close cycle would leak state that nothing can
// reach again, because pids are never reused.
//
// The module-unload variant of this case is deliberately not driven here, and the reason
// is a policy fact rather than a test gap: tty:open is refused to the plugin domain, so no
// module can ever hold a console handle, and init never goes through UnloadModule. The
// backstop for that case is dropTTYsFor, which the integrator wires into module.go for a
// future in which the owner widens tty:open.
func TestTTYHandleReclamationDropsTheRegistryEntry(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	fd, err := kernel.TTYOpen(k.InitContext())
	require.NoError(t, err)
	assert.Len(t, kernel.TTYList(k.InitContext().PID()), 1)

	require.NoError(t, k.InitContext().SyscallClose(fd))
	assert.Empty(t, kernel.TTYList(k.InitContext().PID()),
		"an explicitly closed handle must leave the registry")

	// Both double-close paths reclamation depends on: through the fd table the entry is
	// gone, and on the resource object it reports errClosed. Code handling only one of
	// the two reports a spurious failure during unload.
	err = k.InitContext().SyscallClose(fd)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is not open in pid")

	// And the slot is genuinely free: a second open now succeeds, which it could not if
	// the registry entry had survived the close.
	fd2, err := kernel.TTYOpen(k.InitContext())
	require.NoError(t, err, "the per-pid slot must be released by the close")
	assert.NotEqual(t, fd, fd2, "a released fd number is not reissued within a boot")
}

// TestTTYOpenCeilingIsAttributed pins that the per-pid ceiling refuses with a fault naming
// the pid. A refusal an operator cannot attribute is a refusal nobody can act on, which is
// why lock.go and pipe.go emit their own attributed fault before delegating to install().
func TestTTYOpenCeilingIsAttributed(t *testing.T) {
	buf := harness.QuietConsole(t)
	k := harness.BootOne(t)

	fd, err := kernel.TTYOpen(k.InitContext())
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.InitContext().SyscallClose(fd) })

	_, err = kernel.TTYOpen(k.InitContext())
	require.Error(t, err)
	assert.True(t, errors.Is(err, kernel.ErrTTYLimit), "want ErrTTYLimit, got %v", err)

	var saw bool
	for _, r := range harness.Faults(buf) {
		if strings.Contains(r.Msg, "tty ceiling reached") {
			saw = true
		}
	}
	assert.True(t, saw, "the ceiling refusal must be attributed to a pid on the console")
	assert.Equal(t, 1, kernel.TTYStatsSnapshot().MaxPerPID)
}

// ---------------------------------------------------------------------------
// The credential: unforgeable, and no oracle.

// TestConsoleCredentialIsNeverDisclosed is the load-bearing security test. The credential
// is installed by the host and never leaves the kernel: not in console history, not on the
// audit chain, not in the dump, not in the stats snapshot, and not in a refusal message.
func TestConsoleCredentialIsNeverDisclosed(t *testing.T) {
	buf := harness.QuietConsole(t)
	k := harness.BootOne(t)
	cred := installCredential(t, k, 32)
	secret := string(cred)

	fd, err := kernel.TTYOpen(k.InitContext())
	require.NoError(t, err)

	// Exercise every path that touches the credential: a successful privileged act, a
	// wrong credential, and an empty one.
	name := ttyCounter.next("tty-loaded")
	harness.RegisterProbe(t, name, &harness.NoopModule{})
	_, err = kernel.TTYLoadModule(k.InitContext(), fd, append([]byte(nil), cred...),
		kernel.Manifest{
			Name: name, Version: "1", MinKernelAPI: kernel.KernelAPI, MaxKernelAPI: kernel.KernelAPI,
		})
	require.NoError(t, err)

	_, err = kernel.TTYProcessTable(k.InitContext(), fd, []byte("definitely-not-the-credential"))
	require.Error(t, err)
	_, err = kernel.TTYProcessTable(k.InitContext(), fd, nil)
	require.Error(t, err)

	// Read the console back through the handle, which is the path that returns console
	// content to a caller.
	window, err := kernel.TTYRead(k.InitContext(), fd, 0)
	require.NoError(t, err)

	// Now assert absence everywhere the credential could leak.
	assert.NotContains(t, buf.String(), secret, "the console must not render the credential")
	for _, r := range window.Records {
		assert.NotContains(t, r.Msg, secret)
		enc, merr := json.Marshal(r.Fields)
		require.NoError(t, merr)
		assert.NotContains(t, string(enc), secret)
	}
	for _, e := range auditQuery(t, "") {
		assert.NotContains(t, e.Msg, secret)
		enc, merr := json.Marshal(e.Fields)
		require.NoError(t, merr)
		assert.NotContains(t, string(enc), secret, "audit seq %d discloses the credential", e.Seq)
	}

	var dump bytes.Buffer
	require.NoError(t, kernel.Dump(&dump))
	assert.NotContains(t, dump.String(), secret, "the dump must not render the credential")

	// Nor its length, which narrows a brute-force search. keyring records neither a
	// secret nor its size for exactly this reason.
	assert.NotContains(t, dump.String(), fmt.Sprintf("credential_bytes=%d", len(secret)))
	stats := kernel.TTYStatsSnapshot()
	assert.True(t, stats.Credential, "the snapshot reports that a credential exists")
	assert.NotContains(t, fmt.Sprintf("%+v", stats), secret)
}

// TestConsoleCredentialRefusalIsIndistinguishable pins that wrong, empty and uninstalled
// produce the same error. A caller that could tell those apart has an oracle for whether
// a credential exists, which converts a guess into a search.
func TestConsoleCredentialRefusalIsIndistinguishable(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)
	fd, err := kernel.TTYOpen(k.InitContext())
	require.NoError(t, err)

	// No credential installed at all.
	_, errNone := kernel.TTYProcessTable(k.InitContext(), fd, []byte("anything-at-all-32bytes!"))
	require.Error(t, errNone)

	// Now install one and try wrong and empty candidates.
	installCredential(t, k, 32)
	_, errWrong := kernel.TTYProcessTable(k.InitContext(), fd, []byte("anything-at-all-32bytes!"))
	require.Error(t, errWrong)
	_, errEmpty := kernel.TTYProcessTable(k.InitContext(), fd, nil)
	require.Error(t, errEmpty)

	assert.Equal(t, errNone.Error(), errWrong.Error(),
		"no-credential and wrong-credential must be the same refusal")
	assert.Equal(t, errWrong.Error(), errEmpty.Error(),
		"wrong-credential and empty-credential must be the same refusal")

	// The refusal is not a policy denial, and the distinction matters: an operator
	// reading a denial looks for a grant problem, and here there is none.
	assert.False(t, kernel.IsDenied(errWrong),
		"a missing console key is not a policy denial")
	assert.Empty(t, kernel.DenialReason(errWrong))

	var ttyErr *kernel.TTYError
	require.True(t, errors.As(errWrong, &ttyErr), "want a typed TTYError, got %T", errWrong)
	assert.Nil(t, ttyErr.Unwrap(), "a credential refusal wraps no sentinel")
}

// TestConsoleCredentialRefusalIsNotABruteForceOracle pins the aggregate-visible,
// per-candidate-invisible split. The loop is small and deterministic: the invariant holds
// at any N, and a thousand-iteration loop would be brute-force-shaped test code asserting
// a property that does not depend on the iteration count.
func TestConsoleCredentialRefusalIsNotABruteForceOracle(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)
	installCredential(t, k, 32)
	fd, err := kernel.TTYOpen(k.InitContext())
	require.NoError(t, err)

	before := kernel.TTYStatsSnapshot()

	candidates := [][]byte{
		[]byte("a-32-byte-candidate-value-here!!"),
		[]byte("b-32-byte-candidate-value-here!!"),
		[]byte("c-32-byte-candidate-value-here!!"),
		{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
			0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
			0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f},
		nil,
		{},
	}
	var messages []string
	for _, c := range candidates {
		presented := append([]byte(nil), c...)
		_, err := kernel.TTYProcessTable(k.InitContext(), fd, presented)
		require.Error(t, err)
		messages = append(messages, err.Error())

		// Ownership of the bytes transferred when they crossed the syscall boundary, so
		// the kernel wipes them on the refusal path as well as the success path. A
		// candidate left intact in the caller's heap is a credential-shaped secret that
		// survives the call it was rejected by, which is the same hazard keyring.go
		// wipes for. This assertion is the only thing that catches removing the wipe
		// from the refusal path: nothing about the returned error changes.
		// Elementwise rather than assert.Equal against a fresh zero slice, because a
		// nil candidate and an empty one are both "no bytes" and must not be compared
		// by slice identity: wipe zeroes in place and does not truncate, so the
		// property is that the length is unchanged and every byte is zero.
		assert.Len(t, presented, len(c), "wiping must not truncate the caller's slice")
		for i, b := range presented {
			assert.Zero(t, b, "byte %d of a refused candidate was not wiped", i)
		}
	}

	for i, m := range messages {
		assert.Equal(t, messages[0], m, "candidate %d produced a distinguishable refusal", i)
	}

	after := kernel.TTYStatsSnapshot()
	assert.Equal(t, int64(len(candidates)), after.Refused-before.Refused,
		"refusals are counted in aggregate, so an operator sees the attempt")
	assert.Equal(t, before.Issued, after.Issued, "and no candidate was accepted")

	// Two properties of this gate are deliberately NOT asserted here, because no
	// functional test can observe them and a green suite must not read as covering them:
	//
	//   - That the comparison is constant-time. Replacing
	//     constantTimeEqualBytes with `string(working) == string(credential)` produces
	//     identical results for every input, so it differs only in timing, which is not
	//     reliably measurable in a test suite. The property is held by reusing
	//     keyring's helper rather than by a test, and mutation testing confirms that
	//     swapping it out stays green. Reviewing that this call site still uses that
	//     helper is the control.
	//   - That a late install cannot land in the next boot. The generation counter
	//     closes a window in which a host call that already passed its shutdown check
	//     is in flight while Shutdown runs resetKernel. Reaching it needs the two to
	//     interleave at the instruction level, and a test that forced it would be
	//     asserting on a race it had to create. TestTTYInstallAfterShutdownIsRefused
	//     covers the shutdown-flag path, which is the one an operator can actually hit.
}

// TestConsoleCredentialInstallValidatesItsInput pins that the installer refuses a
// credential too short to be one. Accepting a two-byte key would make the gate
// decorative while looking like a control.
func TestConsoleCredentialInstallValidatesItsInput(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)

	require.Error(t, k.InstallConsoleCredential(nil), "an empty credential is not a credential")
	require.Error(t, k.InstallConsoleCredential([]byte("short")),
		"a credential below the floor is not a credential")
	require.Error(t, k.InstallConsoleCredential(make([]byte, 5000)),
		"a credential above the ceiling is refused rather than copied")

	assert.False(t, kernel.TTYStatsSnapshot().Credential,
		"a refused install must not leave a credential installed")

	// The caller's bytes are wiped on the refusal paths too, so a host that read the
	// credential from an environment variable does not leave it recoverable.
	candidate := ttyCredential(3)
	require.Error(t, k.InstallConsoleCredential(candidate))
	assert.Equal(t, []byte{0, 0, 0}, candidate, "a refused credential must still be wiped")

	// Rotation overwrites, and the new credential is the one that works.
	first := installCredential(t, k, 32)
	second := ttyCredential(40)
	require.NoError(t, k.InstallConsoleCredential(append([]byte(nil), second...)))

	fd, err := kernel.TTYOpen(k.InitContext())
	require.NoError(t, err)
	_, err = kernel.TTYProcessTable(k.InitContext(), fd, append([]byte(nil), first...))
	require.Error(t, err, "the rotated-out credential must stop working")

	table, err := kernel.TTYProcessTable(k.InitContext(), fd, append([]byte(nil), second...))
	require.NoError(t, err, "the new credential must work")
	assert.NotEmpty(t, table)
}

// ---------------------------------------------------------------------------
// The privileged acts and their evidence.

// TestTTYPrivilegedActionsLeaveAuditEvidence pins that every privileged act through the
// console is on the chain. A console that can load a module without recording it is a
// console that can be used to erase itself.
func TestTTYPrivilegedActionsLeaveAuditEvidence(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)
	cred := installCredential(t, k, 32)
	fd, err := kernel.TTYOpen(k.InitContext())
	require.NoError(t, err)

	name := ttyCounter.next("tty-privileged")
	harness.RegisterProbe(t, name, &harness.NoopModule{})
	manifest := kernel.Manifest{
		Name: name, Version: "1", MinKernelAPI: kernel.KernelAPI, MaxKernelAPI: kernel.KernelAPI,
	}

	pid, err := kernel.TTYLoadModule(k.InitContext(), fd, append([]byte(nil), cred...), manifest)
	require.NoError(t, err)
	assert.NotZero(t, pid)

	table, err := kernel.TTYProcessTable(k.InitContext(), fd, append([]byte(nil), cred...))
	require.NoError(t, err)
	var sawModule bool
	for _, p := range table {
		if p.PID == pid {
			sawModule = true
			assert.Equal(t, kernel.DomainPlugin, p.Domain)
		}
	}
	assert.True(t, sawModule, "ps must read the one real process table, and the load must be in it")

	require.NoError(t, kernel.TTYUnloadModule(k.InitContext(), fd, append([]byte(nil), cred...), pid))

	// The provenance records, in the order the acts happened. The console-sourced
	// record follows module.go's own AuditLoad rather than preceding it: a record
	// written before the load would state an intention as an accomplished fact, and on
	// a failed load the chain would say the module loaded and was then rejected.
	msgs := auditMsgs(t, kernel.AuditPolicy)
	loadIdx, unloadIdx, psIdx := -1, -1, -1
	for i, m := range msgs {
		switch m {
		case "console module load":
			loadIdx = i
		case "console module unload":
			unloadIdx = i
		case "console process table read":
			psIdx = i
		}
	}
	require.NotEqual(t, -1, loadIdx, "the console-sourced load record must be on the chain")
	require.NotEqual(t, -1, unloadIdx)
	require.NotEqual(t, -1, psIdx)
	assert.Less(t, loadIdx, psIdx, "records must be in the order the acts happened")
	assert.Less(t, psIdx, unloadIdx)

	// And the loader's own records are there too, which is what makes the two
	// attributable separately: the console record says where the command came from and
	// the loader's record says what happened.
	loader := auditMsgs(t, kernel.AuditLoad)
	assert.NotEmpty(t, loader, "module.go's own load record must still be written")

	// The chain is intact across all of it, which is the property that makes any of
	// these records worth reading.
	assert.Equal(t, -1, kernel.VerifyChain(kernel.AuditQuery(kernel.AuditFilter{}), kernel.AuditGenesis),
		"the audit chain must verify")
}

// TestTTYPrivilegedActWithWrongCredentialLeavesNoLoadEvidence is the denial counterpart.
// A refused act writes an escalation and no load record, so an attacker cannot produce
// evidence of an authorization that did not happen.
func TestTTYPrivilegedActWithWrongCredentialLeavesNoLoadEvidence(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)
	installCredential(t, k, 32)
	fd, err := kernel.TTYOpen(k.InitContext())
	require.NoError(t, err)

	before := countAuditMsg(t, kernel.AuditLoad, "")
	name := ttyCounter.next("tty-wrongcred")
	harness.RegisterProbe(t, name, &harness.NoopModule{})

	_, err = kernel.TTYLoadModule(k.InitContext(), fd,
		[]byte("a-wrong-credential-of-length-32!"),
		kernel.Manifest{
			Name: name, Version: "1", MinKernelAPI: kernel.KernelAPI, MaxKernelAPI: kernel.KernelAPI,
		})
	require.Error(t, err)

	assert.Equal(t, before, countAuditMsg(t, kernel.AuditLoad, ""),
		"a refused load must not write a load record")
	assert.Zero(t, countAuditMsg(t, kernel.AuditPolicy, "console module load"))

	var saw bool
	for _, e := range auditQuery(t, kernel.AuditEscalation) {
		if e.Msg == "console credential refused" {
			saw = true
			assert.Equal(t, k.InitContext().PID(), e.PID)
		}
	}
	assert.True(t, saw, "the refused credential must be recorded as an escalation")
	assert.Equal(t, -1, kernel.VerifyChain(kernel.AuditQuery(kernel.AuditFilter{}), kernel.AuditGenesis))
}

// TestTTYLoadModuleStillChecksModuleLoad pins that the credential is an additional fact
// and not a substitute for the grant. LoadModule runs its own check inside, so policy is
// enforced twice and a future tty holder without module:load is still refused.
func TestTTYLoadModuleStillChecksModuleLoad(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)
	cred := installCredential(t, k, 32)
	fd, err := kernel.TTYOpen(k.InitContext())
	require.NoError(t, err)

	// The delegation is asserted behaviourally: a load that succeeds proves init's
	// module:load was consulted, and the ceiling fact below proves a domain without it
	// could not have got here even holding the credential.
	assert.True(t, kernel.Allowed(kernel.DomainInit, kernel.OpModuleLoad))
	assert.False(t, kernel.Allowed(kernel.DomainPlugin, kernel.OpTTYOpen),
		"a plugin cannot reach the credential check at all")

	// A manifest that fails validation is refused by the loader, and the console record
	// is not written for it: the provenance record describes an accomplished act.
	before := countAuditMsg(t, kernel.AuditPolicy, "console module load")
	_, err = kernel.TTYLoadModule(k.InitContext(), fd, append([]byte(nil), cred...),
		kernel.Manifest{Name: "", Version: "1"})
	require.Error(t, err)
	assert.Equal(t, before, countAuditMsg(t, kernel.AuditPolicy, "console module load"),
		"a failed load must not be recorded as an accomplished one")
}

// ---------------------------------------------------------------------------
// Reading and writing through the handle.

// TestTTYReadIsBoundedAndCursorHonest pins the two properties a console view has to have:
// one read returns a bounded window rather than the whole buffer, and the window says
// where it started so a caller can tell that records were evicted rather than assuming
// continuity it does not have.
func TestTTYReadIsBoundedAndCursorHonest(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)
	fd, err := kernel.TTYOpen(k.InitContext())
	require.NoError(t, err)

	console := kernel.KernelConsole()
	console.SetLimit(4096)
	t.Cleanup(func() { console.SetLimit(4096) })

	const bound = 256 // maxTTYReadLines
	for range bound + 40 {
		require.NoError(t, kernel.TTYWrite(k.InitContext(), fd, kernel.LogInfo,
			ttyCounter.next("tty-line")))
	}

	window, err := kernel.TTYRead(k.InitContext(), fd, 0)
	require.NoError(t, err)
	assert.Len(t, window.Records, bound, "one read must return a bounded window")
	assert.Zero(t, window.Base)

	// The second page continues where the first stopped, which is what makes `since`
	// usable as a cursor at all. Its length is derived from the history rather than
	// assumed, because the console also carries this boot's own records alongside the
	// lines written here.
	history := kernel.KernelConsole().History()
	require.Greater(t, len(history), bound, "the test must have written past the bound")
	resume := window.Base + len(window.Records)
	next, err := kernel.TTYRead(k.InitContext(), fd, resume)
	require.NoError(t, err)
	assert.Equal(t, resume, next.Base, "the window must report where it started")
	assert.Len(t, next.Records, len(history)-resume)
	assert.NotEqual(t, window.Records[0].Msg, next.Records[0].Msg)

	// A negative since is treated as the beginning rather than refused, and a since past
	// the end returns an empty window with the real base rather than silently clamping.
	fromStart, err := kernel.TTYRead(k.InitContext(), fd, -5)
	require.NoError(t, err)
	assert.Zero(t, fromStart.Base)

	past, err := kernel.TTYRead(k.InitContext(), fd, 1<<20)
	require.NoError(t, err)
	assert.Empty(t, past.Records)
	assert.Greater(t, past.Base, 0, "an exhausted cursor reports where it landed")

	// Retention is what makes `since` unable to be a stable cursor, and Dropped is how
	// a caller finds out.
	console.SetLimit(8)
	for range 20 {
		require.NoError(t, kernel.TTYWrite(k.InitContext(), fd, kernel.LogInfo, "evict me"))
	}
	dropped, err := kernel.TTYRead(k.InitContext(), fd, 0)
	require.NoError(t, err)
	assert.Greater(t, dropped.Dropped, int64(0), "evictions must be visible to the reader")
	assert.LessOrEqual(t, len(dropped.Records), 8)
}

// TestTTYReadIsRefusedOnAClosedHandle pins that a handle is a resource with a lifetime
// rather than an integer that keeps working.
func TestTTYReadIsRefusedOnAClosedHandle(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)
	fd, err := kernel.TTYOpen(k.InitContext())
	require.NoError(t, err)

	require.NoError(t, k.InitContext().SyscallClose(fd))

	_, err = kernel.TTYRead(k.InitContext(), fd, 0)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "is not open in pid")

	err = kernel.TTYWrite(k.InitContext(), fd, kernel.LogInfo, "after close")
	require.Error(t, err)

	// And another pid's handle is not this pid's handle, which is the per-pid property
	// the fd table exists to provide.
	name := ttyCounter.next("tty-otherpid")
	probe := &harness.Probe{}
	harness.RegisterProbe(t, name, probe)
	pid, err := k.Load(kernel.Manifest{
		Name: name, Version: "1", MinKernelAPI: kernel.KernelAPI, MaxKernelAPI: kernel.KernelAPI,
		Require: []kernel.Op{kernel.OpLogWrite},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Unload(pid) })

	_, err = kernel.TTYRead(probe.Ctx, fd, 0)
	require.Error(t, err, "a module must not reach init's console handle by number")
	assert.True(t, kernel.IsDenied(err), "the policy gate fires before the fd lookup: %v", err)
}

// TestTTYWriteAddsNoFaultBypass pins that writing through a console handle is log:write
// with the same rules. A console handle that could emit a fault record would be a way
// around the reservation that makes fault records trustworthy.
func TestTTYWriteAddsNoFaultBypass(t *testing.T) {
	buf := harness.QuietConsole(t)
	k := harness.BootOne(t)
	fd, err := kernel.TTYOpen(k.InitContext())
	require.NoError(t, err)

	require.NoError(t, kernel.TTYWrite(k.InitContext(), fd, kernel.LogInfo, "console info"))
	require.NoError(t, kernel.TTYWrite(k.InitContext(), fd, kernel.LogFault, "console fault"))

	var sawInfo, sawFault bool
	for _, r := range harness.Records(t, buf) {
		if r.Msg == "console info" {
			sawInfo = true
		}
		if r.Msg == "console fault" && r.Level == kernel.LogFault {
			sawFault = true
		}
	}
	assert.True(t, sawInfo)
	assert.True(t, sawFault, "init holds the fault level, as it does through SyscallLog")

	// A line break is refused rather than rewritten. Silently sanitizing would change
	// what the operator asked to log, and refusing is the honest outcome: a message
	// containing a newline would render as two console lines and the second would look
	// like a kernel record no kernel call produced.
	err = kernel.TTYWrite(k.InitContext(), fd, kernel.LogInfo, "first\nINJECTED fault line")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "line break")
	assert.NotContains(t, buf.String(), "INJECTED")

	err = kernel.TTYWrite(k.InitContext(), fd, kernel.LogInfo, "carriage\rreturn")
	require.Error(t, err)

	// An invented level is refused at the boundary rather than rendered as an unknown
	// string an operator's log filter does not match.
	err = kernel.TTYWrite(k.InitContext(), fd, kernel.Level("smuggle"), "unknown level")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "unknown console level")

	// An over-long line is refused rather than truncated.
	err = kernel.TTYWrite(k.InitContext(), fd, kernel.LogInfo, strings.Repeat("x", 5000))
	require.Error(t, err)
	assert.True(t, errors.Is(err, kernel.ErrTTYLimit), "want ErrTTYLimit, got %v", err)

	// The fault-level reservation is reproduced on this path, and that reproduction is
	// NOT reachable by any test today. It is defence in depth behind the tty:open gate
	// rather than a live control, and the domain facts below are what make that so:
	// the plugin domain holds log:write but not tty:open, so a module can never hold a
	// console handle to write through, and the only domains that can are kernel and
	// init - both of which legitimately hold the fault level through SyscallLog.
	//
	// That is stated rather than left implicit because mutation testing confirms it:
	// replacing the reservation with `if false` leaves this whole suite green. The
	// assertion worth having is therefore the one on the gate that makes the branch
	// unreachable, so that widening tty:open without noticing this branch becomes a
	// visible test failure rather than a silent hole.
	assert.True(t, kernel.Allowed(kernel.DomainPlugin, kernel.OpLogWrite),
		"a plugin may write to the console through log:write")
	assert.False(t, kernel.Allowed(kernel.DomainPlugin, kernel.OpTTYOpen),
		"and may not hold a console handle, which is what keeps the fault-level "+
			"reservation on this path unreachable")
}

// TestTTYWriteRidesLogWriteNotTTYOpen pins the op assignment. Writing to the console is
// log:write and adds no privilege, so a context holding tty:open but not log:write cannot
// write, and one holding log:write but not tty:open still cannot - the handle gate is
// separate from the write gate.
func TestTTYWriteRidesLogWriteNotTTYOpen(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)
	fd, err := kernel.TTYOpen(k.InitContext())
	require.NoError(t, err)

	// A module holds log:write and not tty:open, so it cannot reach the write path
	// through a console handle even though the write op itself is one it holds.
	name := ttyCounter.next("tty-writer")
	var moduleErr error
	probe := &harness.Probe{Load: func(ctx kernel.SContext) error {
		moduleErr = kernel.TTYWrite(ctx, fd, kernel.LogInfo, "from a module")
		return nil
	}}
	harness.RegisterProbe(t, name, probe)
	pid, err := k.Load(kernel.Manifest{
		Name: name, Version: "1", MinKernelAPI: kernel.KernelAPI, MaxKernelAPI: kernel.KernelAPI,
		Require: []kernel.Op{kernel.OpLogWrite},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Unload(pid) })

	require.Error(t, moduleErr)
	// The refusal is the per-pid fd table, which is the STRONGER of the two gates:
	// init's console handle does not exist in the module's table at all, so there is
	// nothing to write through. A module holding log:write still cannot borrow another
	// pid's handle by number, which is the property the fd table exists to provide, and
	// it fires before any log:write check because the handle must resolve first.
	assert.Contains(t, moduleErr.Error(), "is not open in pid",
		"want the per-pid handle gate, got %v", moduleErr)
}

// ---------------------------------------------------------------------------
// Reset and the shutdown boundary.

// TestTTYsResetAcrossRestart pins that an operator session's console key does not survive
// the operator's decision to restart. A credential carried across a boot would be a stale
// trust fact in a kernel that has re-read everything else.
func TestTTYsResetAcrossRestart(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)
	installCredential(t, k, 32)
	fd, err := kernel.TTYOpen(k.InitContext())
	require.NoError(t, err)
	require.NoError(t, kernel.TTYWrite(k.InitContext(), fd, kernel.LogInfo, "before restart"))
	assert.True(t, kernel.TTYStatsSnapshot().Credential)
	require.NoError(t, k.Shutdown())

	k2 := harness.BootOne(t)
	stats := kernel.TTYStatsSnapshot()
	assert.False(t, stats.Credential, "the credential must not survive a restart")
	assert.Zero(t, stats.Open)
	assert.Zero(t, stats.Issued)
	assert.Zero(t, stats.Refused)
	assert.Zero(t, stats.Reads)
	assert.Zero(t, stats.Writes)
	assert.Empty(t, kernel.TTYList(k2.InitContext().PID()), "no console handle survives")

	// And a privileged act now fails for want of a credential, which is the observable
	// consequence: the host must install it again after every boot.
	fd2, err := kernel.TTYOpen(k2.InitContext())
	require.NoError(t, err)
	_, err = kernel.TTYProcessTable(k2.InitContext(), fd2, ttyCredential(32))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "console credential")
}

// TestTTYInstallAfterShutdownIsRefused pins the race the generation counter closes. A host
// call that passed its shutdown check can still be in flight when Shutdown runs
// resetKernel; without the re-check under the lock, a late install would leave a live
// console credential in the fresh boot.
func TestTTYInstallAfterShutdownIsRefused(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)
	require.NoError(t, k.Shutdown())

	err := k.InstallConsoleCredential(ttyCredential(32))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "shut down")

	// The credential the caller handed over is wiped even though the install was
	// refused, so a host does not leave its console key in its own heap.
	candidate := ttyCredential(32)
	require.Error(t, k.InstallConsoleCredential(candidate))
	assert.Equal(t, make([]byte, 32), candidate, "a refused credential must still be wiped")

	assert.False(t, kernel.TTYStatsSnapshot().Credential)
}

// TestTTYSurfaceIsRefusedAfterShutdown pins the same boundary on the syscalls.
func TestTTYSurfaceIsRefusedAfterShutdown(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)
	installCredential(t, k, 32)
	fd, err := kernel.TTYOpen(k.InitContext())
	require.NoError(t, err)
	require.NoError(t, k.Shutdown())

	_, err = kernel.TTYRead(k.InitContext(), fd, 0)
	require.Error(t, err, "a console read must not serve a kernel that is down")

	// The process table is empty here, and that is correct rather than a gap:
	// resetKernel cleared it, because it is per-boot history and a restarted kernel
	// must be indistinguishable from a first-booted one. TestTTYsResetAcrossRestart
	// pins the same property for the console credential.
	assert.Empty(t, kernel.ProcTable())
}

// ---------------------------------------------------------------------------
// Local helpers, following the pattern the other evidence suites use.

// TestTTYPresentersWipeTheCredentialTheyAreGiven pins that the three console entry
// points that take a presented credential - load, unload and process table - wipe the
// caller's slice on every path, including refusals.
//
// The wipe used to be nine individually remembered calls inside each function, and a
// return added above them wiped nothing: probed by inserting one guarded on a length no
// test uses, the credential came back intact and all 20 packages stayed green. The three
// now carry a single deferred wipe, so a new refusal branch inherits it instead of
// having to remember it - the same shape the installers gained in 94efbcb.
//
// Each case below passes its own copy, because a successful call wipes what it was
// given; passing one slice twice would observe the second call's empty credential rather
// than the contract.
func TestTTYPresentersWipeTheCredentialTheyAreGiven(t *testing.T) {
	harness.QuietConsole(t)
	k := harness.BootOne(t)
	cred := installCredential(t, k, 32)

	fd, err := kernel.TTYOpen(k.InitContext())
	require.NoError(t, err)

	// A refusal before the credential is even compared: a handle of the wrong kind.
	timerFD, err := kernel.SchedTimer(k.InitContext(), kernel.TimerSpec{
		Label: ttyCounter.next("tty-wipe-timer"), DelayMillis: 60000,
		Fn: func(kernel.SContext, <-chan struct{}) {},
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.InitContext().SyscallClose(timerFD) })

	// assertWiped checks the bytes only, because the wipe must happen on the success
	// path as well as on refusals and a helper that also asserted an error could not
	// be used for both.
	assertWiped := func(t *testing.T, what string, candidate []byte) {
		t.Helper()
		for i, b := range candidate {
			if b != 0 {
				t.Fatalf("%s: byte %d of the presented credential was not wiped", what, i)
			}
		}
	}

	assertRefused := func(t *testing.T, what string, candidate []byte, err error) {
		t.Helper()
		assert.Error(t, err, "%s must be refused", what)
		assertWiped(t, what, candidate)
	}

	name := ttyCounter.next("tty-wipe")
	harness.RegisterProbe(t, name, &harness.NoopModule{})
	manifest := kernel.Manifest{
		Name: name, Version: "1", MinKernelAPI: kernel.KernelAPI, MaxKernelAPI: kernel.KernelAPI,
	}

	// Wrong-kind handle: refused before the credential reaches the comparison.
	wrongKind := append([]byte(nil), cred...)
	_, err = kernel.TTYLoadModule(k.InitContext(), timerFD, wrongKind, manifest)
	assertRefused(t, "TTYLoadModule with a non-console handle", wrongKind, err)

	wrongKind = append([]byte(nil), cred...)
	_, err = kernel.TTYProcessTable(k.InitContext(), timerFD, wrongKind)
	assertRefused(t, "TTYProcessTable with a non-console handle", wrongKind, err)

	wrongKind = append([]byte(nil), cred...)
	err = kernel.TTYUnloadModule(k.InitContext(), timerFD, wrongKind, 999)
	assertRefused(t, "TTYUnloadModule with a non-console handle", wrongKind, err)

	// Wrong credential: refused inside verifyConsoleCredential, which is a different
	// return path and the one a host with a stale credential takes.
	wrong := []byte("not-the-console-credential-32-bytes")
	_, err = kernel.TTYLoadModule(k.InitContext(), fd, wrong, manifest)
	assertRefused(t, "TTYLoadModule with the wrong credential", wrong, err)

	wrong = []byte("not-the-console-credential-32-bytes")
	_, err = kernel.TTYProcessTable(k.InitContext(), fd, wrong)
	assertRefused(t, "TTYProcessTable with the wrong credential", wrong, err)

	wrong = []byte("not-the-console-credential-32-bytes")
	err = kernel.TTYUnloadModule(k.InitContext(), fd, wrong, 999)
	assertRefused(t, "TTYUnloadModule with the wrong credential", wrong, err)

	// And the success path, so the wipe is not a refusal-only habit.
	good := append([]byte(nil), cred...)
	pid, err := kernel.TTYLoadModule(k.InitContext(), fd, good, manifest)
	require.NoError(t, err)
	assertWiped(t, "TTYLoadModule success", good)

	good = append([]byte(nil), cred...)
	table, err := kernel.TTYProcessTable(k.InitContext(), fd, good)
	require.NoError(t, err)
	assert.NotEmpty(t, table)
	assertWiped(t, "TTYProcessTable success", good)

	good = append([]byte(nil), cred...)
	require.NoError(t, kernel.TTYUnloadModule(k.InitContext(), fd, good, pid))
	assertWiped(t, "TTYUnloadModule success", good)
}

// auditQuery reads the chain through the exported query API.
func auditQuery(t *testing.T, kind kernel.AuditKind) []kernel.AuditEntry {
	t.Helper()
	return kernel.AuditQuery(kernel.AuditFilter{Kind: kind, Limit: 8192})
}

// auditMsgs returns the messages of one kind's entries, in chain order.
func auditMsgs(t *testing.T, kind kernel.AuditKind) []string {
	t.Helper()
	var out []string
	for _, e := range auditQuery(t, kind) {
		out = append(out, e.Msg)
	}
	return out
}

// countAuditMsg counts entries of one kind whose message contains substr.
func countAuditMsg(t *testing.T, kind kernel.AuditKind, substr string) int {
	t.Helper()
	n := 0
	for _, e := range auditQuery(t, kind) {
		if substr == "" || strings.Contains(e.Msg, substr) {
			n++
		}
	}
	return n
}
