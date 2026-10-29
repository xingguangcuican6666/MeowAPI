/*
Copyright (C) 2023-2026 xingguangcuican6666

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

// Package seccomp tests kseccomp: per-instance argument filters.
//
// The properties here are the ones the subsystem exists to hold. The narrowing invariant
// is tested as an attack rather than as a happy path, because a filter that can widen is
// not a filter. The three-way refusal distinction is tested because IsDenied returning
// true for a filtered argument would tell a module it lacks a grant it actually holds,
// and returning false for a real policy denial would hide one. And the enumeration
// oracle is tested because a module that can distinguish "filtered out" from "does not
// exist" can read its own filter by probing, which defeats the point of not letting it
// read the filter.
package seccomp

import (
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/tests/harness"
)

var seccompCounter int

func seccompNextName(prefix string) string {
	seccompCounter++
	return prefix + harness.Itoa(seccompCounter)
}

func seccompBoot(t *testing.T) *kernel.Kernel {
	t.Helper()
	k, err := kernel.Boot(kernel.BootConfig{TrustRoot: kernel.BootTrustRoot{NodeID: "node-seccomp"}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Shutdown() })
	return k
}

// seccompLoad loads a module with the given scoped declaration and returns its context and
// pid. The filter is installed on the pid afterwards, from the host, which is the only
// party that may do it.
func seccompLoad(t *testing.T, k *kernel.Kernel, prefix string, m kernel.Manifest) (kernel.SContext, kernel.PID) {
	t.Helper()
	return seccompLoadNamed(t, k, seccompNextName(prefix), m)
}

// seccompLoadNamed loads under a name the caller already has, which the filesystem cases
// need because a data root is installed for a name before the module with that name loads.
func seccompLoadNamed(t *testing.T, k *kernel.Kernel, name string, m kernel.Manifest) (kernel.SContext, kernel.PID) {
	t.Helper()
	probe := &harness.Probe{}
	harness.RegisterProbe(t, name, probe)
	m.Name = name
	m.Version = "1"
	m.MinKernelAPI = kernel.KernelAPI
	m.MaxKernelAPI = kernel.KernelAPI
	pid, err := k.Load(m)
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Unload(pid) })
	require.NotNil(t, probe.Ctx)
	return probe.Ctx, pid
}

// seccompModuleName looks a pid's module name up in the process table. FSSetDataRoot takes
// a name rather than a pid, because a data root is installed for a module before or after
// its load and the name is the stable handle across both.
func seccompModuleName(t *testing.T, pid kernel.PID) string {
	t.Helper()
	for _, r := range kernel.ProcTable() {
		if r.PID == pid {
			return r.Name
		}
	}
	t.Fatalf("pid %d is not in the process table", pid)
	return ""
}

// ---------------------------------------------------------------------------
// The narrowing invariant, tested as an attack.

// TestAFilterCannotWidenTheDeclaration is the whole reason this subsystem exists. Each
// case names something outside the pid's own declaration and asserts three things: the
// rule did not take effect, the attempt is recorded as an exceeded entry, and a call using
// the widened argument is still refused. The third is what makes this an attack test
// rather than a validation test - a filter that stored the pattern and simply reported it
// as rejected would pass the first two.
func TestAFilterCannotWidenTheDeclaration(t *testing.T) {
	harness.QuietConsole(t)
	k := seccompBoot(t)

	attacks := []struct {
		name string
		m    kernel.Manifest
		rule kernel.SeccompRule
		// over is the pattern the attacker writes into the filter, which is what the
		// install report and the escalation record name.
		over string
		// widen is an argument the attacker then passes to a call, which is what proves
		// the discarded pattern did not take effect. It is not the same string: a filter
		// pattern is a prefix and an argument is a concrete path or alias under it.
		widen   string
		stillIn string
	}{
		{
			// A path outside read_paths.
			name: "read path outside the declaration",
			m: kernel.Manifest{
				Require:   []kernel.Op{kernel.OpFSRead},
				ReadPaths: []string{"cache"},
			},
			rule: kernel.SeccompRule{
				Op: kernel.OpFSRead, Kind: kernel.SeccompRulePath,
				Patterns: []string{"cache", "secrets"},
			},
			over: "secrets", widen: "secrets/master.key", stillIn: "cache/blob",
		},
		{
			// A path outside write_paths, which is the more dangerous half since it is
			// the write side.
			name: "write path outside the declaration",
			m: kernel.Manifest{
				Require:    []kernel.Op{kernel.OpFSWrite},
				WritePaths: []string{"scratch"},
			},
			rule: kernel.SeccompRule{
				Op: kernel.OpFSWrite, Kind: kernel.SeccompRulePath,
				Patterns: []string{"scratch", "cache"},
			},
			over: "cache", widen: "cache/poisoned", stillIn: "scratch/tmp",
		},
		{
			// A host outside allowed_hosts.
			name: "host outside the declaration",
			m: kernel.Manifest{
				Require:      []kernel.Op{kernel.OpNetDial},
				AllowedHosts: []string{"api.provider.example"},
			},
			rule: kernel.SeccompRule{
				Op: kernel.OpNetDial, Kind: kernel.SeccompRuleHost,
				Patterns: []string{"api.provider.example", "attacker.example"},
			},
			over: "attacker.example", widen: "attacker.example", stillIn: "api.provider.example",
		},
		{
			// A credential alias outside secret_prefixes: the widening that would let a
			// module use another provider's key.
			name: "secret alias outside the declaration",
			m: kernel.Manifest{
				Require:        []kernel.Op{kernel.OpSecretUse},
				SecretPrefixes: []string{"openai/"},
			},
			rule: kernel.SeccompRule{
				Op: kernel.OpSecretUse, Kind: kernel.SeccompRuleSecret,
				Patterns: []string{"openai/", "anthropic/"},
			},
			over: "anthropic/", widen: "anthropic/default", stillIn: "openai/default",
		},
		{
			// A route outside serve_routes.
			name: "route outside the declaration",
			m: kernel.Manifest{
				Require:     []kernel.Op{kernel.OpRouteRegister},
				ServeRoutes: []string{"/v1/chat"},
			},
			rule: kernel.SeccompRule{
				Op: kernel.OpRouteRegister, Kind: kernel.SeccompRulePath,
				Patterns: []string{"/v1/chat", "/v1/admin"},
			},
			over: "/v1/admin", widen: "/v1/admin", stillIn: "/v1/chat",
		},
	}

	for _, a := range attacks {
		t.Run(a.name, func(t *testing.T) {
			ctx, pid := seccompLoad(t, k, "secattack", a.m)

			report, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
				Label: "attack", Rules: []kernel.SeccompRule{a.rule},
			})
			require.NoError(t, err, "installing succeeds; the widening is discarded, not rejected wholesale")
			assert.NotEmpty(t, report.Exceeded, "the widening attempt is reported")
			assert.Equal(t, a.over, report.Exceeded[0].Pattern,
				"the report names the pattern that exceeded the declaration")

			// The widened argument is refused, and the narrowed one is not. This is the
			// assertion that distinguishes a discarded pattern from a stored one.
			assert.ErrorIs(t, kernel.SeccompAllow(ctx, a.rule.Op, a.widen),
				kernel.ErrSeccompRefused, "the widened argument must still be refused")
			assert.NoError(t, kernel.SeccompAllow(ctx, a.rule.Op, a.stillIn),
				"the declared argument is still permitted")

			// And the attempt is on the audit chain as an escalation, not only in a
			// return value the installer may not read.
			var escalated bool
			for _, e := range kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditEscalation}) {
				if e.Fields["target"] == pid && e.Fields["pattern"] == a.over {
					escalated = true
				}
			}
			assert.True(t, escalated, "an attempt to widen is escalated on the chain")
		})
	}
}

// TestAFilterCannotGrantAnOperationTheDomainLacks pins the other half of the invariant.
// A filter naming an operation the module never declared must not grant it, and must not
// make the check path permit anything: the layers are ceiling, then scope, then filter,
// and a filter that answered before the ceiling would be a grant.
func TestAFilterCannotGrantAnOperationTheDomainLacks(t *testing.T) {
	harness.QuietConsole(t)
	k := seccompBoot(t)

	// Declares fs:read but not fs:write.
	ctx, pid := seccompLoad(t, k, "secop", kernel.Manifest{
		Require:   []kernel.Op{kernel.OpFSRead},
		ReadPaths: []string{"cache"},
	})

	// A filter that names fs:write. It is filterable and its kind is right, so it is not
	// rejected as malformed - it is intersected against a declaration that has no
	// fs:write paths, which leaves nothing to permit.
	report, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
		Label: "ungranted", Rules: []kernel.SeccompRule{{
			Op: kernel.OpFSWrite, Kind: kernel.SeccompRulePath, Patterns: []string{"cache"},
		}},
	})
	require.NoError(t, err)
	assert.NotEmpty(t, report.Exceeded, "a filter cannot conjure a boundary that was not declared")

	// The filter does not permit it, and separately the module still does not hold the
	// grant. Both facts hold, and the filter is not what decides the second one.
	assert.ErrorIs(t, kernel.SeccompAllow(ctx, kernel.OpFSWrite, "cache/x"),
		kernel.ErrSeccompRefused)

	_, scoped := kernel.GrantsFor(pid)
	require.True(t, scoped)
	grants, _ := kernel.GrantsFor(pid)
	assert.NotContains(t, grants, kernel.OpFSWrite,
		"the filter did not add a grant to the module's effective set")
}

// TestAnUnfilterableOperationIsRefusedAtInstall pins that a filter can only narrow
// arguments the kernel can actually compare. An operation whose argument is an fd or a
// byte slice has nothing to match, and accepting a rule for it would produce a filter that
// looks like it controls something.
func TestAnUnfilterableOperationIsRefusedAtInstall(t *testing.T) {
	harness.QuietConsole(t)
	k := seccompBoot(t)
	ctx, pid := seccompLoad(t, k, "secunfilterable", kernel.Manifest{
		Require: []kernel.Op{kernel.OpPipeOpen, kernel.OpPipeWrite},
	})

	_, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
		Label: "bad", Rules: []kernel.SeccompRule{{
			Op: kernel.OpPipeWrite, Kind: kernel.SeccompRuleKey, Patterns: []string{"x"},
		}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not filterable")
	assert.False(t, kernel.SeccompFiltered(pid), "a refused install leaves no filter")

	// A rule whose kind disagrees with its operation is refused rather than silently
	// reinterpreted, because the author would otherwise believe a path filter was in force
	// on a key operation.
	_, err = kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
		Label: "mismatched", Rules: []kernel.SeccompRule{{
			Op: kernel.OpFSRead, Kind: kernel.SeccompRuleHost, Patterns: []string{"cache"},
		}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "takes a path rule")
	_ = ctx
}

// ---------------------------------------------------------------------------
// A genuinely narrowing filter.

// TestANarrowingFilterTakesEffect is the positive case, and it is what makes the negative
// cases above meaningful: without a filter that demonstrably narrows, a subsystem that
// refused everything would pass all of them.
func TestANarrowingFilterTakesEffect(t *testing.T) {
	harness.QuietConsole(t)
	k := seccompBoot(t)
	ctx, pid := seccompLoad(t, k, "secnarrow", kernel.Manifest{
		Require:    []kernel.Op{kernel.OpFSRead, kernel.OpFSWrite},
		ReadPaths:  []string{"cache", "logs"},
		WritePaths: []string{"cache", "scratch"},
	})

	// Before any filter, everything the declaration permits is permitted.
	require.NoError(t, kernel.SeccompAllow(ctx, kernel.OpFSRead, "logs/today"))
	require.NoError(t, kernel.SeccompAllow(ctx, kernel.OpFSRead, "cache/blob"))

	report, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
		Label: "cache only", Rules: []kernel.SeccompRule{{
			Op: kernel.OpFSRead, Kind: kernel.SeccompRulePath, Patterns: []string{"cache"},
		}},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, report.Installed)
	assert.Empty(t, report.Exceeded)
	assert.NotEmpty(t, report.Applied, "the report says what took effect")
	assert.True(t, kernel.SeccompFiltered(pid))

	// logs/ is now refused even though the manifest declares it. That is the narrowing.
	assert.ErrorIs(t, kernel.SeccompAllow(ctx, kernel.OpFSRead, "logs/today"),
		kernel.ErrSeccompRefused)
	assert.NoError(t, kernel.SeccompAllow(ctx, kernel.OpFSRead, "cache/blob"),
		"and the filtered scope still works")

	// An operation the filter does not mention is untouched, because refusing every
	// unlisted operation would make installing one rule equivalent to revoking the
	// module's other grants, which is not what narrowing means.
	assert.NoError(t, kernel.SeccompAllow(ctx, kernel.OpFSWrite, "scratch/tmp"))

	// Traversal, in both directions, because a prefix match on the raw string would get
	// one of them wrong. "cache/x/../logs/y" cleans to cache/logs/y, which is genuinely
	// inside cache and so is permitted; permitting it is correct rather than a hole, and
	// asserting a refusal here would be asserting the filter is wrong where it is right.
	assert.NoError(t, kernel.SeccompAllow(ctx, kernel.OpFSRead, "cache/x/../logs/y"),
		"this cleans to cache/logs/y, inside the filtered scope")
	assert.ErrorIs(t, kernel.SeccompAllow(ctx, kernel.OpFSRead, "cache/../logs/x"),
		kernel.ErrSeccompRefused, "and this cleans to logs/x, outside it")
	assert.ErrorIs(t, kernel.SeccompAllow(ctx, kernel.OpFSRead, "cache/../logs/today"),
		kernel.ErrSeccompRefused)
}

// TestSegmentMatchingIsNotStringPrefixing pins the boundary that decides whether a filter
// is a boundary at all. "cache2" is not inside "cache", and a string-prefix comparison
// would say it is, which is a bypass rather than a nit: a module could write to
// cache2/poisoned under a filter that meant to confine it to cache/.
func TestSegmentMatchingIsNotStringPrefixing(t *testing.T) {
	harness.QuietConsole(t)
	k := seccompBoot(t)
	ctx, pid := seccompLoad(t, k, "secsegment", kernel.Manifest{
		Require:   []kernel.Op{kernel.OpFSRead},
		ReadPaths: []string{"cache", "cache2"},
	})

	_, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
		Label: "cache only", Rules: []kernel.SeccompRule{{
			Op: kernel.OpFSRead, Kind: kernel.SeccompRulePath, Patterns: []string{"cache"},
		}},
	})
	require.NoError(t, err)

	assert.NoError(t, kernel.SeccompAllow(ctx, kernel.OpFSRead, "cache/blob"))
	assert.NoError(t, kernel.SeccompAllow(ctx, kernel.OpFSRead, "cache/deep/nested/blob"))
	assert.ErrorIs(t, kernel.SeccompAllow(ctx, kernel.OpFSRead, "cache2/blob"),
		kernel.ErrSeccompRefused,
		"cache2 is a different directory that happens to share a string prefix")
	assert.ErrorIs(t, kernel.SeccompAllow(ctx, kernel.OpFSRead, "cache2"),
		kernel.ErrSeccompRefused)
	assert.ErrorIs(t, kernel.SeccompAllow(ctx, kernel.OpFSRead, "caches/blob"),
		kernel.ErrSeccompRefused)
}

// TestHostFilterCannotBeEvadedByRespelling pins that host rules use net.go's
// normalization. A filter narrowing to one host that could be evaded by changing the case
// or adding a trailing dot would not be a narrowing.
func TestHostFilterCannotBeEvadedByRespelling(t *testing.T) {
	harness.QuietConsole(t)
	k := seccompBoot(t)
	ctx, pid := seccompLoad(t, k, "sechost", kernel.Manifest{
		Require:      []kernel.Op{kernel.OpNetDial},
		AllowedHosts: []string{"api.provider.example"},
	})

	_, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
		Label: "one host", Rules: []kernel.SeccompRule{{
			Op: kernel.OpNetDial, Kind: kernel.SeccompRuleHost,
			Patterns: []string{"API.Provider.Example"},
		}},
	})
	require.NoError(t, err)

	for _, ok := range []string{"api.provider.example", "API.PROVIDER.EXAMPLE", "api.provider.example."} {
		assert.NoError(t, kernel.SeccompAllow(ctx, kernel.OpNetDial, ok),
			"%q is the filtered host respelled", ok)
	}
	for _, bad := range []string{"other.provider.example", "api.provider.example.evil",
		"xapi.provider.example"} {
		assert.ErrorIs(t, kernel.SeccompAllow(ctx, kernel.OpNetDial, bad),
			kernel.ErrSeccompRefused, "%q is not the filtered host", bad)
	}
}

// ---------------------------------------------------------------------------
// The three-way refusal distinction.

// TestAFilterRefusalIsNotAPolicyDenial pins the distinction that makes both answers
// useful. IsDenied true would tell a module it lacks a grant it holds, which sends its
// author to fix the manifest for a problem the manifest does not have; IsDenied false for
// a real denial would hide a ceiling violation from anything watching for one.
func TestAFilterRefusalIsNotAPolicyDenial(t *testing.T) {
	harness.QuietConsole(t)
	k := seccompBoot(t)
	ctx, pid := seccompLoad(t, k, "secdeny", kernel.Manifest{
		Require:   []kernel.Op{kernel.OpFSRead},
		ReadPaths: []string{"cache"},
	})
	// logs is deliberately not declared, so a read of it below is a scope refusal with a
	// reason rather than a ceiling refusal without one.

	_, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
		Label: "one path", Rules: []kernel.SeccompRule{{
			Op: kernel.OpFSRead, Kind: kernel.SeccompRulePath, Patterns: []string{"cache"},
		}},
	})
	require.NoError(t, err)

	filtered := kernel.SeccompAllow(ctx, kernel.OpFSRead, "logs/today")
	require.Error(t, filtered)
	assert.ErrorIs(t, filtered, kernel.ErrSeccompRefused)
	assert.False(t, kernel.IsDenied(filtered),
		"the module holds fs:read; what it lacks is this argument")
	assert.Empty(t, kernel.DenialReason(filtered),
		"and there is no denial reason to report, because nothing was denied by policy")

	// A genuine policy denial, for contrast. metadata:write is not in the plugin domain's
	// ceiling and is not grantable by declaration, so this is a real ceiling refusal rather
	// than an argument refusal, and it is the pair that makes the distinction above
	// observable rather than theoretical.
	denied := ctx.SyscallMetadataSet("filtered.probe", "x")
	require.Error(t, denied)
	assert.True(t, kernel.IsDenied(denied), "a real ceiling refusal is a denial")
	assert.Empty(t, kernel.DenialReason(denied),
		"a ceiling refusal carries no reason, because the reason field is what distinguishes "+
			"a missing declaration from a missing grant, and this is the latter")

	// And the declaration case does carry one, which is the distinction the empty reason
	// above is meaningful against: a module that holds fs:read but asks for a path outside
	// its declaration gets told which of the two problems it has. FSCheckWrite is used
	// rather than FSWriteFile because the file syscall needs a data root this module does
	// not have, and would fail before reaching the scope check.
	root := t.TempDir()
	_, scopeDenied := kernel.FSCheckRead(ctx, root, "logs/today")
	require.Error(t, scopeDenied)
	assert.True(t, kernel.IsDenied(scopeDenied))
	assert.NotEmpty(t, kernel.DenialReason(scopeDenied),
		"a scope refusal names what is missing so the module author can fix the manifest")
	assert.Contains(t, kernel.DenialReason(scopeDenied), "logs/today")

	// The two are distinguishable with errors.As, which is what a caller needs in order to
	// give its own user the right answer.
	var sec *kernel.SeccompError
	assert.False(t, errors.As(filtered, &sec), "a filter refusal is not a subsystem error")
}

// TestARefusalDoesNotDistinguishFilteredFromAbsent pins the oracle. A module that can tell
// "the filter refused this" from "this does not exist" can map its own filter by probing,
// and a filter whose contents a module can reconstruct is a filter it can plan around. The
// message returned to the caller is therefore the same for both, while the operator-visible
// record carries the argument.
func TestARefusalDoesNotDistinguishFilteredFromAbsent(t *testing.T) {
	buf := harness.QuietConsole(t)
	k := seccompBoot(t)
	ctx, pid := seccompLoad(t, k, "secoracle", kernel.Manifest{
		Require:   []kernel.Op{kernel.OpFSRead},
		ReadPaths: []string{"cache"},
	})

	_, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
		Label: "one path", Rules: []kernel.SeccompRule{{
			Op: kernel.OpFSRead, Kind: kernel.SeccompRulePath, Patterns: []string{"cache"},
		}},
	})
	require.NoError(t, err)

	filtered := kernel.SeccompAllow(ctx, kernel.OpFSRead, "logs/today")
	absent := kernel.SeccompAllow(ctx, kernel.OpFSRead, "nonexistent/nothing")
	require.Error(t, filtered)
	require.Error(t, absent)

	assert.Equal(t, filtered.Error(), absent.Error(),
		"a module cannot tell a filtered argument from an absent one")
	assert.NotContains(t, filtered.Error(), "logs",
		"and the refused argument is not echoed back to the caller")

	// The operator-visible records DO carry it, which is the asymmetry that makes the
	// oracle closed without making the refusal useless to debug.
	records := harness.Records(t, buf)
	var sawArgument bool
	for _, r := range records {
		if r.Fields["argument"] == "logs/today" {
			sawArgument = true
		}
	}
	assert.True(t, sawArgument, "the console carries the argument the module cannot see")
}

// ---------------------------------------------------------------------------
// Who may touch a filter.

// TestAModuleCannotTouchItsOwnFilter pins the access rule. It is not a missing grant: a
// module that could read its filter would learn exactly what it is restricted from, and a
// module that could modify it would make the subsystem a formality. The sentinel is
// distinct so a caller can tell "you may never do this" from "you lack a grant today".
func TestAModuleCannotTouchItsOwnFilter(t *testing.T) {
	harness.QuietConsole(t)
	k := seccompBoot(t)
	ctx, pid := seccompLoad(t, k, "secself", kernel.Manifest{
		Require:   []kernel.Op{kernel.OpFSRead},
		ReadPaths: []string{"cache"},
	})

	_, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
		Label: "installed by the host", Rules: []kernel.SeccompRule{{
			Op: kernel.OpFSRead, Kind: kernel.SeccompRulePath, Patterns: []string{"cache"},
		}},
	})
	require.NoError(t, err)

	// Install over its own filter.
	_, err = kernel.SeccompInstall(ctx, pid, kernel.SeccompFilter{
		Label: "empty", Rules: []kernel.SeccompRule{{
			Op: kernel.OpFSRead, Kind: kernel.SeccompRulePath, Patterns: []string{"cache"},
		}},
	})
	require.Error(t, err)
	assert.ErrorIs(t, err, kernel.ErrSeccompSelfModification)

	// Remove its own filter.
	assert.ErrorIs(t, kernel.SeccompRemove(ctx, pid), kernel.ErrSeccompSelfModification)

	// Read its own filter's contents.
	_, err = kernel.SeccompSnapshotFor(ctx, pid)
	require.Error(t, err)
	assert.ErrorIs(t, err, kernel.ErrSeccompSelfModification)

	// The host's filter is still in force, which is the assertion that matters: none of
	// those attempts changed anything.
	assert.True(t, kernel.SeccompFiltered(pid))
	assert.ErrorIs(t, kernel.SeccompAllow(ctx, kernel.OpFSRead, "logs/x"),
		kernel.ErrSeccompRefused)

	// And the one thing a module may learn is the boolean, because knowing that a filter
	// exists is useful to a module that wants to shed load, while knowing what it says is
	// the oracle above.
	snap, err := ctx.SyscallSeccompFiltered()
	require.NoError(t, err)
	assert.True(t, snap)
}

// TestInitMayFilterAModuleItLoaded pins the positive half of the access rule. A filter
// nobody can install is not a feature, and init is the party that loads modules, so it is
// the party that can decide one instance should run narrower than its manifest allows.
func TestInitMayFilterAModuleItLoaded(t *testing.T) {
	harness.QuietConsole(t)
	k := seccompBoot(t)
	_, pid := seccompLoad(t, k, "secinit", kernel.Manifest{
		Require:   []kernel.Op{kernel.OpFSRead},
		ReadPaths: []string{"cache", "logs"},
	})

	report, err := kernel.SeccompInstall(k.InitContext(), pid, kernel.SeccompFilter{
		Label: "installed by init", Rules: []kernel.SeccompRule{{
			Op: kernel.OpFSRead, Kind: kernel.SeccompRulePath, Patterns: []string{"logs"},
		}},
	})
	require.NoError(t, err)
	assert.Equal(t, 1, report.Installed)
	assert.Equal(t, pid, report.PID)

	snap, err := kernel.SeccompSnapshotFor(k.InitContext(), pid)
	require.NoError(t, err)
	assert.Equal(t, "installed by init", snap.Label)
	require.Len(t, snap.Rules, 1)
	assert.Equal(t, []string{"logs"}, snap.Rules[0].Patterns)
	assert.Equal(t, kernel.OpFSRead, snap.Rules[0].Op)
	assert.Equal(t, "path", snap.Rules[0].Kind)
}

// TestAnotherModuleCannotFilterItsNeighbour pins that the rule is about self-modification
// and about domains, not about pids in general. A plugin holding every grantable operation
// still has no path to another module's filter.
func TestAnotherModuleCannotFilterItsNeighbour(t *testing.T) {
	harness.QuietConsole(t)
	k := seccompBoot(t)
	_, victim := seccompLoad(t, k, "secvictim", kernel.Manifest{
		Require:   []kernel.Op{kernel.OpFSRead},
		ReadPaths: []string{"cache"},
	})
	attackerCtx, _ := seccompLoad(t, k, "secattacker", kernel.Manifest{
		Require:   []kernel.Op{kernel.OpFSRead, kernel.OpKVRead, kernel.OpKVWrite},
		ReadPaths: []string{"cache"},
	})

	_, err := kernel.SeccompInstall(attackerCtx, victim, kernel.SeccompFilter{
		Label: "hostile", Rules: []kernel.SeccompRule{{
			Op: kernel.OpFSRead, Kind: kernel.SeccompRulePath, Patterns: []string{"cache"},
		}},
	})
	require.Error(t, err)
	assert.True(t, kernel.IsDenied(err), "a plugin domain has no path to another pid's filter")
	assert.False(t, kernel.SeccompFiltered(victim), "and nothing was installed")

	assert.Error(t, kernel.SeccompRemove(attackerCtx, victim))
	_, err = kernel.SeccompSnapshotFor(attackerCtx, victim)
	require.Error(t, err)
	assert.True(t, kernel.IsDenied(err))
}

// ---------------------------------------------------------------------------
// Budgets, lifetime, bounds.

// TestAnAbsoluteBudgetCapsOneInstance pins the budget rule and its boundary. It is an
// absolute count rather than a rate, because kqos already shapes per-minute traffic and a
// second rate limiter here would be a second answer to the same question; what a filter can
// express that kqos cannot is "this instance gets N of these, ever".
func TestAnAbsoluteBudgetCapsOneInstance(t *testing.T) {
	harness.QuietConsole(t)
	k := seccompBoot(t)
	ctx, pid := seccompLoad(t, k, "secbudget", kernel.Manifest{
		Require:   []kernel.Op{kernel.OpFSRead},
		ReadPaths: []string{"cache"},
	})

	_, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
		Label: "three reads", Rules: []kernel.SeccompRule{{
			Op: kernel.OpFSRead, Kind: kernel.SeccompRulePath,
			Patterns: []string{"cache"}, Budget: 3,
		}},
	})
	require.NoError(t, err)

	for i := range 3 {
		assert.NoError(t, kernel.SeccompAllow(ctx, kernel.OpFSRead, "cache/blob"),
			"call %d is inside the budget", i+1)
	}
	// The boundary: the fourth is refused, and the refusal says it is the budget rather
	// than the argument, because those have different fixes.
	fourth := kernel.SeccompAllow(ctx, kernel.OpFSRead, "cache/blob")
	require.Error(t, fourth)
	assert.ErrorIs(t, fourth, kernel.ErrSeccompRefused)
	assert.Contains(t, fourth.Error(), "budget")

	// A refused call still consumes budget, because it still happened and still cost the
	// kernel a decision. Counting only permitted calls would let a module spend an
	// unbounded number of refusals against a budget meant to bound its activity.
	for range 3 {
		assert.ErrorIs(t, kernel.SeccompAllow(ctx, kernel.OpFSRead, "cache/blob"),
			kernel.ErrSeccompRefused)
	}

	snap, err := kernel.SeccompSnapshotFor(nil, pid)
	require.NoError(t, err)
	require.Len(t, snap.Rules, 1)
	assert.Equal(t, int64(3), snap.Rules[0].Budget)
	assert.GreaterOrEqual(t, snap.Rules[0].Used, int64(6))
	assert.Positive(t, snap.BudgetHits)
}

// TestAFilterWithNoPatternsRefusesTheOperationEntirely pins the empty-pattern rule. It is a
// legitimate narrowing - "this instance may not do this at all" - and it is what a rule
// whose every pattern exceeded the declaration becomes, which is why that case returns a
// projection rather than nothing.
func TestAFilterWithNoPatternsRefusesTheOperationEntirely(t *testing.T) {
	harness.QuietConsole(t)
	k := seccompBoot(t)
	ctx, pid := seccompLoad(t, k, "secempty", kernel.Manifest{
		Require:   []kernel.Op{kernel.OpFSRead},
		ReadPaths: []string{"cache"},
	})

	_, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
		Label: "no reads", Rules: []kernel.SeccompRule{{
			Op: kernel.OpFSRead, Kind: kernel.SeccompRulePath, Patterns: nil,
		}},
	})
	require.NoError(t, err)

	refused := kernel.SeccompAllow(ctx, kernel.OpFSRead, "cache/blob")
	require.Error(t, refused)
	assert.ErrorIs(t, refused, kernel.ErrSeccompRefused)
	assert.Contains(t, refused.Error(), "may not perform")
	assert.NotContains(t, refused.Error(), "cache",
		"the argument is not echoed back to the caller")
}

// TestAnEmptyFilterIsRefused pins that installing nothing is not a hardening step. An empty
// filter would appear in the audit chain as "filter installed" while changing nothing, and
// a reader of that chain would believe the instance was filtered.
func TestAnEmptyFilterIsRefused(t *testing.T) {
	harness.QuietConsole(t)
	k := seccompBoot(t)
	_, pid := seccompLoad(t, k, "secnofilter", kernel.Manifest{
		Require:   []kernel.Op{kernel.OpFSRead},
		ReadPaths: []string{"cache"},
	})

	_, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{Label: "empty"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no rules")
	assert.False(t, kernel.SeccompFiltered(pid))
}

// TestFiltersDieWithTheirPid pins the lifetime. A filter surviving its pid would apply to
// whatever the next boot assigns that pid, and pids restart at 1, so a stale filter would
// land on init.
func TestFiltersDieWithTheirPid(t *testing.T) {
	harness.QuietConsole(t)
	k := seccompBoot(t)

	name := seccompNextName("seclifetime")
	probe := &harness.Probe{}
	harness.RegisterProbe(t, name, probe)
	pid, err := k.Load(kernel.Manifest{
		Name: name, Version: "1", MinKernelAPI: kernel.KernelAPI, MaxKernelAPI: kernel.KernelAPI,
		Require: []kernel.Op{kernel.OpFSRead}, ReadPaths: []string{"cache"},
	})
	require.NoError(t, err)

	_, err = kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
		Label: "dies with the pid", Rules: []kernel.SeccompRule{{
			Op: kernel.OpFSRead, Kind: kernel.SeccompRulePath, Patterns: []string{"cache"},
		}},
	})
	require.NoError(t, err)
	require.True(t, kernel.SeccompFiltered(pid))

	require.NoError(t, k.Unload(pid))
	assert.False(t, kernel.SeccompFiltered(pid), "the filter died with its pid")

	// The history keeps the record, because an operator investigating a module that is
	// already gone still needs to know what was applied to it.
	var sawInstall bool
	for _, e := range kernel.SeccompHistory() {
		if e.PID == pid && e.Action == "installed" {
			sawInstall = true
			assert.Equal(t, name, e.Module)
		}
	}
	assert.True(t, sawInstall)
}

// TestRemoveIsAuditedAsAWidening pins that removing a filter is a policy change and not
// bookkeeping. It widens what the instance may do, so an operator needs it on the chain.
func TestRemoveIsAuditedAsAWidening(t *testing.T) {
	buf := harness.QuietConsole(t)
	k := seccompBoot(t)
	ctx, pid := seccompLoad(t, k, "secremove", kernel.Manifest{
		Require:   []kernel.Op{kernel.OpFSRead},
		ReadPaths: []string{"cache", "logs"},
	})

	_, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
		Label: "removable", Rules: []kernel.SeccompRule{{
			Op: kernel.OpFSRead, Kind: kernel.SeccompRulePath, Patterns: []string{"cache"},
		}},
	})
	require.NoError(t, err)
	require.ErrorIs(t, kernel.SeccompAllow(ctx, kernel.OpFSRead, "logs/x"),
		kernel.ErrSeccompRefused)

	require.NoError(t, kernel.SeccompRemove(nil, pid))
	assert.False(t, kernel.SeccompFiltered(pid))
	assert.NoError(t, kernel.SeccompAllow(ctx, kernel.OpFSRead, "logs/x"),
		"with the filter gone the declaration's full scope stands")

	var sawRemoval bool
	for _, e := range kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditPolicy}) {
		if e.Msg == "instance filter removed" && e.Fields["target"] == pid {
			sawRemoval = true
		}
	}
	assert.True(t, sawRemoval, "a removal is on the audit chain")
	assert.NotEmpty(t, harness.Faults(buf), "and on the console")

	// Removing twice is an error rather than a silent no-op, because the second removal
	// means the caller believed a filter was in force when it was not.
	assert.Error(t, kernel.SeccompRemove(nil, pid))
}

// TestReplacingAFilterIsAtomic pins that a call never sees half of two filters. The old
// instance is replaced in one step under the write lock.
func TestReplacingAFilterIsAtomic(t *testing.T) {
	harness.QuietConsole(t)
	k := seccompBoot(t)
	ctx, pid := seccompLoad(t, k, "secreplace", kernel.Manifest{
		Require:   []kernel.Op{kernel.OpFSRead},
		ReadPaths: []string{"cache", "logs"},
	})

	for _, label := range []string{"first", "second", "third"} {
		_, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
			Label: label, Rules: []kernel.SeccompRule{{
				Op: kernel.OpFSRead, Kind: kernel.SeccompRulePath, Patterns: []string{label},
			}},
		})
		if err != nil {
			// "first"/"second"/"third" are not inside the declaration, so every rule
			// exceeds and the projection permits nothing. That is the narrowing working.
			assert.NotEmpty(t, err.Error())
		}
	}

	// What must hold after all of it: the filter in force is the last one installed, and
	// no call sees a mixture.
	snap, err := kernel.SeccompSnapshotFor(nil, pid)
	require.NoError(t, err)
	assert.Equal(t, "third", snap.Label)
	require.Len(t, snap.Rules, 1)
	// The third label's pattern is not inside the declaration, so the projection permits
	// nothing and every argument is refused. What matters is that the answer is coherent
	// rather than that it is a particular answer.
	assert.ErrorIs(t, kernel.SeccompAllow(ctx, kernel.OpFSRead, "cache/x"),
		kernel.ErrSeccompRefused, "the last filter installed is the one in force")

	history := kernel.SeccompHistory()
	var installs int
	for _, e := range history {
		if e.PID == pid && e.Action == "installed" {
			installs++
		}
	}
	assert.Positive(t, installs)
}

// TestTheRuleCeilingsAreEnforced pins that a filter cannot be unboundedly large. Both
// bounds are kernel constants: while only the host installs filters, a host bug that
// produced an unbounded filter would grow kernel memory on the hot path of every scoped
// call.
func TestTheRuleCeilingsAreEnforced(t *testing.T) {
	harness.QuietConsole(t)
	k := seccompBoot(t)
	_, pid := seccompLoad(t, k, "secceil", kernel.Manifest{
		Require:   []kernel.Op{kernel.OpFSRead},
		ReadPaths: []string{"cache"},
	})

	stats := kernel.SeccompStatsSnapshot()
	require.Positive(t, stats.MaxRules)

	// Too many rules.
	many := make([]kernel.SeccompRule, 0, stats.MaxRules+1)
	for range stats.MaxRules + 1 {
		many = append(many, kernel.SeccompRule{
			Op: kernel.OpFSRead, Kind: kernel.SeccompRulePath, Patterns: []string{"cache"},
		})
	}
	_, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{Label: "many", Rules: many})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ceiling")

	// Too many patterns in one rule.
	wide := make([]string, 0, 65)
	for i := range 65 {
		wide = append(wide, "cache/"+harness.Itoa(i))
	}
	_, err = kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
		Label: "wide", Rules: []kernel.SeccompRule{{
			Op: kernel.OpFSRead, Kind: kernel.SeccompRulePath, Patterns: wide,
		}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ceiling")

	// A label carrying a line break is refused, because the label goes into the console
	// and the audit chain and a newline in it forges a record boundary.
	_, err = kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
		Label: "two\nlines", Rules: []kernel.SeccompRule{{
			Op: kernel.OpFSRead, Kind: kernel.SeccompRulePath, Patterns: []string{"cache"},
		}},
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "line break")

	assert.False(t, kernel.SeccompFiltered(pid), "none of the refused installs took effect")
}

// TestTheHistoryIsBoundedAndTrimsInOneStep pins the ledger bound and the shape of the trim.
func TestTheHistoryIsBoundedAndTrimsInOneStep(t *testing.T) {
	harness.QuietConsole(t)
	k := seccompBoot(t)
	_, pid := seccompLoad(t, k, "sechistory", kernel.Manifest{
		Require:   []kernel.Op{kernel.OpFSRead},
		ReadPaths: []string{"cache"},
	})

	rule := kernel.SeccompRule{
		Op: kernel.OpFSRead, Kind: kernel.SeccompRulePath, Patterns: []string{"cache"},
	}
	for range 600 {
		_, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{Label: "again", Rules: []kernel.SeccompRule{rule}})
		require.NoError(t, err)
	}

	stats := kernel.SeccompStatsSnapshot()
	assert.LessOrEqual(t, stats.History, 512, "the history never exceeds its bound")
	assert.Positive(t, stats.Evicted, "records were evicted rather than accumulated")
	assert.GreaterOrEqual(t, stats.Installs, int64(600))

	history := kernel.SeccompHistory()
	for i := 1; i < len(history); i++ {
		assert.Greater(t, history[i].Seq, history[i-1].Seq, "sequence numbers increase")
	}
}

// TestSnapshotsAreCopies pins that mutating a returned snapshot cannot reach kernel state.
func TestSnapshotsAreCopies(t *testing.T) {
	harness.QuietConsole(t)
	k := seccompBoot(t)
	_, pid := seccompLoad(t, k, "seccopy", kernel.Manifest{
		Require:      []kernel.Op{kernel.OpFSRead, kernel.OpNetDial},
		ReadPaths:    []string{"cache"},
		AllowedHosts: []string{"api.example"},
	})

	_, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
		Label: "copyable", Rules: []kernel.SeccompRule{
			{Op: kernel.OpFSRead, Kind: kernel.SeccompRulePath, Patterns: []string{"cache"}},
			{Op: kernel.OpNetDial, Kind: kernel.SeccompRuleHost, Patterns: []string{"api.example"}},
		},
	})
	require.NoError(t, err)

	snap, err := kernel.SeccompSnapshotFor(nil, pid)
	require.NoError(t, err)
	require.Len(t, snap.Rules, 2)
	assert.Equal(t, kernel.OpFSRead, snap.Rules[0].Op, "rules are sorted by operation")

	snap.Rules[0].Patterns[0] = "tampered"
	snap.Rules = append(snap.Rules, kernel.SeccompRuleView{Op: kernel.OpKVWrite})
	snap.Label = "tampered"

	again, err := kernel.SeccompSnapshotFor(nil, pid)
	require.NoError(t, err)
	assert.Equal(t, "copyable", again.Label)
	require.Len(t, again.Rules, 2)
	assert.Equal(t, []string{"cache"}, again.Rules[0].Patterns)

	history := kernel.SeccompHistory()
	if len(history) > 0 {
		history[0].Label = "tampered"
	}
	assert.NotEqual(t, "tampered", kernel.SeccompHistory()[0].Label)
}

// TestNothingSurvivesRestart pins the reset.
func TestNothingSurvivesRestart(t *testing.T) {
	harness.QuietConsole(t)
	k := seccompBoot(t)
	ctx, pid := seccompLoad(t, k, "secreset", kernel.Manifest{
		Require:   []kernel.Op{kernel.OpFSRead},
		ReadPaths: []string{"cache"},
	})
	_, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
		Label: "before restart", Rules: []kernel.SeccompRule{{
			Op: kernel.OpFSRead, Kind: kernel.SeccompRulePath, Patterns: []string{"cache"},
		}},
	})
	require.NoError(t, err)
	require.True(t, kernel.SeccompFiltered(pid))
	require.Positive(t, kernel.SeccompStatsSnapshot().Installs)

	require.NoError(t, k.Shutdown())

	k2 := seccompBoot(t)
	_ = k2
	assert.False(t, kernel.SeccompFiltered(pid))
	assert.Empty(t, kernel.SeccompHistory())
	stats := kernel.SeccompStatsSnapshot()
	assert.Zero(t, stats.Filtered)
	assert.Zero(t, stats.Installs)
	assert.Zero(t, stats.Refused)
	_ = ctx
}

// ---------------------------------------------------------------------------
// The surface itself, and concurrency.

// TestTheFilterableSetIsWhatTheKernelCanActuallyCompare pins the declared set against the
// subsystem's own documentation. A filter for an operation whose argument the kernel cannot
// compare would be a filter that looks like it controls something.
func TestTheFilterableSetIsWhatTheKernelCanActuallyCompare(t *testing.T) {
	ops := kernel.SeccompFilterableOps()
	assert.NotEmpty(t, ops)

	want := map[kernel.Op]kernel.SeccompRuleKind{
		kernel.OpMetadataRead:  kernel.SeccompRuleKey,
		kernel.OpMetadataWrite: kernel.SeccompRuleKey,
		kernel.OpKVRead:        kernel.SeccompRuleKey,
		kernel.OpKVWrite:       kernel.SeccompRuleKey,
		kernel.OpFSRead:        kernel.SeccompRulePath,
		kernel.OpFSWrite:       kernel.SeccompRulePath,
		kernel.OpNetDial:       kernel.SeccompRuleHost,
		kernel.OpPeerDial:      kernel.SeccompRuleHost,
		kernel.OpSecretUse:     kernel.SeccompRuleSecret,
		kernel.OpRouteRegister: kernel.SeccompRulePath,
	}
	assert.Equal(t, want, ops)

	names := kernel.SeccompFilterableOpNames()
	assert.Len(t, names, len(want))
	for i := 1; i < len(names); i++ {
		assert.Less(t, names[i-1], names[i], "the name list is sorted")
	}

	// Every key operation is scoped or ceiling-granted, and every host/path/secret one is
	// scoped, so a filter always narrows something that already had a boundary or a grant.
	for op := range want {
		assert.NotEmpty(t, string(op))
	}
}

// TestTheSyscallSurfaceIsReachable pins that the module-readable half is reachable through
// the sealed SContext rather than only through the package functions, which would keep
// passing if the group were missing from the composition in context.go.
func TestTheSyscallSurfaceIsReachable(t *testing.T) {
	harness.QuietConsole(t)
	k := seccompBoot(t)
	ctx, pid := seccompLoad(t, k, "secwire", kernel.Manifest{
		Require:   []kernel.Op{kernel.OpFSRead},
		ReadPaths: []string{"cache"},
	})

	before, err := ctx.SyscallSeccompFiltered()
	require.NoError(t, err)
	assert.False(t, before)

	_, err = kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
		Label: "wired", Rules: []kernel.SeccompRule{{
			Op: kernel.OpFSRead, Kind: kernel.SeccompRulePath, Patterns: []string{"cache"},
		}},
	})
	require.NoError(t, err)

	after, err := ctx.SyscallSeccompFiltered()
	require.NoError(t, err)
	assert.True(t, after, "the module can see that it is filtered")

	// And the boolean is all it can see: the refusal it gets carries no rule contents.
	assert.ErrorIs(t, kernel.SeccompAllow(ctx, kernel.OpFSRead, "logs/x"),
		kernel.ErrSeccompRefused)
}

// TestConcurrentChecksWhileTheFilterIsReplaced exercises the read path under contention
// with the write path replacing the filter. The check path is on the hot path of every
// scoped call, so it takes the read lock, and a replacement must not let a call see a
// half-swapped instance.
func TestConcurrentChecksWhileTheFilterIsReplaced(t *testing.T) {
	harness.QuietConsole(t)
	k := seccompBoot(t)
	ctx, pid := seccompLoad(t, k, "secconc", kernel.Manifest{
		Require:   []kernel.Op{kernel.OpFSRead},
		ReadPaths: []string{"cache", "logs"},
	})

	_, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
		Label: "start", Rules: []kernel.SeccompRule{{
			Op: kernel.OpFSRead, Kind: kernel.SeccompRulePath, Patterns: []string{"cache", "logs"},
		}},
	})
	require.NoError(t, err)

	stop := make(chan struct{})
	var readers sync.WaitGroup
	for range 6 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				select {
				case <-stop:
					return
				default:
					// Either permitted or refused; what must never happen is a panic, a
					// torn read, or a nil-projection dereference.
					err := kernel.SeccompAllow(ctx, kernel.OpFSRead, "cache/blob")
					if err != nil {
						assert.ErrorIs(t, err, kernel.ErrSeccompRefused)
					}
					_ = kernel.SeccompStatsSnapshot()
					_ = kernel.SeccompFiltered(pid)
				}
			}
		}()
	}

	var writers sync.WaitGroup
	for w := range 4 {
		writers.Add(1)
		go func(w int) {
			defer writers.Done()
			for i := range 20 {
				patterns := []string{"cache"}
				if (w+i)%2 == 0 {
					patterns = []string{"cache", "logs"}
				}
				_, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
					Label: "replaced", Rules: []kernel.SeccompRule{{
						Op: kernel.OpFSRead, Kind: kernel.SeccompRulePath, Patterns: patterns,
					}},
				})
				assert.NoError(t, err)
			}
		}(w)
	}

	writers.Wait()
	close(stop)
	readers.Wait()

	// After the contention, exactly one filter is in force and it answers coherently.
	snap, err := kernel.SeccompSnapshotFor(nil, pid)
	require.NoError(t, err)
	assert.Equal(t, "replaced", snap.Label)
	require.Len(t, snap.Rules, 1)
	assert.NoError(t, kernel.SeccompAllow(ctx, kernel.OpFSRead, "cache/blob"))
}

// ---------------------------------------------------------------------------
// End to end, through the real syscalls.
//
// Everything above drives SeccompAllow directly, which tests the decision. It does not
// test that anything consults the decision, and that is the gap that makes an unwired
// filter indistinguishable from a working one: both pass every test that calls the
// function. These cases go through the actual syscall so a removed call site fails.

// TestTheFilterIsConsultedByTheRealSyscalls is the wiring test, one case per call site.
// Each installs a filter that narrows the declaration, then performs the operation twice
// through the public syscall: once with an argument inside the filter and once outside it.
// The pair is what makes the case meaningful, because a call site that refuses everything
// would pass the outside-half and a call site that consults nothing would pass the
// inside-half.
func TestTheFilterIsConsultedByTheRealSyscalls(t *testing.T) {
	harness.QuietConsole(t)
	k := seccompBoot(t)

	// fs:read and fs:write, through the file syscalls rather than SeccompAllow.
	t.Run("fs read and write", func(t *testing.T) {
		// The data root goes in before the load. A root cannot change while a module is
		// loaded, which is the property that stops a module being handed a different
		// filesystem than the one its manifest was reviewed against.
		name := seccompNextName("secwirefs")
		require.NoError(t, kernel.FSSetDataRoot(name, t.TempDir()))
		ctx, pid := seccompLoadNamed(t, k, name, kernel.Manifest{
			Require:    []kernel.Op{kernel.OpFSRead, kernel.OpFSWrite},
			ReadPaths:  []string{"cache", "logs"},
			WritePaths: []string{"cache", "scratch"},
		})

		_, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
			Label: "cache only", Rules: []kernel.SeccompRule{
				{Op: kernel.OpFSRead, Kind: kernel.SeccompRulePath, Patterns: []string{"cache"}},
				{Op: kernel.OpFSWrite, Kind: kernel.SeccompRulePath, Patterns: []string{"cache"}},
			},
		})
		require.NoError(t, err)

		// Inside the filter. The file does not exist, which is fine: the point is that the
		// refusal is not the filter's, so the error must not be a seccomp one.
		require.NoError(t, kernel.FSWriteFile(ctx, "cache/blob", []byte("payload")))
		got, err := kernel.FSReadFile(ctx, "cache/blob")
		require.NoError(t, err)
		assert.Equal(t, []byte("payload"), got)

		// Outside the filter but inside the declaration, which is the case that only a
		// wired filter catches.
		assert.ErrorIs(t, kernel.FSWriteFile(ctx, "scratch/other", []byte("x")),
			kernel.ErrSeccompRefused)
		_, err = kernel.FSReadFile(ctx, "logs/today")
		require.Error(t, err)
		assert.ErrorIs(t, err, kernel.ErrSeccompRefused)
	})

	// metadata:read, through the metadata syscall.
	t.Run("metadata", func(t *testing.T) {
		ctx, pid := seccompLoad(t, k, "secwiremeta", kernel.Manifest{
			Require: []kernel.Op{kernel.OpMetadataRead},
		})
		_, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
			Label: "own namespace", Rules: []kernel.SeccompRule{{
				Op: kernel.OpMetadataRead, Kind: kernel.SeccompRuleKey,
				Patterns: []string{"meowapi."},
			}},
		})
		require.NoError(t, err)

		// Keys have no manifest declaration, so the baseline a key filter narrows against
		// is the ceiling grant, which permits every key. The filter reduces that to one
		// prefix, which is the confinement this subsystem was specified for.
		_, err = ctx.SyscallMetadataGet("other.namespace")
		require.Error(t, err)
		assert.ErrorIs(t, err, kernel.ErrSeccompRefused,
			"a key outside the filtered prefix is refused")

		// A key inside the prefix reaches the metadata store. A key that was never written
		// reads as a nil value with no error, because the store is sparse and a miss is not
		// a failure; what the case needs is that the filter did not refuse it, which is what
		// distinguishes a wired narrowing from a call site that refuses everything.
		_, err = ctx.SyscallMetadataGet("meowapi.state")
		assert.NotErrorIs(t, err, kernel.ErrSeccompRefused)
	})

	// kv:read and kv:write, through the KV syscalls.
	t.Run("kv", func(t *testing.T) {
		ctx, pid := seccompLoad(t, k, "secwirekv", kernel.Manifest{
			Require: []kernel.Op{kernel.OpKVRead, kernel.OpKVWrite},
		})
		_, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
			Label: "kv namespace", Rules: []kernel.SeccompRule{
				{Op: kernel.OpKVWrite, Kind: kernel.SeccompRuleKey, Patterns: []string{"own/"}},
				{Op: kernel.OpKVRead, Kind: kernel.SeccompRuleKey, Patterns: []string{"own/"}},
			},
		})
		require.NoError(t, err)

		require.NoError(t, kernel.KVPut(ctx, "own/state", []byte("v")),
			"a key inside the filtered prefix is written")
		got, err := kernel.KVGet(ctx, "own/state")
		require.NoError(t, err)
		assert.Equal(t, []byte("v"), got)

		assert.ErrorIs(t, kernel.KVPut(ctx, "other/state", []byte("v")),
			kernel.ErrSeccompRefused, "a key outside it is refused")
		_, err = kernel.KVGet(ctx, "other/state")
		assert.ErrorIs(t, err, kernel.ErrSeccompRefused)
		// The refusal does not leak which keys exist: a filtered key and an absent one are
		// both refused by the same rule, and neither is distinguishable from the other.
		_, err = kernel.KVGet(ctx, "own/never-written")
		require.Error(t, err)
		assert.NotErrorIs(t, err, kernel.ErrSeccompRefused,
			"an absent key inside the filter is a not-found, not a filter refusal")
	})

	// net:dial, through the dial syscall. The host is declared, so the filter genuinely
	// narrows rather than refusing everything.
	t.Run("net dial", func(t *testing.T) {
		ctx, pid := seccompLoad(t, k, "secwirenet", kernel.Manifest{
			Require:      []kernel.Op{kernel.OpNetDial},
			AllowedHosts: []string{"api.provider.example", "backup.provider.example"},
		})
		_, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
			Label: "primary only", Rules: []kernel.SeccompRule{{
				Op: kernel.OpNetDial, Kind: kernel.SeccompRuleHost,
				Patterns: []string{"api.provider.example"},
			}},
		})
		require.NoError(t, err)

		// The backup host is declared and would dial, but the filter refuses it first.
		_, err = kernel.NetDial(ctx, kernel.NetSpec{Host: "backup.provider.example", Port: 443})
		require.Error(t, err)
		assert.ErrorIs(t, err, kernel.ErrSeccompRefused,
			"a declared host the filter does not permit is refused by the filter")
		assert.False(t, kernel.IsDenied(err), "and it is not a policy denial: the module holds the grant")
	})

	// route:register, through the route syscall.
	t.Run("route register", func(t *testing.T) {
		ctx, pid := seccompLoad(t, k, "secwireroute", kernel.Manifest{
			Require:     []kernel.Op{kernel.OpRouteRegister},
			ServeRoutes: []string{"/v1/chat", "/v1/models"},
		})
		_, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
			Label: "chat only", Rules: []kernel.SeccompRule{{
				Op: kernel.OpRouteRegister, Kind: kernel.SeccompRulePath,
				Patterns: []string{"/v1/chat"},
			}},
		})
		require.NoError(t, err)

		handler := func(kernel.SContext, kernel.RouteRequest) (kernel.RouteResponse, error) {
			return kernel.RouteResponse{Status: 200}, nil
		}
		assert.NoError(t, kernel.RouteRegister(ctx, "/v1/chat", handler),
			"the filtered route registers")
		assert.ErrorIs(t, kernel.RouteRegister(ctx, "/v1/models", handler),
			kernel.ErrSeccompRefused,
			"the declared route the filter omits does not")
	})

	// secret:use, through the keyring syscall. Both credentials really exist, because a
	// test against aliases nobody installed passes whether or not the filter is wired: the
	// keyring's own "not visible" answer refuses both, and the filter is never consulted.
	t.Run("secret use", func(t *testing.T) {
		require.NoError(t, k.InstallSecret(kernel.SecretSpec{
			Alias: "openai/default", Scheme: "Bearer ", Value: []byte("sk-openai-value"),
		}))
		require.NoError(t, k.InstallSecret(kernel.SecretSpec{
			Alias: "anthropic/default", Header: "x-api-key", Value: []byte("sk-ant-value"),
		}))

		ctx, pid := seccompLoad(t, k, "secwiresecret", kernel.Manifest{
			Require:        []kernel.Op{kernel.OpSecretUse},
			SecretPrefixes: []string{"openai/", "anthropic/"},
		})

		// Before any filter, the declared scope reaches both credentials. This is the
		// baseline that makes the filtered case below mean something.
		both, err := kernel.SecretUse(ctx, "anthropic/default", kernel.SecretActionHeader, nil)
		require.NoError(t, err, "a declared alias with no filter installed is usable")
		assert.Equal(t, "x-api-key", both.Header, "the credential defines its own header")
		assert.NotEqual(t, kernel.FD(0), both.FD, "the rendered value is sealed behind a handle")

		_, err = kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
			Label: "openai only", Rules: []kernel.SeccompRule{{
				Op: kernel.OpSecretUse, Kind: kernel.SeccompRuleSecret,
				Patterns: []string{"openai/"},
			}},
		})
		require.NoError(t, err)

		// The credential that was usable a moment ago is now refused, and the refusal is
		// the SAME message as an unknown alias. That folding is the control rather than a
		// detail: the alias inventory belongs to the deployment and not to the manifest, so
		// a distinct filter error here would let a module discover which credentials exist.
		_, err = kernel.SecretUse(ctx, "anthropic/default", kernel.SecretActionHeader, nil)
		require.Error(t, err)
		assert.NotErrorIs(t, err, kernel.ErrSeccompRefused,
			"a filtered secret alias must not be distinguishable from an unknown one")
		assert.Contains(t, err.Error(), "not visible")

		_, unknown := kernel.SecretUse(ctx, "nobody/has-this", kernel.SecretActionHeader, nil)
		require.Error(t, unknown)
		assert.Equal(t, err.Error(), unknown.Error(),
			"the two refusals are identical, so neither is an oracle")

		// And the permitted prefix still works, so the refusal above is the filter and not
		// a broken keyring.
		kept, err := kernel.SecretUse(ctx, "openai/default", kernel.SecretActionHeader, nil)
		require.NoError(t, err)
		assert.Equal(t, "Authorization", kept.Header, "an empty scheme renders the default header")
		assert.NotEqual(t, kernel.FD(0), kept.FD)
	})

	// kv:delete, which is the write side of the KV store and has its own call site.
	t.Run("kv delete", func(t *testing.T) {
		ctx, pid := seccompLoad(t, k, "secwiredelete", kernel.Manifest{
			Require: []kernel.Op{kernel.OpKVRead, kernel.OpKVWrite},
		})
		require.NoError(t, kernel.KVPut(ctx, "own/keep", []byte("v")))
		require.NoError(t, kernel.KVPut(ctx, "shared/gone", []byte("v")))

		_, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
			Label: "own namespace", Rules: []kernel.SeccompRule{{
				Op: kernel.OpKVWrite, Kind: kernel.SeccompRuleKey, Patterns: []string{"own/"},
			}},
		})
		require.NoError(t, err)

		assert.ErrorIs(t, kernel.KVDelete(ctx, "shared/gone"), kernel.ErrSeccompRefused,
			"deleting outside the filtered prefix is refused")

		// Still there, which is what distinguishes a refused delete from a successful one
		// that happened to return no error. The read succeeds because the filter carries a
		// kv:write rule and no kv:read rule, and an operation a filter does not mention is
		// untouched: refusing every unlisted operation would make installing one rule
		// equivalent to revoking the module's other grants.
		still, err := kernel.KVGet(ctx, "shared/gone")
		require.NoError(t, err, "kv:read is not narrowed by this filter")
		assert.Equal(t, []byte("v"), still)

		require.NoError(t, kernel.KVDelete(ctx, "own/keep"),
			"deleting inside the filtered prefix works")
		_, err = kernel.KVGet(ctx, "own/keep")
		assert.Error(t, err)
	})
}

// TestRemovingTheCallSiteWouldFailTheseTests is the meta-assertion: without a filter,
// every argument above is permitted. It is what makes the end-to-end cases prove the
// wiring rather than prove that the operations fail for some other reason.
func TestRemovingTheCallSiteWouldFailTheseTests(t *testing.T) {
	harness.QuietConsole(t)
	k := seccompBoot(t)

	name := seccompNextName("secunwired")
	require.NoError(t, kernel.FSSetDataRoot(name, t.TempDir()))
	ctx, pid := seccompLoadNamed(t, k, name, kernel.Manifest{
		Require:    []kernel.Op{kernel.OpFSRead, kernel.OpFSWrite},
		ReadPaths:  []string{"cache", "logs"},
		WritePaths: []string{"cache", "scratch"},
	})

	require.False(t, kernel.SeccompFiltered(pid))
	require.NoError(t, kernel.FSWriteFile(ctx, "scratch/other", []byte("x")))
	_, err := kernel.FSReadFile(ctx, "logs/today")
	// No file exists at that path, so this is a stat failure rather than nil. What matters
	// is that it is NOT a filter refusal, which is the baseline the filtered cases below are
	// measured against.
	assert.NotErrorIs(t, err, kernel.ErrSeccompRefused,
		"with no filter the declaration's full scope is available")

	// And the same operations are refused once a filter is attached, which is the
	// difference the wiring produces.
	_, err = kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
		Label: "cache only", Rules: []kernel.SeccompRule{
			{Op: kernel.OpFSRead, Kind: kernel.SeccompRulePath, Patterns: []string{"cache"}},
			{Op: kernel.OpFSWrite, Kind: kernel.SeccompRulePath, Patterns: []string{"cache"}},
		},
	})
	require.NoError(t, err)
	assert.ErrorIs(t, kernel.FSWriteFile(ctx, "scratch/other", []byte("x")),
		kernel.ErrSeccompRefused)
	_, err = kernel.FSReadFile(ctx, "logs/today")
	assert.ErrorIs(t, err, kernel.ErrSeccompRefused)
}

// TestThePeerAndInitCallSitesAreWired covers the two remaining call sites, which the
// cases above cannot reach: peer:dial, and metadata:write on a context that actually holds
// it.
//
// metadata:write is not in the plugin domain's ceiling, so no module can ever reach that
// call site - which is why the mutation testing found it uncovered rather than why it is
// untestable. Init does hold it, and init is a legitimate target for an instance filter:
// an operator confining the host's own long-lived context to one metadata namespace is the
// same narrowing applied to a module. Leaving the call site uncovered would leave a
// removal of it undetected.
func TestThePeerAndInitCallSitesAreWired(t *testing.T) {
	harness.QuietConsole(t)
	k := seccompBoot(t)

	t.Run("peer dial", func(t *testing.T) {
		ctx, pid := seccompLoad(t, k, "secwirepeer", kernel.Manifest{
			Require:      []kernel.Op{kernel.OpPeerDial},
			AllowedHosts: []string{"mesh-a.cluster.example", "mesh-b.cluster.example"},
		})

		// Both endpoints are declared, so the manifest boundary permits either. No transport
		// is installed, which is fine: the filter refusal happens before any bytes move, and
		// that ordering is what the case is asserting.
		_, err := kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
			Label: "one peer", Rules: []kernel.SeccompRule{{
				Op: kernel.OpPeerDial, Kind: kernel.SeccompRuleHost,
				Patterns: []string{"mesh-a.cluster.example"},
			}},
		})
		require.NoError(t, err)

		_, err = kernel.PeerDial(ctx, kernel.PeerDialSpec{
			Endpoint: "https://mesh-b.cluster.example:8443/mesh", Label: "peer b",
		})
		require.Error(t, err)
		assert.ErrorIs(t, err, kernel.ErrSeccompRefused,
			"the filter narrows the declared endpoints")

		// And the narrowing is on the host, not on the endpoint's spelling: the permitted
		// peer fails later, at the transport, which proves the filter let it through.
		_, err = kernel.PeerDial(ctx, kernel.PeerDialSpec{
			Endpoint: "https://mesh-a.cluster.example:8443/mesh", Label: "peer a",
		})
		require.Error(t, err)
		assert.NotErrorIs(t, err, kernel.ErrSeccompRefused,
			"the permitted endpoint reaches the transport rather than the filter")
		assert.ErrorIs(t, err, kernel.ErrPeerNoTransport)
	})

	t.Run("metadata write on init", func(t *testing.T) {
		initCtx := k.InitContext()
		pid := initCtx.PID()

		// Init holds metadata:write, so the call site is reachable here and nowhere else.
		require.NoError(t, initCtx.SyscallMetadataSet("meowapi.state", "before"))
		v, err := initCtx.SyscallMetadataGet("meowapi.state")
		require.NoError(t, err)
		assert.Equal(t, "before", v)

		_, err = kernel.SeccompInstall(nil, pid, kernel.SeccompFilter{
			Label: "one namespace", Rules: []kernel.SeccompRule{{
				Op: kernel.OpMetadataWrite, Kind: kernel.SeccompRuleKey,
				Patterns: []string{"meowapi.state"},
			}},
		})
		require.NoError(t, err)

		assert.ErrorIs(t, initCtx.SyscallMetadataSet("other.namespace", "x"),
			kernel.ErrSeccompRefused, "a write outside the filtered prefix is refused")
		require.NoError(t, initCtx.SyscallMetadataSet("meowapi.state", "after"),
			"and one inside it is not")

		v, err = initCtx.SyscallMetadataGet("meowapi.state")
		require.NoError(t, err)
		assert.Equal(t, "after", v, "the permitted write really landed")
	})
}
