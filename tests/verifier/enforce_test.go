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

package verifier

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/xingguangcuican6666/MeowAPI/kernel"
	"github.com/xingguangcuican6666/MeowAPI/tests/harness"
)

// The boot-time posture, tested through the paths a deployment actually takes.
//
// Everything here was previously untestable, because VerifyManifestLoad had no caller on
// the load path: the appraisal could be asserted directly and the suite did, but nothing
// could show that LoadModule invoked it. AGENT.md's claim that a manifest is appraised
// before any module code runs was false for the whole life of the subsystem while those
// direct-call tests were green. These tests assert the wiring instead.

// TestAnUnsignedBootRefuses is the default a deployment gets.
func TestAnUnsignedBootRefuses(t *testing.T) {
	harness.QuietConsole(t)
	k, err := kernel.Boot(kernel.BootConfig{TrustRoot: kernel.BootTrustRoot{NodeID: "n"}})
	// Boot loads no modules here, so it succeeds; what must refuse is the load.
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Shutdown() })

	assert.Equal(t, kernel.VerifierEnforce, kernel.VerifierPolicyCurrent(),
		"the default posture is enforce, whatever the trust root holds")

	harness.RegisterProbe(t, "unsigned", &harness.NoopModule{})
	_, err = k.Load(kernel.Manifest{
		Name: "unsigned", Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1,
	})
	require.Error(t, err, "an unsigned manifest must not load under the default posture")
	assert.True(t, errors.Is(err, kernel.ErrVerifierUnsigned), "got %v", err)

	// The refusal is on the chain, in the ledger, and in the process table - the three
	// places an investigator looks.
	var onChain bool
	for _, e := range kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditReject}) {
		if e.Fields["module"] == "unsigned" {
			onChain = true
		}
	}
	assert.True(t, onChain, "the refusal is on the audit chain")
	assert.NotEmpty(t, kernel.VerifierLedger(), "and in the appraisal ledger")
	var rejected bool
	for _, r := range kernel.ProcTable() {
		if r.Name == "unsigned" && r.State == kernel.ProcRejected {
			rejected = true
		}
	}
	assert.True(t, rejected, "and as a rejected record, so it is investigable")
}

// TestAnUnsignedBootFailsTheBootWhenTheModuleIsConfigured is the shape a deployment
// meets first: the module is in BootConfig.Modules, so the whole boot is refused rather
// than the daemon coming up without it.
func TestAnUnsignedBootFailsTheBootWhenTheModuleIsConfigured(t *testing.T) {
	harness.QuietConsole(t)
	harness.RegisterProbe(t, "configured", &harness.NoopModule{})

	_, err := kernel.Boot(kernel.BootConfig{
		TrustRoot: kernel.BootTrustRoot{NodeID: "n"},
		Modules: []kernel.Manifest{{
			Name: "configured", Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1,
		}},
	})
	require.Error(t, err, "a boot whose configured module is unsigned must be refused")
	assert.Contains(t, err.Error(), "boot aborted")
	assert.True(t, errors.Is(err, kernel.ErrVerifierUnsigned), "got %v", err)

	// The guard was released on the way out, so the failure is recoverable rather than
	// terminal for the process.
	assert.NotPanics(t, func() {
		k, berr := kernel.Boot(kernel.BootConfig{
			TrustRoot:      kernel.BootTrustRoot{NodeID: "n"},
			VerifierPolicy: kernel.VerifierOff,
		})
		require.NoError(t, berr, "a corrected boot must be possible after a refused one")
		_ = k.Shutdown()
	})
}

// TestASignedBootLoads is the positive case: a manifest signed by a key the trust root
// names loads, and the module that loaded is the one that was appraised.
func TestASignedBootLoads(t *testing.T) {
	seed, pub := verifierKeyPair(t)
	harness.QuietConsole(t)

	m := verifierManifest("signed-boot", kernel.OpLogWrite)
	sig := verifierSign(t, seed, m)

	var onLoadRan bool
	harness.RegisterProbe(t, m.Name, &harness.Probe{Load: func(kernel.SContext) error {
		onLoadRan = true
		return nil
	}})

	k, err := kernel.Boot(kernel.BootConfig{
		TrustRoot: kernel.BootTrustRoot{
			NodeID: "n", ClusterRootKeys: []string{pub}, SigningKeyPEM: seed,
		},
		Modules:       []kernel.Manifest{m},
		ModulesSigned: map[string]*kernel.VerifierSignature{m.Name: &sig},
	})
	require.NoError(t, err, "a correctly signed configured module must load")
	t.Cleanup(func() { _ = k.Shutdown() })

	assert.True(t, onLoadRan)
	require.Len(t, kernel.LoadedModules(), 1)
	assert.Equal(t, m.Digest(), kernel.LoadedModules()[0].Manifest.Digest())

	// The boot record names the posture, so an investigator reading the chain after the
	// fact does not have to infer it.
	var named bool
	for _, e := range kernel.AuditQuery(kernel.AuditFilter{Kind: kernel.AuditBoot}) {
		if e.Fields["verify_policy"] == string(kernel.VerifierEnforce) {
			named = true
		}
	}
	assert.True(t, named, "the boot record names the posture in force")
}

// TestBootRefusesAConfiguredModuleSignedForAnotherDeclaration is the widening case, at
// the boot path: the signature is real, the key is trusted, and the manifest changed
// after signing. That is the exact attack the subsystem exists for.
func TestBootRefusesAConfiguredModuleSignedForAnotherDeclaration(t *testing.T) {
	seed, pub := verifierKeyPair(t)
	harness.QuietConsole(t)

	narrow := verifierManifest("widened", kernel.OpLogWrite)
	sig := verifierSign(t, seed, narrow)

	wide := verifierManifest("widened", kernel.OpLogWrite, kernel.OpKVWrite)
	require.NotEqual(t, narrow.Digest(), wide.Digest(), "the fixture must actually differ")

	harness.RegisterProbe(t, wide.Name, &harness.NoopModule{})
	_, err := kernel.Boot(kernel.BootConfig{
		TrustRoot: kernel.BootTrustRoot{
			NodeID: "n", ClusterRootKeys: []string{pub}, SigningKeyPEM: seed,
		},
		Modules:       []kernel.Manifest{wide},
		ModulesSigned: map[string]*kernel.VerifierSignature{wide.Name: &sig},
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, kernel.ErrVerifierDigestMismatch),
		"the refusal must say the digest moved, got %v", err)
}

// TestTheBootPolicyFieldIsTheConfigurationWindow pins the ordering the field exists for.
// Boot loads its modules before it returns, so a host that calls VerifierSetPolicy after
// Boot has already missed the window - and under enforce the load has already happened.
func TestTheBootPolicyFieldIsTheConfigurationWindow(t *testing.T) {
	harness.QuietConsole(t)
	harness.RegisterProbe(t, "declared", &harness.NoopModule{})

	m := kernel.Manifest{Name: "declared", Version: "1", MinKernelAPI: 1, MaxKernelAPI: 1}

	// Declared off: the unsigned module loads.
	k, err := kernel.Boot(kernel.BootConfig{
		TrustRoot:      kernel.BootTrustRoot{NodeID: "n"},
		VerifierPolicy: kernel.VerifierOff,
		Modules:        []kernel.Manifest{m},
	})
	require.NoError(t, err)
	assert.Len(t, kernel.LoadedModules(), 1)
	require.NoError(t, k.Shutdown())

	// And the same module, same build, refused when the boot declares nothing - which is
	// what makes the field load-bearing rather than decorative.
	_, err = kernel.Boot(kernel.BootConfig{
		TrustRoot: kernel.BootTrustRoot{NodeID: "n"},
		Modules:   []kernel.Manifest{m},
	})
	require.Error(t, err)
	assert.True(t, errors.Is(err, kernel.ErrVerifierUnsigned), "got %v", err)
}

// TestAPreBootPolicyIsHonoured pins the window kverifier documents: a host may set the
// posture BEFORE calling Boot, and that choice governs the boot that follows. Wiring
// resetVerifier into resetKernel cleared it, which silently broke this path; the restore
// in Boot is what keeps the documented behaviour true.
func TestAPreBootPolicyIsHonoured(t *testing.T) {
	harness.QuietConsole(t)
	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierOff))

	k, err := kernel.Boot(kernel.BootConfig{TrustRoot: kernel.BootTrustRoot{NodeID: "n"}})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Shutdown() })

	assert.Equal(t, kernel.VerifierOff, kernel.VerifierPolicyCurrent(),
		"a posture set before Boot governs the boot that follows it")

	// And it is cleared with the boot, so the next one does not inherit it.
	require.NoError(t, k.Shutdown())
	assert.Equal(t, kernel.VerifierEnforce, kernel.VerifierPolicyCurrent(),
		"the next boot re-derives its posture rather than inheriting this one")
}

// TestABootPolicyOverrideBeatsThePreBootChoice pins precedence: BootConfig wins, because a
// deployment's own configuration file is more specific than a call the process made
// earlier.
func TestABootPolicyOverrideBeatsThePreBootChoice(t *testing.T) {
	harness.QuietConsole(t)
	require.NoError(t, kernel.VerifierSetPolicy(kernel.VerifierOff))

	k, err := kernel.Boot(kernel.BootConfig{
		TrustRoot:      kernel.BootTrustRoot{NodeID: "n"},
		VerifierPolicy: kernel.VerifierEnforce,
	})
	require.NoError(t, err)
	t.Cleanup(func() { _ = k.Shutdown() })

	assert.Equal(t, kernel.VerifierEnforce, kernel.VerifierPolicyCurrent())
}
