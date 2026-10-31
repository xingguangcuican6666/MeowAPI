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
	"crypto/ed25519"
	"io"
	"testing"
)

// TestAPanicInTheSettlementWindowDoesNotWedgeShutdown pins the lock discipline in
// issueReceipt: the settlement mutex is released by defer, so a panic inside the commit
// window cannot leave it held.
//
// Nothing else in the tree can reach this. With the key-cache fix in place, no input
// makes signing panic - parseEd25519Private ends in a 64-byte key or an error on every
// path, so no operator material reaches ed25519.Sign with a wrong length - and the
// refusal happens at NodeKeyID before the window opens. That makes the defer untested by
// construction, and the property it buys is the one that turned a bad receipt into a
// ten-minute hang: the panic used to leave kreceipts.mu held, and the next taker was
// resetReceipts during Shutdown.
//
// So the test forces the cache into the state the old defect left behind. It is
// in-package for that reason, beside fsscope_test.go which reaches a package-private map
// the same way.
//
// The assertion is TryLock rather than a timed wait on Shutdown. It names the property
// - the mutex is not held - instead of measuring a consequence of it, and it cannot
// flake on a loaded runner. The consequence is real and is what the mutant shows: with
// the defer replaced by hand-managed unlocks, TryLock returns false and Shutdown blocks
// until the test's own deadline, which is how the original defect reported as a timeout
// rather than as a failure.
func TestAPanicInTheSettlementWindowDoesNotWedgeShutdown(t *testing.T) {
	// The material must equal the boot's signing key, because the cache fast path
	// compares it - and it must be unparseable, so nothing else in this kernel can
	// have populated the cache with a real key.
	const badMaterial = "not-an-ed25519-key"
	kc, err := Boot(BootConfig{Console: io.Discard,
		TrustRoot: BootTrustRoot{NodeID: "settle-probe", SigningKeyPEM: badMaterial}})
	if err != nil {
		t.Fatalf("boot: %v", err)
	}
	// Shutdown runs inline below, once the assertions have passed. This defer is the net
	// for the paths that t.Fatalf out before reaching it, and it deliberately does
	// nothing once the test has failed - because the failure this test detects IS a held
	// mutex, and Shutdown blocks on it in resetReceipts. Registering an unconditional
	// cleanup is what turned a microsecond failure into a 60-second timeout under the
	// mutant: measured, with the defer replaced by hand-managed unlocks. On the success
	// path Shutdown is therefore called twice, and the second call is a no-op because
	// Shutdown is idempotent on its own flag.
	defer func() {
		if t.Failed() {
			return
		}
		if err := kc.Shutdown(); err != nil {
			t.Errorf("shutdown after a recovered panic: %v", err)
		}
	}()

	// Force the state a cached parse failure used to leave: a non-nil priv of the wrong
	// length, with a material string that matches, so the fast path accepts it. A
	// 63-byte ed25519 key makes Sign panic with "bad private key length".
	kcryptoKeys.mu.Lock()
	kcryptoKeys.material = nodeSigningKey()
	kcryptoKeys.priv = make(ed25519.PrivateKey, ed25519.PrivateKeySize-1)
	kcryptoKeys.keyID = "forced"
	kcryptoKeys.mu.Unlock()

	var recovered any
	func() {
		defer func() { recovered = recover() }()
		// IssueReceipt is the host path. It performs no policy check, because no live
		// context holds receipt:issue, which is what makes this reachable at all.
		_, _ = kc.IssueReceipt(ReceiptSpec{Prompt: []byte("p"), Completion: []byte("c")})
	}()
	if recovered == nil {
		t.Fatalf("the forced key state must make signing panic; if it no longer does, " +
			"this test has stopped exercising the window it exists to cover")
	}

	// The property: the settlement mutex is free after the panic was recovered.
	if !kreceipts.mu.TryLock() {
		t.Fatalf("a panic inside the commit window left kreceipts.mu held; Shutdown would " +
			"block forever in resetReceipts. The unlock must be deferred.")
	}
	kreceipts.mu.Unlock()

	// Shutdown is called synchronously with no deadline of its own, and that is safe
	// only because the assertion above just proved the one lock it would block on is
	// free. Under the mutant that assertion fires first, so this line is never reached
	// and the test fails in microseconds instead of consuming the ten-minute CI timeout
	// the original defect consumed.
	if err := kc.Shutdown(); err != nil {
		t.Fatalf("shutdown after a recovered panic: %v", err)
	}

	// The forced cache state must not outlive the test. resetCrypto clears it during
	// Shutdown, so a sibling test in this package sees an empty cache rather than the
	// wrong-length key this one planted.
	kcryptoKeys.mu.Lock()
	material, priv, keyID := kcryptoKeys.material, kcryptoKeys.priv, kcryptoKeys.keyID
	kcryptoKeys.mu.Unlock()
	if material != "" || priv != nil || keyID != "" {
		t.Fatalf("the forced cache state survived Shutdown: material=%q priv!=nil? %v keyID=%q",
			material, priv != nil, keyID)
	}
}
