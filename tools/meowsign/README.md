# meowsign

`meowsign` mints the detached manifest signature the MeowAPI kernel requires before
it will load a module. It runs on the operator's machine, not in the kernel: kverifier
deliberately offers no signing entry point, because a signing function inside the
kernel would be reachable from any module linked into the same binary, and a module
that could appraise its own widened declaration is the exact attack the appraisal
exists to stop. What the kernel exports is the payload a signature must cover. This
command is the other half.

Build it with the rest of the host tools:

```
go build -o bin/meowsign ./tools/meowsign
```

## What a signature covers

A signature is an ed25519 signature over `kernel.VerifierBindingPayload(m)`, which is
the module's name, its version and the manifest's digest, each written as a
length-prefixed `name=value` pair in a fixed order. The digest is `Manifest.Digest()`,
the sha256 of the marshalled manifest, so two manifests that differ only in whitespace
or key order sign identically and one whose `require` list grew does not.

Signing anything else produces a file the kernel refuses as a bad signature. Use the
exported payload function rather than re-deriving the bytes, which is what this command
does and the reason it imports `kernel`.

## Signing a component

Write the component's declaration as JSON. It must be the same declaration the
component exports as its `MeowAPIManifest` symbol, because the kernel appraises the
manifest the component carries and not a copy of it:

```json
{
  "name": "example",
  "version": "0.1.0",
  "min_kernel_api": 1,
  "max_kernel_api": 1,
  "require": ["log:write", "metadata:read", "cputime:read"]
}
```

Then sign it, writing the signature beside the component where the console loader
looks for it:

```
meowsign -manifest example.json -key signing.key -out root/bin/example.so.sig
```

`-key` names a file, `-key-hex` gives the material inline. Prefer the file: a seed on a
command line lands in the shell history and in the process listing of every account on
the host. Key material is never printed by this command, on success or in an error.

The command prints the declaration audit first, and refuses to sign when it reported
anything:

```
meowsign: the declaration audit reported 3 finding(s) for wide 0.1.0:
  1. [missing-scope] secret_prefixes: a secret operation is requested with no key
     prefix declared, so the keyring scope is empty and every alias is invisible
  2. [private-host] allowed_hosts: host "10.0.0.5" is a numeric address in RFC1918
     private space and passes validation, which refuses loopback by name only
  3. [path-form] read_paths: path "cache/../cache" cleans to "cache", and the cleaned
     form is the grant, not the spelling under review
meowsign: refusing to sign wide 0.1.0: resolve the findings above, or pass -force
```

The findings are advisory in the kernel and stay that way - it loads modules and must
not turn a review observation into a refusal. A signing tool that printed them and
signed regardless would make the checklist decoration, so the refusal is here instead,
where the reviewer is. `-force` signs with them unresolved and says so on stderr, which
makes the decision a recorded act rather than a message scrolled past.

Finally, add the public key to the deployment's trust root. The command prints it, so
the operator does not have to derive it from the seed with a second tool:

```
meowsign: the matching cluster root key is 3ff815fb...
```

```
./MeowAPI -daemon -verify-key 3ff815fb...
```

Every `-verify-key` becomes one `cluster_root_keys` entry in the sealed trust root. A
signature whose key id is not among them is refused as untrusted, which is a key
inventory problem rather than a declaration problem, and is reported distinctly.

## Checking a signature before deploying it

```
meowsign -verify -manifest example.json -sig root/bin/example.so.sig -roots 3ff815fb...,9f2c...
```

`-roots` is the comma-separated cluster root list the deployment seals, in the same
encodings the trust root accepts. The check reproduces the kernel's own appraisal order
- structure, then identity, then digest, then trust, then the cryptographic verdict - so
the operator learns which of the kernel's refusals a deployment is about to produce, and
in the same words. It exits 0 on a clean verdict and 1 on a refusal, and takes no
signing key: verifying against public roots is not a key-custody operation.

## Key material

Both flags accept every encoding `BootTrustRoot.SigningKeyPEM` accepts, so a key the
operator already deploys works without re-encoding: a 32-byte ed25519 seed, a full
64-byte ed25519 private key, or a PKCS8 block, each carried as hex, base64 or PEM. A
public key for `-roots` takes the same carriers, as 32 raw bytes or a PKIX block.

Nothing else is accepted. A signing tool that took more material than the kernel does
would mint signatures no trust root can name, which look complete everywhere they are
read and verify nowhere.

Generate a seed with any ed25519 tooling. `openssl genpkey -algorithm ed25519` produces
a PKCS8 PEM this command reads directly.

## Exit codes

`0` minted a signature or confirmed one. `1` refused on the declaration - findings
without `-force` - or on the signature under `-verify`. `2` invoked wrongly: an
unreadable file, a manifest that does not parse or that the kernel would refuse at load,
key material that is not an ed25519 key, a flag combination that asks for nothing or for
two things at once.

A refusal to sign is a finding about the declaration and a mistake in how the command was
run is something else, so a pipeline can tell "fix the manifest" from "fix the command
line" without parsing text.

## Where the signature goes

The console's component loader reads `<component>.so` and looks for `<component>.so.sig`
beside it, parsing the file as a `kernel.VerifierSignature`. A missing file is the
unsigned case, which the default posture refuses; a file that exists and does not parse
is reported as a note explaining why a component the operator believes they signed is
being refused.

A signature stored inside the component would let the component carry and re-present its
own appraisal, which is why it travels beside the deployment rather than in it. Keep it
that way: the manifest is module-authored data, the signature is the operator's
appraisal of it, and the two must not become one file the appraised party produced.

## Flags

| Flag | Meaning |
| --- | --- |
| `-manifest` | the module manifest, as JSON |
| `-key` | a file holding the signing key material |
| `-key-hex` | the signing key material itself; never echoed back |
| `-out` | write the signature to this path instead of to stdout |
| `-force` | sign even though the declaration audit reported findings |
| `-verify` | check an existing signature instead of minting one |
| `-sig` | with `-verify`, the signature file to check |
| `-roots` | with `-verify`, comma-separated cluster root public keys |
