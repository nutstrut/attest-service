# SAR-402 Path B: local development profile

## Purpose

Lets a developer build and test the SAR-402 Path B recording-attribution
flow entirely on their own machine, using the exact same credential-loader
architecture the production Path B lane uses (`sar402_pathb_credential.py`,
`sar402_recording_wrapper.py`), without touching production key custody,
production registries, or production services.

This is a development tool, not a rotation mechanism. It does not change,
rotate, or otherwise affect production Path B, which stays pinned to
`defaultverifier-recording-ed25519-1` (active producer/verifier); the
prepared `defaultverifier-recording-ed25519-2` rotation target is untouched.

## Architecture

```
local credential file (.local-credentials/path-b-recording-dev-key)
        |
        v
Path B credential loader (sar402_pathb_credential.py — UNMODIFIED)
        |
        v
derive public key
        |
        v
startup coherence check (configured kid / expected pubkey / loaded key /
                          producer-supported kid set = {dev kid only})
        |
        v
SAR-402 recording-wrapper signer (sar402_recording_wrapper.py — UNMODIFIED)
        |
        v
local verifier (verify_recording_wrapper, same process)
```

The local workflow does not fork or duplicate the loader or the signer. It
supplies a different *value set* (dev kid, dev key file, dev public key) to
the same code, and passes a `producer_supported_kids=["defaultverifier-recording-dev-ed25519-1"]`
set to `startup_coherence_gate` instead of the production kid set — the same
fail-closed gate production goes through.

## Local credential setup

### 1. Generate a dev key

```
python3 dev/path-b-local/generate_dev_key.py
```

Writes a fresh Ed25519 seed (0600 permissions) to
`.local-credentials/path-b-recording-dev-key` and prints the kid, the public
key hex, and a short fingerprint. It never prints, logs, or returns the
private key. Refuses to overwrite an existing dev credential unless
`--force` is passed.

### 2. Create your local config

```
cp dev/path-b-local/.env.local.example dev/path-b-local/.env.local
```

Paste the `PATH_B_RECORDING_PUBLIC_KEY_HEX` value printed in step 1 into
`.env.local`. Both `.local-credentials/` and `dev/path-b-local/.env.local`
are gitignored — never commit either.

### 3. Run the local round trip

```
python3 dev/path-b-local/run_local_roundtrip.py
```

This: loads the dev credential through the unmodified production loader,
runs the startup coherence gate, builds a Path A SAR-402 receipt
(`persist=False` — never written to the production ledger), signs a Path B
recording wrapper over it, and verifies the wrapper in the same process.
Prints only safe fields: kid, public-key fingerprint, wrapped receipt
id/digest, timestamps, `wrapper_type`, `recording_context`, `verified`, and
`production_endpoint_contacted` (always `False` for this script — nothing in
this path makes a network call).

## Verifying receipts

`run_local_roundtrip.py`'s `verified` field comes from
`sar402_recording_wrapper.verify_recording_wrapper`, the same verification
function production uses — it checks the wrapper contract fields, the
authority-boundary block, the inner-receipt id/digest binding, and the
Ed25519 signature itself. A tampered wrapper or receipt makes this `False`.

## Development vs. production keys

| | Development | Production |
|---|---|---|
| kid | `defaultverifier-recording-dev-ed25519-1` | `defaultverifier-recording-ed25519-1` (active), `-2` (prepared) |
| custody | `.local-credentials/`, gitignored, generated locally | Encrypted custody artifact, root-controlled, separate from repo |
| registry | Never listed anywhere | `defaultverifier.com/.well-known/sar-keys.json` |
| loader | `sar402_pathb_credential.py` (same code) | `sar402_pathb_credential.py` (same code) |
| producer-supported kid set | `{dev kid}` only, passed explicitly by `run_local_roundtrip.py` | Live producer's kid set — currently pinned to `-1` |

The dev kid can never pass the production `startup_coherence_gate` call
(which uses the production kid set), and the production kids can never pass
the dev round trip's gate call (which uses `{dev kid}` only) — see
`tests/test_path_b_local_dev.py::test_wrong_kid_fails_closed`.

## Security rules

- Never commit `.local-credentials/` or `dev/path-b-local/.env.local`.
- Never put a private key value directly in an env file —
  `PATH_B_RECORDING_PRIVATE_KEY_FILE` points at a file on disk; the loader
  reads bytes from that path, not from the env var value itself.
- Never reuse a dev key as a production key, or vice versa.
- Never register a dev kid in a production registry.
- The loader and wrapper modules are fail-closed by construction: any
  mismatch (missing file, wrong kid, wrong public key, malformed contents)
  raises before anything is signed. Do not add a fallback path that signs
  with a different key when the configured one is unavailable.
