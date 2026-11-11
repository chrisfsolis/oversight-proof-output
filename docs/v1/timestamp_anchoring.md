# Optional timestamp anchoring (RFC 3161)

> **Status: optional, opt-in, additive.** This feature is off unless you ask for it. The engine
> stays local-first, offline, deterministic, and dependency-free; all anchoring code lives outside
> the `oversight_proof` package. Wording here is advisory — no compliance or certification claims.

## What it is

Every report/assess packet already carries an integrity manifest whose **dossier root** is the head
of a SHA-256 hash chain over the packet. That root makes the packet *tamper-evident* relative to a
previously recorded root. What the chain alone cannot show is *when* the root existed: a party who
controls every input could rebuild a fresh, internally-consistent chain after the fact (the
"post-hoc reconstruction" gap noted in `audit_oversight_method.md` and
`threat_model.md`, both part of the licensed engine documentation, not published here).

An **RFC 3161 timestamp anchor** closes that specific gap. You ask a Time-Stamping Authority (TSA)
to sign a token that says "I saw this hash at this time." The token is independent evidence that the
dossier root existed at or before the TSA's `genTime`, so the chain can no longer be silently
back-dated or re-created later without contradicting the stamp.

The token is a **sidecar**. It is written next to the packet, never inside it:

```
mypacket/                 # the canonical packet — byte-for-byte unchanged
  oversight_report.json
  integrity_manifest.json
  ...
mypacket.anchor/          # the sidecar (default: a sibling <packet>.anchor/, override with --out)
  dossier_root.tsr        # the DER-encoded RFC 3161 token
  anchor.json             # metadata: tsa_url, hash_alg, root_hex, token status, genTime
```

The sidecar never enters the canonical packet bytes, the integrity manifest, or the `inputs_hash`.
A packet is byte-identical whether or not it has been anchored — there is a test that asserts
exactly this, and the standalone trust anchor (`kit/verify.py`) still passes afterward.

## Privacy: only a hash leaves

Anchoring sends the TSA **only the dossier root hash** — never decision data, names, or any packet
content. The root is a SHA-256 digest; the TSA timestamps that digest and learns nothing about what
it summarizes. This privacy fact is stated in `oversight-anchor anchor --help`.

## Default-offline; one call to stamp, none to verify

- **No network by default.** There is no baked-in TSA URL and nothing auto-fires. The `anchor`
  command **requires** an explicit `--tsa-url` (https-only, with a timeout) before any request is
  made.
- **Obtaining a stamp needs exactly one network call** — that is inherent to asking an external
  authority for a timestamp.
- **Verifying a stamp is fully offline.** `oversight-anchor verify` makes no network call: it checks
  the token's signature against a TSA certificate (supplied with `--tsa-cert`, or the small bundled
  set of well-known TSA roots) and confirms the token's `messageImprint` commits to this packet's
  dossier root, then reports `PASS`/`FAIL` plus the `genTime`. The `verify` module imports nothing
  that can reach the network, and a test enforces that.

## Install

The dependency lives in its own optional extra; the core install is unchanged.

```sh
pip install 'oversight-proof[timestamp]'
```

## Use it

```sh
# Anchor a produced packet against a free public TSA (anonymous):
oversight-anchor anchor mypacket --tsa-url https://freetsa.org/tsr

# Verify the sidecar offline (uses the bundled roots, or pass --tsa-cert):
oversight-anchor verify mypacket
oversight-anchor verify mypacket --tsa-cert path/to/tsa-ca.pem --json
```

`python -m oversight_proof_timestamp anchor|verify ...` is equivalent to the `oversight-anchor`
console script. This CLI is deliberately separate from the `oversight` engine CLI so the engine
never gains the dependency or the network surface.

### Known free public TSAs

These are anonymous (no credential needed). Listing them does not contact them — nothing is reached
unless you pass one as `--tsa-url`:

- `https://freetsa.org/tsr`
- `https://timestamp.digicert.com`
- `https://timestamp.sectigo.com`

## The "qualified" (eIDAS) path is configuration, not new code

A *qualified* electronic timestamp from an eIDAS-accredited Qualified Trust Service Provider (QTSP)
carries an EU **legal presumption** of the date and time it shows and of the integrity of the data
it covers. Reaching that level here is purely a configuration and business decision — no code
change:

```sh
oversight-anchor anchor mypacket \
  --tsa-url https://qtsp.example/qualified/tsr \
  --tsa-credential env:QTSP_KEY
```

- `--tsa-credential` takes a **reference**, never a literal secret: `env:NAME` or `file:/path`
  (mirroring the server's credential-by-reference pattern). A bare literal is rejected.
- The secret is resolved only at request time, sent as the endpoint's `Authorization` header, and is
  **never** written to the sidecar or `anchor.json`, never returned, and redacted from any error
  text. With no credential, anchoring is anonymous against a free public TSA.

Notes on the qualified path (advisory):

- A qualified timestamp is **not required by the EU AI Act**. It is an optional strengthening for
  customers who want the eIDAS legal presumption.
- Qualified timestamps typically cost on the order of a few cents per dossier and require an account
  with a QTSP; whether that is worthwhile is a customer/business decision.
- Choosing a QTSP and paying for it does not, by itself, make any output a compliance or
  certification artifact — this tool makes no such claim.

## Dependency choice and a recorded fallback

The feature uses **`rfc3161-client`** (Trail of Bits) — the same client Sigstore uses: actively
maintained, with a memory-safe parser. It is pinned **`>=1.0.6`** because earlier versions had an
authorization-bypass in the verification path (CVE-2026-33753). It is isolated to the optional
`timestamp` extra, so the core package stays dependency-free. `rfc3161-client` pulls in
`cryptography` transitively (the same library other extras use). It ships compiled wheels for
Windows, Linux, and macOS; for an air-gapped install of this extra, vendor the platform wheel.

**Recorded fallback (not built now):** if a hard pure-Python / no-compiled-wheel air-gap requirement
ever arises, the supported fallback is to build on `asn1crypto` (pure Python, with a `tsp` module)
plus the `cryptography` already depended on, using pyHanko's timestamp module as a reference
implementation. This is recorded as a deliberate option only; it is intentionally **not**
implemented today.

## A note on trust pinning

`rfc3161-client` validates a token's chain against the union of the certificates embedded in the
token and the roots you supply. Some TSAs (e.g. FreeTSA) embed their own self-signed root in the
token, which would otherwise let it self-anchor. `verify` therefore additionally requires that any
self-signed root embedded in a token is one of the roots you actually trust, so the supplied or
bundled trust anchor is genuinely pinned.

## License
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Oversight Proof LLC. This specification is licensed under the
Apache License, Version 2.0 (see LICENSE-APACHE.txt). You may implement this format
freely, including in commercial and competing products.
