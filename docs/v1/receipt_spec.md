# Oversight receipt spec (v1)

> **Status: optional, opt-in, additive, offline.** An oversight receipt is produced *after* a packet
> exists, by the optional `timestamp` extra (outside the engine). It changes no packet bytes and the
> engine never imports it. Wording here is advisory — no compliance or certification claims.

An **oversight receipt** is a small, portable, offline-verifiable file that anchors the *existence*,
*time*, and *immutability* of an Oversight Proof evidence dossier, while revealing no decision data.
It builds on the RFC 3161 timestamp anchoring sidecar (see [timestamp_anchoring.md](timestamp_anchoring.md))
and generalizes it to multiple, independent anchors.

## What a receipt proves (and does not)

Every receipt embeds this exact statement (the single source of truth is `CLAIMS` in
`oversight_proof_timestamp/receipt.py`; it is quoted here verbatim and a test enforces the match):

> This oversight receipt attests the existence, time, and immutability of an OversightProof evidence dossier: that a dossier committing to this salted root existed no later than the anchored time and has not changed since. It does not attest that the underlying human review was meaningful, that the inputs were truthful or complete, or that any legal or regulatory obligation is met. It is advisory evidence for an accountable human owner, not legal advice and not a compliance determination.

A receipt is an anchor on evidence, never a judgment about it.

## Structure

A receipt is a JSON object (schema: [`receipt.schema.json`](receipt.schema.json),
`schema_version: "oversight-receipt-v1"`) with four required blocks:

- **`commitment`** — the salted commitment to the dossier root:
  `hmac-sha256(salt, dossier_root_bytes)` as `salted_root_hex`. This is the only representation of
  the dossier root that may leave the machine. The dossier root is the evidence-packet
  integrity-chain root; its construction is specified in
  [integrity_manifest_spec.md](integrity_manifest_spec.md).
- **`metadata`** — a small, **allowlisted**, non-PII set (schema/engine versions, dossier record
  count, `as_of` time, an opaque run id). The publishable payload can only ever carry the keys in
  `ALLOWED_METADATA_KEYS`; see `oversight_proof_timestamp/commitment.py`.
- **`anchors`** — one or more independent anchor proofs over the salted commitment (multi-anchor, so
  no single anchor is a sole authority). Each names its `type` and its offline proof file.
- **`claims`** — the advisory statement above, embedded verbatim.

## The salting scheme

`commitment = HMAC-SHA256(key = salt, msg = dossier_root_bytes)`. It is **binding** (SHA-256
preimage and collision resistance tie a commitment to one root) and **hiding** (a fresh 32-byte salt
blinds the root, so a published commitment does not confirm a guessed root without the salt). A real
receipt uses a fresh random salt per receipt; the salt and the raw dossier root stay **local** and
never enter the publishable payload. A committed example uses a fixed salt so its bytes regenerate
identically under `--check`.

## Privacy

Only the **salted commitment** plus the **allowlisted** metadata may ever leave the machine. No
decision-log field, review content, reviewer identity, or other PII is ever included — enforced as an
allowlist, not a denylist, and covered by a redaction test.

## Anchors

Anchors are pluggable and standards-forward; the receipt does not invent a proprietary proof format:

- **RFC 3161** — an existing signed timestamp token, verified offline against a trusted TSA root.
- **OpenTimestamps** — an `.ots` proof committing the salted commitment through a merkle path to a
  timestamp attestation, verified offline.
- **SCITT / COSE** — a COSE Signed Statement over the salted commitment plus a COSE Receipt (an
  RFC 9162 inclusion proof) from a transparency service, verified offline against committed issuer
  and service public keys. See *SCITT/COSE representation* below.

A receipt may carry more than one anchor, from independent authorities, so trust is never
concentrated in a single anchor. **No anchor makes a network call in this feature**: proofs are
supplied and verified from committed fixtures or local input. Obtaining or refreshing a proof online
(contacting a TSA, a SCITT transparency service, or an OpenTimestamps calendar) is the **opt-in
publish path**, isolated in one network module; see `publish.md` (part of the licensed engine
documentation, not published here).

## Verification

The standalone verifier (`scripts/verify_receipt.py`, kit-style) checks a receipt **fully offline and
deterministically**: it recomputes the salted commitment from the local salt and dossier root,
confirms the receipt's integrity, verifies each anchor's proof against the commitment, and prints
PASS/FAIL together with the advisory statement. A changed dossier root, altered metadata, or a
backdated time fails verification; the receipt threat model (salting, minimal metadata, multi-anchor
as not-a-sole-authority, and exactly what a receipt does not prove) is documented in
`receipt_threat_model.md` alongside this spec.

## SCITT/COSE representation (additive)

The same publishable core can also be represented as a SCITT-style COSE structure. This is
**additive**: the JSON receipt and the standard-library `receipt_verify` stay the primary,
dependency-free offline path, and `verify.py` never imports the COSE code. The COSE path lives in
`oversight_proof_timestamp/cose.py` and needs the optional `timestamp` extra (`cbor2` +
`cryptography`), lazy-imported so the offline core keeps working without it.

Two objects, both verified fully offline:

- **COSE Signed Statement** — a `COSE_Sign1` (RFC 9052) signed by an issuer, whose payload is the
  receipt's publishable core (`salted_root_hex`, the allowlisted metadata, and the `CLAIMS`
  statement). Only publishable data is carried; the salt and the raw dossier root are never in it.
- **COSE Receipt** — a `COSE_Sign1` signed by a transparency service over the head (root) of an
  RFC 9162 binary Merkle tree, carrying the inclusion proof for the signed statement in its
  unprotected header. Signatures use Ed25519 (COSE `EdDSA`), which is deterministic, so committed
  fixtures regenerate byte-identically.

Verification recomputes the tree head from the signed statement and the audit path (RFC 9162
§2.1.3.2) and checks the service's signature over that head, so it confirms — offline, against
committed public keys — that the statement was logged. A receipt may carry this as one `scitt`
anchor among others (multi-anchor), through the same `anchors.verify_anchor` interface as RFC 3161
and OpenTimestamps; its descriptor names the `proof_file` (the COSE Receipt) plus the
`signed_statement_file`, `issuer_key_file`, and `service_key_file`. Obtaining a COSE Receipt from a
live transparency service is the separate, opt-in publish path, never this offline layer. The
committed fixture lives at `tests/timestamp/fixtures/cose/` and is verified in
`tests/timestamp/test_cose.py`; regenerate it with `python scripts/build_cose_fixture.py`.

## Independent implementations

This format is openly licensed (see the License below), so working with it does not require
Oversight Proof's own tooling. Anyone may write their own producer or verifier against
[`receipt.schema.json`](receipt.schema.json) and this spec, in any language, including in a commercial
or competing product. A recipient checking a receipt need not trust or run Oversight Proof's code: a
receipt is meant to be verified independently from its schema, its embedded `claims` statement, and
the public anchor standards it builds on (RFC 3161, OpenTimestamps, and RFC 9052 / RFC 9162 for
SCITT/COSE). Independent verification is the intent — trust should rest on the evidence and the open
format, not on the vendor.

## License
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Oversight Proof LLC. This specification is licensed under the
Apache License, Version 2.0 (see LICENSE-APACHE.txt). You may implement this format
freely, including in commercial and competing products.
