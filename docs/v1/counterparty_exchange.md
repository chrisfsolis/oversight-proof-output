# Counterparty attestation exchange (v1)

> **Status: runtime CLI and local app, design-forward, offline.** This document, its JSON Schema, the example
> envelopes, and `oversight-anchor exchange offer|verify|acknowledge` describe and implement a local
> file workflow. There is still no hosted delivery, registry, write-back, revocation, or expiry
> protocol. Wording here is advisory; it makes no certification or compliance claims.

A **counterparty attestation exchange** lets one party hand an [oversight receipt](receipt_spec.md)
to another party — an auditor, a customer, a partner, a regulator's reviewer — in a small, portable,
**offline-verifiable** envelope, and lets the receiver check it without ever seeing the sender's
underlying decision data. It builds directly on the existing publishable core (the salted commitment
plus allowlisted, non-PII metadata plus the enforced advisory statement) and adds only the metadata
needed to describe the exchange itself.

Exchanging an envelope is **evidence that a human review occurred and was shared**: that an
Oversight Proof evidence dossier existed at the anchored time, has not changed since, and was passed
from a named sender to a named audience for a stated purpose. It is **not** a determination that
either party is in compliance with any obligation, and **not** a certification of the counterparty.
It is advisory evidence for an accountable human owner, not legal advice and not a compliance
determination.

## The exchange envelope

An exchange envelope is a JSON object
(schema: [`counterparty_exchange.schema.json`](counterparty_exchange.schema.json),
`schema_version: "oversight-exchange-v1"`) with three required blocks and one optional block:

- **`receipt`** — a full, publishable oversight receipt, exactly as defined by
  [`receipt.schema.json`](receipt.schema.json): its `commitment` (the salted root), its allowlisted
  `metadata`, its independent `anchors`, and the receipt's own verbatim `claims`. This is the same
  object that already may leave the machine; the exchange carries it unchanged.
- **`exchange`** — metadata describing the hand-off: an opaque `sender` identifier, the intended
  `audience` (recipient), a free-text `purpose`, an `issued_at` timestamp, and an opaque
  `exchange_id`. These describe *who shared what, with whom, and why* — never any review content.
- **`claims`** — the advisory statement for the exchange itself, embedded verbatim (below).
- **`counter_signature`** *(optional)* — a recipient's countersignature over what it received (see
  [Counter-attest](#3-counter-attest-optional)).

### What must NEVER be included

An envelope carries only publishable data. The following never appear in any envelope, in any block:

- the **salt** (`HMAC` key) used to blind the dossier root;
- the **local witness** (the salt plus the raw dossier root kept beside the packet);
- the **raw dossier root** hash (only its salted commitment travels);
- any **decision data** — decision-log fields, review content, outcomes, reviewer identities, or any
  other PII; and
- any **non-allowlisted metadata** — the `metadata` block is restricted to the same allowlist as a
  receipt (`ALLOWED_METADATA_KEYS`), and the exchange metadata is restricted to the fields named
  above. A key outside those sets does not belong in an envelope.

This is enforced as an **allowlist, not a denylist**, and a test asserts the example envelopes carry
none of the forbidden material.

## CLI workflow

The runtime surface is the `oversight-anchor exchange` command group. It runs locally and does not
make network calls.

Create an offer from an existing receipt directory:

```sh
oversight-anchor exchange offer <receipt_dir> \
  --sender <opaque-sender> \
  --audience <opaque-audience> \
  --purpose <text> \
  --issued-at <date-time> \
  --exchange-id <safe-id> \
  --out <exchange_dir>
```

The output directory contains `exchange.json` plus only the anchor proof files referenced by the
receipt. The sender's `local_witness.json`, salt, raw dossier root, and decision data are not copied.

Verify an exchange offline, anchor-only:

```sh
oversight-anchor exchange verify <exchange_dir>
```

If the envelope carries a detached recipient acknowledgement, the receiver can also verify the COSE
signature bytes with a raw Ed25519 public key:

```sh
oversight-anchor exchange verify <exchange_dir> --countersigner-key <recipient_pub.raw>
```

A receiver may acknowledge exactly the received publishable commitment by writing a new exchange
directory:

```sh
oversight-anchor exchange acknowledge <exchange_dir> \
  --recipient <opaque-recipient> \
  --signed-at <date-time> \
  --signing-key <recipient_seed.raw> \
  --out <acknowledged_exchange_dir>
```

`acknowledge` and `verify --countersigner-key` reuse the existing lazy COSE helpers and therefore
need the optional `timestamp` extra. The base offer and anchor-only verification paths remain
stdlib-only and offline.

## Local app workflow

The local web app exposes the same narrow workflow in the **Counterparty exchange** card:

- **Create exchange envelope** uploads a receipt `.zip` to the local loopback process with explicit
  `sender`, `audience`, `purpose`, `issued_at`, and `exchange_id` values. The browser does not fill
  the time or generate an id.
- **Verify exchange envelope** uploads an exchange `.zip` and optionally a countersigner public key.
  The server calls the same anchor-only verification helper used by the CLI; it never invokes the
  witness-based receipt verifier and never treats a countersignature as an anchor.
- **Acknowledge exchange envelope** uploads an exchange `.zip`, explicit recipient and `signed_at`,
  and a local private key file. The key is used in memory for that request and is not written to
  local history, `SecureStore`, temp files, logs, browser responses, or the downloaded bundle.
- **Download** returns the created or acknowledged exchange bundle through an opaque local token,
  stored encrypted at rest under the local profile.

The app does not add delivery, registry, revocation, expiry, replay, key management, or write-back.
It is a local convenience surface over the file workflow.

## Flow

The exchange is a four-step flow. Every step is offline; nothing here makes a network call.

### 1. Offer

The sender builds an envelope from an existing receipt plus the exchange metadata, for example with
`oversight-anchor exchange offer`, and hands it to the
audience by any transport (a file, an email attachment, an object store, a portal upload). The
envelope is self-contained: it carries the receipt and its anchor proofs.

### 2. Verify (anchor-only)

The receiver verifies the envelope's receipt **anchor-only**, for example with
`oversight-anchor exchange verify`, with the semantics of
`anchor_verify`: it checks each anchor proof against the receipt's public salted commitment —
**existence, time, and immutability** — and recomputes nothing from a witness, because it holds no
witness. A receipt with more than one independent anchor is not backed by a sole authority; the
receiver decides which anchor authorities it trusts. The receiver confirms the hand-off **without any
underlying data present to surface.**

The witness-based holder path (`receipt_verify`, which ties a receipt to one specific dossier on the
machine that produced it) is deliberately **not** part of the exchange: it stays local to the sender.

### 3. Counter-attest (optional)

The receiver may issue its own **COSE Signed Statement**, for example with
`oversight-anchor exchange acknowledge`, over exactly what it received — the receipt's
publishable core (`salted_root_hex`, the allowlisted metadata, and the advisory statement) — following
the shape of `cose.build_signed_statement`: a `COSE_Sign1` (RFC 9052) whose protected header names the
algorithm (Ed25519 / COSE `EdDSA`) and a content type, and whose CWT claims carry the recipient as the
issuer (`iss`) and the salted commitment as the subject (`sub`). Recording this in the envelope's
`counter_signature` block is a durable acknowledgement that the recipient *received and checked* this
exact commitment at a stated time. It signs only publishable data; it adds no witness and no secret.

### 4. Record

Each side keeps its own **local record**: the sender keeps the envelope it offered (and its local
witness, unshared); the receiver keeps the envelope it verified and any countersignature it issued.
There is no shared ledger and no central authority — two independent local records that each verify
offline.

## Trust boundaries

What each party can and cannot see or prove:

| | Sender | Receiver |
| --- | --- | --- |
| Sees the raw dossier / decision data | Yes (local) | **No** — never leaves the sender |
| Holds the salt + raw root (witness) | Yes (local) | **No** |
| Can verify existence, time, immutability | Yes | **Yes** (anchor-only) |
| Can tie the commitment to a specific dossier | Yes (witness) | **No** |
| Can determine the counterparty is in compliance | **No** | **No** |

- **The receiver verifies without any underlying data.** Anchor-only verification confirms that a
  dossier committing to the salted root existed no later than the anchored time and has not changed —
  it does not reveal, and cannot reconstruct, what the dossier contained.
- **Multi-anchor, never a sole authority.** Trust rests on the independent public-log anchors a
  verifier chooses to trust (RFC 3161 / OpenTimestamps / an external SCITT log), not on trusting the
  sender or any single service. An envelope stands as long as any one of its anchor authorities is
  sound.
- **A countersignature is an acknowledgement, not a verdict.** It records that the recipient received
  and checked a specific commitment; it is not a statement that the sender's process is adequate or
  that any obligation is met.

## Honesty framing

An exchange moves an **anchor on evidence**, never a judgment about it. Verifying an envelope confirms
provenance (existence, time, immutability) and the fact of a shared hand-off. It does not attest that
the underlying human review was meaningful, that the inputs were truthful or complete, or that any
legal or regulatory obligation is met. Two honest parties end up with two independent, offline-
verifiable records of the same fact — nothing more, and nothing that reveals the sender's data.

## Non-goals / not yet built

The runtime exchange surface is intentionally narrow. This batch does **not** deliver:

- **No network transport.** No offer delivery, no fetch, no online anchor refresh, and no default
  endpoint.
- **No hosted exchange surface.** Any hosted delivery, registry, portal, or shared ledger is out of
  scope; the local, offline records are the whole model here.
- **No hosted or enterprise exchange surface.** The local app wraps this file workflow, but the
  enterprise server and hosted attest service remain unchanged.
- **No write-back.** The CLI writes local exchange files only. It does not update a system of record
  or notify a counterparty.
- **No key management.** Optional acknowledgement expects caller-managed local Ed25519 key material;
  it does not create a trust store or manage recipient identities.
- **No revocation, expiry, or replay protocol.** How a party withdraws or supersedes an offered
  envelope is deliberately left for a later design.

## Standards alignment

The exchange invents no proprietary proof format. It reuses the receipt and anchor formats already
specified in [receipt_spec.md](receipt_spec.md), and its optional countersignature follows
**SCITT / COSE**:

- **COSE** (RFC 9052 / RFC 9053) for the `COSE_Sign1` signed statement, and RFC 8392 CWT claims
  (`iss`, `sub`) in its protected header — the same shape `cose.build_signed_statement` already emits.
- **RFC 9162** (the transparency-log Merkle structure) for the SCITT anchor an underlying receipt may
  already carry.
- **SCITT** (Supply Chain Integrity, Transparency and Trust) as the framing for a signed statement
  exchanged between parties and optionally logged in a transparency service.

**SCITT is still settling** as a standard, so this exchange format is **design-forward, not final**:
it is aligned with the direction of COSE/SCITT and the existing receipt formats, and is expected to
track those specifications as they stabilize.

## Related

- [receipt_spec.md](receipt_spec.md) — the oversight receipt format the envelope carries.
- `receipt_threat_model.md` (part of the licensed engine documentation, not published here) —
  what a receipt does and does not prove, the salting scheme, multi-anchor as
  not-a-sole-authority, and the publishable-vs-local boundary this exchange inherits.

## Independent implementations

This exchange-envelope format is openly licensed (see the License below), so producing or checking an
envelope does not require Oversight Proof's own tooling. Anyone may implement their own producer or
verifier against [`counterparty_exchange.schema.json`](counterparty_exchange.schema.json) and the
[`receipt.schema.json`](receipt.schema.json) it embeds, in any language, including in a commercial or
competing product. A recipient can verify an envelope independently — from the schemas, the embedded
`claims`, and the public anchor standards — without trusting or running Oversight Proof's code. That
independence is the point: the artifact carries its own evidence, so trust does not depend on the
vendor.

## License
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Oversight Proof LLC. This specification is licensed under the
Apache License, Version 2.0 (see LICENSE-APACHE.txt). You may implement this format
freely, including in commercial and competing products.
