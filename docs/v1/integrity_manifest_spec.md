# Evidence-packet integrity format (v1)

> **Status: normative, stable, offline.** This document specifies the tamper-evidence format of an
> Oversight Proof evidence packet: the canonical serialization, the SHA-256 hash chain, the manifest
> layout, and the verification procedure. It is written so that a competent engineer with **no access
> to the Oversight Proof engine** can implement a conforming producer and verifier from this document
> alone and confirm correctness against the [test vectors](#test-vectors) below. Wording is advisory:
> the format establishes that a set of files is internally consistent and unmodified relative to a
> recorded root. It is not a legal or compliance determination and says nothing about whether the
> underlying human review was adequate.

An evidence packet is a directory of report files plus one `integrity_manifest.json`. The manifest
carries a SHA-256 **hash chain** over every other file in the packet. Recomputing the chain and
comparing its root to the recorded root detects any modified, added, removed, or reordered file. The
chain root is also the **dossier root** that an [oversight receipt](receipt_spec.md) commits to.

Key words **MUST**, **MUST NOT**, **SHOULD**, and **MAY** are used in their ordinary normative sense.

## 1. The two serializations

There are **two distinct serializations**, and using the wrong one is the single most common way an
independent implementation diverges. Read this section carefully.

1. **The canonical hashing form** (`canonical_json`) feeds **every hash**. It is compact, sorts keys,
   and normalizes timestamps. Nothing is ever hashed in any other form.
2. **The file layout** (`dumps_canonical`) is what is **written to disk**. It is a human-readable,
   insertion-ordered, hybrid layout. It is never hashed directly.

Hashes are computed over the canonical form, **NOT** over the on-disk file layout. The one place raw
file *bytes* are hashed is the per-file `sha256` in the manifest (see [§3.1](#31-integrity_manifestjson)),
and even there the resulting digest is then carried inside a small object that is hashed in canonical
form.

### 1.1 Canonical hashing form (`canonical_json` / `canonical_bytes`)

`canonical_json(value)` returns a UTF-8 string produced by:

- recursively **canonicalizing** the value (see below), then
- serializing with JSON using, in the terms of Python's `json.dumps`: `sort_keys=True`,
  `ensure_ascii=False`, `separators=(",", ":")`, `allow_nan=False`.

Concretely, the output MUST satisfy all of:

- **Keys sorted** at every level. Object keys are first stringified (see below), then sorted
  **lexicographically as strings** (byte/code-point order), not numerically.
- **Minimal separators**: `,` between members and `:` between key and value, with **no** spaces.
- **Non-ASCII preserved** (`ensure_ascii=False`): a character such as `é` (U+00E9) is emitted as its
  UTF-8 bytes (`0xC3 0xA9`), never escaped to `é`. The string is then UTF-8 encoded to
  `canonical_bytes`.
- **No `NaN` / `Infinity`** (`allow_nan=False`): these are not representable and MUST cause an error
  rather than be emitted.

Canonicalization (applied recursively before serialization):

- a **string** is passed through timestamp normalization ([§1.2](#12-timestamp-normalization));
- a **boolean** is left as `true` / `false`;
- an **object/dict** has each key replaced by its string form (`str(key)`: e.g. integer `1` becomes
  the key `"1"`, boolean `true` becomes `"True"`) and each value canonicalized recursively;
- an **array/list (or tuple)** has each element canonicalized recursively; a tuple becomes an array;
- **numbers** (`int`, `float`) and **null** are left unchanged.

`canonical_bytes(value)` = `canonical_json(value)` encoded as UTF-8.

Examples (input → `canonical_json` output):

| input value | `canonical_json` output |
| --- | --- |
| `{"b": 1, "a": 2}` | `{"a":2,"b":1}` |
| `{"x": [1, 2, {"z": 9, "y": 8}]}` | `{"x":[1,2,{"y":8,"z":9}]}` |
| `{"t": (1, 2, 3)}` | `{"t":[1,2,3]}` |
| `{1: "a", 2: "b"}` | `{"1":"a","2":"b"}` |
| `{"as_of": "2026-03-16T12:30:45+05:30"}` | `{"as_of":"2026-03-16T07:00:45Z"}` |

### 1.2 Timestamp normalization

Every **string** value is run through this normalization before hashing, so that the same instant
hashes identically no matter which timezone offset it was written with.

A string is treated as a timestamp only if it matches this shape (a superset of ISO-8601):

```
YYYY-MM-DD (T or single space) HH:MM [:SS] [.fraction] [offset]
```

where `offset` is one of `Z`, `±HH:MM`, `±HHMM`, or absent. If the string does not match the shape,
**or** matches the shape but is not a real instant (e.g. month `13`, day `99`, hour `25`, or a leap
second `:60`), it is returned **unchanged** and hashed as ordinary text.

For a matching, valid timestamp, the normalized output is `YYYY-MM-DDTHH:MM:SS[.fraction]Z`, where:

- the separator is always `T`; seconds are always present (default `00` when omitted);
- fractional seconds keep their digits with **trailing zeros trimmed**, and are dropped entirely if
  all zero;
- `Z`, `+00:00`, `+0000`, and an **absent** offset are all treated as UTC and rendered `Z` with no
  shift;
- any other numeric offset shifts the instant to UTC — a `+HH:MM` offset is **subtracted**, a
  `-HH:MM` offset is **added** — rolling minute/hour/day/month/year over as needed, then rendered `Z`.

Normalization examples (input → output):

| input | output |
| --- | --- |
| `2026-03-16T00:00:00Z` | `2026-03-16T00:00:00Z` |
| `2026-03-16T12:30:45+00:00` | `2026-03-16T12:30:45Z` |
| `2026-03-16T12:30:45+0000` | `2026-03-16T12:30:45Z` |
| `2026-03-16T12:30:45` | `2026-03-16T12:30:45Z` |
| `2026-03-16 12:30` | `2026-03-16T12:30:00Z` |
| `2026-03-16T12:30:45.500Z` | `2026-03-16T12:30:45.5Z` |
| `2026-03-16T12:30:45.000Z` | `2026-03-16T12:30:45Z` |
| `2026-03-16T12:30:45+05:30` | `2026-03-16T07:00:45Z` |
| `2026-03-16T12:30:45-08:00` | `2026-03-16T20:30:45Z` |
| `2026-03-16T23:30:45+05:30` | `2026-03-16T18:00:45Z` |
| `2026-03-16` | `2026-03-16` (date only: no time, unchanged) |
| `not-a-timestamp` | `not-a-timestamp` (unchanged) |

### 1.3 `content_hash`

```
content_hash(value) = lowercase-hex SHA-256 of canonical_bytes(value)
```

This is the only hash primitive the chain uses. Every content hash and every link hash is a
`content_hash` of some object.

### 1.4 File layout on disk (`dumps_canonical`)

Report files (including the manifests) are written with a separate **human-readable** serializer.
This layout is what lands on disk; it is **never** the input to a hash. State it precisely to
reproduce a file byte-for-byte:

- Encoding is **UTF-8**; line endings are **LF** (`\n`); the file ends with exactly one **trailing
  newline**.
- Key order is the object's **insertion order** — keys are **not** sorted (unlike the hashing form).
- Timestamps are **not** normalized in this layout (unlike the hashing form).
- Indentation is **two spaces** per level.
- A value is **"complex"** if it is an object, or an array that itself contains an object or array.
- An object is rendered **compact** on one line (using `, ` and `: ` separators, i.e. a space after
  each comma and colon) if it is empty or **none** of its values is complex; otherwise it is
  **expanded**, one `"key": value` member per line, each value rendered recursively at the next
  indent level, with a trailing `,` on every member except the last.
- An array is rendered **compact** on one line if it is empty or **no** element is itself an object
  or array; otherwise it is **expanded**, one element per line.
- Scalars (string, number, boolean, null) render as standard JSON on one line.

Because keys are not sorted and timestamps are not normalized here, a producer MUST build each object
with its members in the intended order; the layout preserves that order verbatim.

## 2. The hash chain

### 2.1 Genesis

```
GENESIS = lowercase-hex SHA-256 of the ASCII bytes "OEA-GENESIS-v1"
        = fe5644cfa7cc7d9d8a75caa6e104e83ad560ad99ada403ca33756fd45fda094a
```

### 2.2 Records

A chain is built over an **ordered list of records**. Each record is an object with exactly two
fields the chain reads:

- `record_id` (string) — a stable identifier for the record. For a packet it is the file's path
  ([§3.1](#31-integrity_manifestjson)).
- `payload` (any JSON value) — the content committed for that record. For a packet it is the object
  `{"sha256": "<hex of the file's raw bytes>"}`.

Input order **is** the committed order. For a packet, that order is the file paths sorted ascending
(byte/code-point order) as POSIX relative paths.

### 2.3 Links

For each record `i` (0-based), in order:

1. `content = content_hash(record.payload)`.
2. `prev_hash` is `GENESIS` when `i == 0`, otherwise the `link_hash` of record `i-1`.
3. `link_hash = content_hash({ "content_hash": content, "index": i, "prev_hash": prev_hash, "record_id": record.record_id })`.

The object hashed in step 3 has **exactly these four fields** — `content_hash`, `index`, `prev_hash`,
`record_id` — with the types shown (`index` is an integer; the others are strings). The link's own
`link_hash` is **not** part of the object it hashes. As always, the object is hashed via
`content_hash`, so its keys are sorted into the order `content_hash, index, prev_hash, record_id` by
the canonical form.

### 2.4 Root

The dossier **root** is the `link_hash` of the **last** record. The root of an **empty** chain (no
records) is `GENESIS`.

## 3. File layouts

All three files below are written on disk in the [§1.4](#14-file-layout-on-disk-dumps_canonical)
layout.

### 3.1 `integrity_manifest.json`

The tamper-evidence manifest at the packet root. Fields:

- `as_of` (string) — the packet's time anchor, copied from the input envelope.
- `genesis` (string) — the `GENESIS` constant (64 lowercase hex).
- `root_hash` (string) — the chain root (64 lowercase hex).
- `record_count` (integer) — the number of files covered (= number of records).
- `files` (array) — one entry per covered file, **sorted ascending by `path`**, each:
  - `path` (string) — the file's POSIX path relative to the packet root.
  - `sha256` (string) — SHA-256 (64 lowercase hex) of the file's **raw bytes** on disk.
- `records` (array) — the chain, one entry per file in the **same order** as `files`, each the link's
  five fields: `content_hash`, `index`, `link_hash`, `prev_hash`, `record_id`. Here `record_id`
  equals the file's `path`, and the record's `payload` is `{"sha256": <that file's sha256>}`.
- `note` (string) — a human-readable description of the construction.

The manifest file **itself is excluded** from the chain: when building or verifying, the file named
`integrity_manifest.json` at the packet root is not one of the covered files.

The two hashing levels for a packet file are therefore:

1. `sha256` = SHA-256 of the file's raw bytes (this is a hash of bytes, **not** of `canonical_json`).
2. the record's `content_hash` = `content_hash({"sha256": <that hex>})` (this **is** a `canonical_json`
   hash), which then feeds the `link_hash`.

### 3.2 `run_manifest.json`

A per-run manifest that some tools write beside their reports (for example under an `audit-*`
subdirectory). A verifier treats it as an ordinary packet file — it is hashed by its raw bytes like
any other and is **not** parsed to verify the chain. Its observed fields are:

- `as_of` (string) — the time anchor.
- `evidence_root_hash` (string) — the tool's own evidence root.
- `format` (string) — the output format written (e.g. `both`).
- `inputs_hash` (string) — a `content_hash` over the tool's canonical inputs.
- `output_inventory` (array of string) — the files the tool produced.
- `scenario` (string) — the scenario name.
- `schema_version` (string) — the record/schema version.
- `tool_version` (string) — the producing **component's** frozen version.

**No oversight-proof package version appears in `run_manifest.json`.** The `tool_version` above is the
individual audit component's own frozen version (data-bearing, part of the reproducibility baseline),
never the version of the installed `oversight-proof` package. This is deliberate: excluding the
package version is what lets the same input reproduce **byte-identical** packet files regardless of
which package version produced them (see `DECISIONS.md` and `docs/versioning.md`, both
part of the licensed engine documentation, not published here). A conforming producer MUST NOT
write the package version into any packet file.

### 3.3 `snapshot_envelope.json`

The input envelope the packet was produced from. It is included in the packet so a verifier can
re-derive the reports and confirm reproducibility. Its top-level shape is `schema_version` (string),
`as_of` (string), an optional `scenario` (string), the record arrays (`review_items`, `decision_log`,
`dispositions`, `reviewer_roster`), and the policy blocks. Its full field-by-field contract is the
[snapshot contract](snapshot_contract.md); it is not repeated here. For integrity purposes it is one
more covered file, hashed by its raw bytes.

## 4. Verification

A verifier is given a packet directory. It MUST:

1. Read `integrity_manifest.json` at the packet root.
2. Enumerate every file under the packet **except** the `integrity_manifest.json` at the packet
   root, as POSIX paths relative to the packet root, and **sort them ascending**. A file of that
   name in a subfolder is an ordinary file and is covered like any other.
3. For each file, compute `sha256` of its raw bytes, and form the record
   `{ "record_id": <path>, "payload": {"sha256": <sha256>} }`.
4. Build the chain ([§2](#2-the-hash-chain)) over those records in sorted order and take its root.
5. Compare against the manifest.

**PASS** requires all of: the recomputed record count equals the manifest's; each recomputed
`record_id`, `content_hash`, and `link_hash` equals the manifest's stored record at the same index;
and the recomputed root equals the manifest's `root_hash`. If an `expected_root` is supplied out of
band (for example from a receipt or `provenance.json`), it MUST also equal the recomputed root.

Otherwise the result is **FAIL**, and a conforming verifier SHOULD name the **first** divergence, by
index and kind:

- **`count`** — the packet has more or fewer files than the manifest (a file was **added** or
  **deleted**); reported at the boundary index (the smaller of the two counts).
- **`record_id`** — the file at an index differs from the manifest's (reordering).
- **`content`** — a file's `content_hash` differs (its **bytes were modified**); the file is named by
  its `record_id`/path.
- **`link`** — the per-link hash differs though content matched (a chain inconsistency).
- **`root`** — every per-record hash matched but the manifest root, or a supplied expected root,
  differs.

A single changed byte in any covered file surfaces as a `content` divergence naming that file; a
deleted or added file surfaces as a `count` divergence. The check reads only bytes already in the
packet: it makes no network call and reads no wall clock.

## Test vectors

The values below were produced by running the reference engine; an anti-drift test
(`tests/docs/test_integrity_spec_vectors.py`, in the licensed engine repository, not published
here) re-derives them and fails the build if this document and the implementation ever disagree.

### Constants

- `GENESIS` = `fe5644cfa7cc7d9d8a75caa6e104e83ad560ad99ada403ca33756fd45fda094a`
- `content_hash({"sha256":"<64 zeros>"})` = `2827b82d5d864b615b237ca45cf8a10fc5c14a1b73ba5bb8b358dddefc8e9f8c`

### Worked chain: two records

Inputs, in committed order (each record is `{"record_id": …, "payload": …}`):

- record 0: `record_id` = `a.txt`, `payload` = `{"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}`
- record 1: `record_id` = `b.txt`, `payload` = `{"sha256":"1111111111111111111111111111111111111111111111111111111111111111"}`

Step by step:

**Record 0** (`prev_hash` = `GENESIS`):

- `canonical_json(payload)` = `{"sha256":"0000000000000000000000000000000000000000000000000000000000000000"}`
- record 0 `content_hash` = `2827b82d5d864b615b237ca45cf8a10fc5c14a1b73ba5bb8b358dddefc8e9f8c`
- link object = `{"content_hash":"2827b82d5d864b615b237ca45cf8a10fc5c14a1b73ba5bb8b358dddefc8e9f8c","index":0,"prev_hash":"fe5644cfa7cc7d9d8a75caa6e104e83ad560ad99ada403ca33756fd45fda094a","record_id":"a.txt"}`
- record 0 `link_hash` = `42972df35edd5a076453875357f57bed92e8840ac79b31678a601e1f636848c2`

**Record 1** (`prev_hash` = record 0's `link_hash`):

- `canonical_json(payload)` = `{"sha256":"1111111111111111111111111111111111111111111111111111111111111111"}`
- record 1 `content_hash` = `96f554e44817506903722ba66b6b001897989fe181ef986478bc023e1fedf4b1`
- link object = `{"content_hash":"96f554e44817506903722ba66b6b001897989fe181ef986478bc023e1fedf4b1","index":1,"prev_hash":"42972df35edd5a076453875357f57bed92e8840ac79b31678a601e1f636848c2","record_id":"b.txt"}`
- record 1 `link_hash` = `4d24f04684369303bf85693d26e9f0c4556b998b6a4fab5248491782726363b5`

Result:

- dossier `root_hash` = `4d24f04684369303bf85693d26e9f0c4556b998b6a4fab5248491782726363b5`
- root of an empty chain = `GENESIS` = `fe5644cfa7cc7d9d8a75caa6e104e83ad560ad99ada403ca33756fd45fda094a`

### End-to-end reference

A committed, openly licensed end-to-end artifact lives in
[`examples/receipt/`](../../examples/receipt/) (Apache-2.0; the grant travels as this
repository's top-level `LICENSE`, and the engine's `examples/README.md` is part of the licensed
engine documentation, not published here). Its `local_witness.json` records a real
`dossier_root_hex` — a chain root produced by exactly this construction — and `receipt.json` shows the
salted commitment over that root (see [receipt_spec.md](receipt_spec.md)). This links the integrity
format specified here to the receipt layer built on top of it.

## Independent implementations

This format is openly licensed (see the License below), so working with it does not require the
Oversight Proof engine. Anyone may write their own producer or verifier from this document, in any
language, including in a commercial or competing product, and confirm it against the test vectors
above. A recipient checking a packet need not trust or run Oversight Proof's code: everything needed to
recompute the chain and detect tampering is specified here. Independent verification is the intent —
trust should rest on the recomputable evidence and the open format, not on the vendor.

## License
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Oversight Proof LLC. This specification is licensed under the
Apache License, Version 2.0 (see LICENSE-APACHE.txt). You may implement this format
freely, including in commercial and competing products.
