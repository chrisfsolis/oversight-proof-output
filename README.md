# OversightProof — the verifier and the v1 formats

SPDX-License-Identifier: Apache-2.0

This is the open half of OversightProof: the v1 evidence-packet formats, and a
standard-library-only verifier that re-checks a delivered packet offline. A writer SDK for the
agent action log format is planned; today this repository is the verifier and the formats. The
verifier reports whether a packet's files match its manifest and a root hash — the one recorded in
the kit, or one you received separately; it has no opinion about what the packet says.

OversightProof is **advisory**. It does not make legal, regulatory, or compliance determinations,
and its framework mappings (including EU AI Act Article 14) are orientation only, not legal advice.

## Verify a packet in one minute

A committed sample kit is in this repository, so there is something to run before you have a packet
of your own.

```
git clone https://github.com/chrisfsolis/oversight-proof-output
cd oversight-proof-output
python3 verify.py examples/kit/reference_packet
```

```
PASS (internally consistent): every file matches the manifest and the root recorded in this kit (ce699c8ef1c4b717de1f585ded9eba7b1a03388fc8c388446a49a03c19b57280). To confirm the packet is the one that was sent, compare this root with one you received separately, or run again with --expect-root.
  files checked: 75
  root: ce699c8ef1c4b717de1f585ded9eba7b1a03388fc8c388446a49a03c19b57280
This checks the packet's files against that root. It is not a compliance finding.
```

That PASS says the kit agrees with itself. The manifest and `provenance.json` travel in the same
folder as the files they describe, so someone who changed a file could change them too and still
get this result. What closes that gap is a root you received **separately** from the kit — by
email, on a ticket, in a contract — passed with `--expect-root`:

```
python3 verify.py examples/kit/reference_packet --expect-root ce699c8ef1c4b717de1f585ded9eba7b1a03388fc8c388446a49a03c19b57280
```

```
PASS: every file matches the manifest, and the root matches the one you supplied (ce699c8ef1c4b717de1f585ded9eba7b1a03388fc8c388446a49a03c19b57280).
  files checked: 75
  root: ce699c8ef1c4b717de1f585ded9eba7b1a03388fc8c388446a49a03c19b57280
This checks the packet's files against that root. It is not a compliance finding.
```

A supplied root that differs is a FAIL that names both roots in full.

Now change a single byte and run it again:

```
cp -r examples/kit/reference_packet /tmp/tampered
python3 - <<'EOF'
import pathlib
p = pathlib.Path("/tmp/tampered/packet/oversight_report.md")
b = bytearray(p.read_bytes())
b[200] = ord("X")
p.write_bytes(bytes(b))
EOF
python3 verify.py /tmp/tampered
```

```
FAIL: the evidence packet did not verify.
  - content changed: oversight_report.md
  - root does not match the manifest (recomputed 2d6ffb8d2d84cdea7a1e788f5a3da091799337e065be993452402ca7011b41d7, manifest ce699c8ef1c4b717de1f585ded9eba7b1a03388fc8c388446a49a03c19b57280)
  - root does not match provenance.json (recomputed 2d6ffb8d2d84cdea7a1e788f5a3da091799337e065be993452402ca7011b41d7, expected ce699c8ef1c4b717de1f585ded9eba7b1a03388fc8c388446a49a03c19b57280)
```

One byte, in a 22 KB report, inside a 76-file packet. The recomputed root you see will differ from
the one above if you change a different byte; what does not differ is that it stops matching.

### Exit codes

- `0` — PASS.
- `1` — FAIL: the problems are listed, each naming the file or the root concerned.
- `2` — the command line could not be read (an unknown option, or an `--expect-root` that is not a
  64-character hexadecimal root). Nothing was checked.

Add `--json` for a machine-readable result. It carries `ok`, the roots, the `problems`, and
`root_source`: `"kit"` when the root came from the kit, `"supplied"` when it came from
`--expect-root`, which is then repeated as `supplied_root`. Every path printed, in either form, is
relative to the kit folder.

## What is in this repository

- `verify.py` — the standalone verifier. Standard library only, no installation, no network use.
- `LICENSE` — the Apache License, Version 2.0, the grant for everything here.
- `docs/v1/integrity_manifest_spec.md` — how a packet's hash chain and integrity manifest are
  built. This is the document `verify.py` implements; read it to write your own verifier.
- `docs/v1/receipt_spec.md` — the oversight-receipt format: a portable, signed summary of one
  assessment.
- `docs/v1/receipt.schema.json` — the JSON Schema for that format.
- `docs/v1/counterparty_exchange.md` — the envelope format for handing an assessment to another
  organization.
- `docs/v1/counterparty_exchange.schema.json` — the JSON Schema for that envelope.
- `docs/v1/timestamp_anchoring.md` — the anchor formats, for checking a receipt that was
  timestamped.
- `docs/v1/verification.md` — what running the verifier establishes, and what it leaves open.
- `docs/v1/snapshot_contract.md` — the input contract, for writing an independent producer.
- `examples/receipt/` — a committed receipt artifact, as a test vector.
- `examples/counterparty/` — committed exchange envelopes, as test vectors.
- `examples/kit/reference_packet/` — the sample kit used above. It carries its own copy of
  `verify.py` at its root, so either copy may be used; both are the same file.

Every artifact in this repository is synthetic. None of it is customer data.

## What a packet is

An evidence packet is a directory of JSON and Markdown reports produced by one run of the tool.
Beside the reports is an integrity manifest: a SHA-256 hash of every file in the packet, chained in
sorted path order, with the manifest at the packet root excluded from its own chain — only that one
file; a file of the same name anywhere else is chained like any other. Chaining those hashes yields
one root hash, which the manifest records. `verify.py` recomputes the whole chain from the files on
disk and compares the root it gets against the one the manifest recorded, the one in
`provenance.json`, and, with `--expect-root`, the one you supply. A packet with no files to check
is a FAIL, not a PASS over nothing.

The construction is specified in
[docs/v1/integrity_manifest_spec.md](docs/v1/integrity_manifest_spec.md).

## What verification means, and what it does not

The verifier says so itself, on the last line of a PASS:

> This checks the packet's files against that root. It is not a compliance finding.

PASS means every file in the packet matches its manifest and the root the headline names. Without
`--expect-root`, that root came from the kit itself, so PASS means the kit is internally
consistent; with a root you received separately, PASS means the packet is the one that root
describes. `verify.py` does not re-run the tool, so it does not show that the reports follow from
their input. It does not say the human oversight the packet describes was adequate, and it does not
say any legal or regulatory obligation has been met.

## Requirements

Python 3.11 or later, and nothing else. `verify.py` imports only the standard library — `hashlib`,
`json`, `re`, `sys`, `datetime`, `pathlib`, `typing`, and `annotations` from `__future__` — and a
guard in the private repository fails the build if an import of the engine is ever added to it.

## License

Apache License, Version 2.0, for everything in this repository — the verifier, the format
documents, the schemas and the vectors. The engine that produces evidence packets is a separate
product, source-available under the Business Source License 1.1 to licensed users, and it is not
part of this repository.

## Where this comes from

These files are maintained in a private repository and published here from a manifest that names
each one. The copy here is refreshed when the verifier or one of the formats changes.
