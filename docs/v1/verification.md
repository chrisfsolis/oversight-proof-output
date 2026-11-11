# Independent verification (`oversight verify` and the kit)

A delivered evidence packet is meant to be checked by someone who did not produce it. There are two
checks, and two tools that run them, offline:

1. **Integrity:** every file matches the packet's integrity manifest. The packet carries a SHA-256
   hash chain over every file; verification recomputes that chain and compares the root. Both
   `oversight verify` and the kit's standalone `verify.py` check this.
2. **Reproducibility:** re-running the tool on the packet's own input envelope reproduces the reports
   byte for byte. Only `oversight verify` checks this, because it needs the tool.

A root compared only with the one recorded inside the packet shows the packet is **internally
consistent**: whoever changed a file could change the manifest too. A root the recipient received
separately — by email, on a ticket, in a contract — is what shows the packet is the one that was
sent. The kit's `verify.py` takes that root with `--expect-root`.

It reuses the existing machinery (`core/integrity.py`, `report/runner.py`) and adds no new hashing
logic. The exact hash-chain construction, canonical serialization, and manifest layout — everything
needed to build an independent verifier from documentation alone — are specified in
[integrity_manifest_spec.md](integrity_manifest_spec.md).

## Verify a packet

```sh
oversight verify out/report
```

It prints one of three headlines:

- `VERIFY PASS: <path>` — integrity passed and the reports were re-derived byte for byte. Exit 0.
- `VERIFY PASS (integrity only): <path> — reproducibility not checked: <reason>` — the hash chain
  passed, but the reports were not re-derived, and the reason says why (no input envelope in the
  packet, another format version, or `--no-rederive`). Exit 3, or exit 0 when you asked for
  integrity only with `--no-rederive`.
- `VERIFY FAIL: <path>` — a check failed. It names the exact first divergence (the file path and
  which field differs). A single changed byte is a `content` divergence on that file; a deleted or
  added file is a `count` divergence. Exit 1.

Exit 2 means the command could not run the check at all (a missing or unreadable packet, or a
usage error).

```sh
oversight verify out/report --json          # machine-readable
oversight verify out/report --no-rederive   # integrity only (skip re-derivation), exit 0 on a pass
```

`--json` prints the full result: `ok` (integrity passed, and reproducibility passed or was not
checked), `integrity`, `reproducibility`, and two summary keys, `reproducibility_checked` (true or
false) and `reproducibility_reason` (why it was not checked, or null). The exit code is the same
with or without `--json`.

### Which packets are re-derived

Reproducibility is promised **for the same packet format version**. Every packet records the
format version that wrote it in `integrity_manifest.json`. When it is this build's, the reports are
re-derived and any differing byte is a FAIL. When it is another version, or none is recorded,
re-derivation is not checked and the reason names both versions: it is never a PASS on bytes this
build did not reproduce, and never a FAIL for bytes another format wrote. From version 1.0.0 the
packet also records the product version, and the promise extends to it.

## Try the committed Trust Gallery

For a buyer-safe packet with no customer data, use the committed synthetic Trust Gallery:

```sh
python scripts/verify_sample_gallery.py
python -m oversight_proof.cli.main verify examples/gallery/reference_packet/packet
```

The gallery metadata names the synthetic source, generated packet, expected manifest, regeneration
command, verification command, data classification, and advisory interpretation summary. To check
that committed outputs still match deterministic regeneration, run:

```sh
python scripts/build_sample_gallery.py --check
```

The gallery docs include the sample report and a plain-language interpretation guide:

- The sample report itself is published, inside the committed verification kit:
  [`examples/kit/reference_packet/packet/oversight_report.md`](../../examples/kit/reference_packet/packet/oversight_report.md).
- `examples/gallery/README.md`, `examples/gallery/reference_packet/metadata.json` and
  `examples/gallery/report_interpretation.md` are part of the licensed engine documentation,
  not published here.

## Export a portable kit

```sh
oversight verify out/report --emit-kit --out out/kit
```

This writes a self-contained folder you can hand to an auditor:

- `packet/` : the delivered reports and the integrity manifest.
- `provenance.json` : the tool version recorded in the packet, the command, the input canonical
  hash, the expected root hash, the `as_of` anchor, and an explicit offline (no network) statement.
- `VERIFY.md` : plain-language re-run instructions.
- `verify.py` : a **standalone, standard-library-only** script. It imports nothing from this project,
  makes no network calls, and runs on a clean Python 3.11 or newer with zero install. This is the
  trust anchor.
- `LICENSE` : the Apache License, Version 2.0, the grant for `verify.py`.

The export refuses, naming the folder and removing nothing, when `--out` would put the kit's
`packet/` folder over, around or inside the packet being exported, or when `--out` already holds a
`packet/` folder that no earlier export wrote. A folder an earlier export wrote is replaced. It
exits 0 when the kit is written and 2 when it refuses.

From the kit folder, the auditor runs:

```sh
python verify.py                              # PASS (internally consistent) / FAIL
python verify.py --expect-root <root>         # PASS only if the packet matches the root you received
python verify.py . --json                     # machine-readable
```

`verify.py` exits 0 on PASS, 1 on FAIL, and 2 when its command line cannot be read (nothing is
checked). Without `--expect-root` its PASS reads "PASS (internally consistent)" and names the root
recorded in the kit; with a matching `--expect-root` it reads "PASS: every file matches the
manifest, and the root matches the one you supplied". A packet with no files to check is a FAIL, and
only the manifest at the packet root is left out of the chain. Every path it prints is relative to
the kit folder.

Emission is deterministic: the same packet yields the same `provenance.json` and the same `verify.py`
(no wall-clock, no randomness; the only time value is the packet's `as_of`).

### Redacting the input

```sh
oversight verify out/report --emit-kit --out out/kit --redact-inputs
```

With `--redact-inputs` the input envelope is withheld from the kit; only its canonical hash is
recorded in `provenance.json`. Integrity stays checkable (the manifest still binds the envelope by
its recorded hash, and `verify.py` says so in its PASS line), but reproducibility cannot be
re-derived without the input. Use this when the source data must not leave the building.

## Why `verify.py` lives outside the package

The standalone `verify.py` is kept in the repo's top-level `kit/` folder, not inside
`src/oversight_proof`, mirroring how the local web app is kept outside the package. The trust anchor
must depend on nothing but the standard library, and the package itself must stay import-clean under
the no-network test. Keeping the standalone code out of the package preserves both.

So that a kit can be exported from an installed copy and from the desktop app, not only from a
source checkout, the package carries a byte-identical copy of `verify.py` and of the Apache-2.0 text
as data (`oversight_proof/verify/kit_assets/`). They are read as bytes and written into the kit; the
copy of `verify.py` is never imported, and a guard holds both copies identical to the originals.

## What it attests, and what it does not

`oversight verify` checks the **integrity** of a packet and, where its format version is this
build's and its input is present, its **reproducibility**: that the reports follow from the recorded
input. The kit's `verify.py` checks integrity only, against the root recorded in the kit or one you
supply. Neither is a legal or regulatory compliance determination, neither judges whether the
underlying human review was adequate, and neither makes a claim about the customer. Those remain
the responsibility of the accountable owner. It is advisory evidence for an accountable human
owner, not legal advice and not a compliance determination. Cryptographic release signing and
third-party attestation workflows are out of scope for v1.

## License
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Oversight Proof LLC. This specification is licensed under the
Apache License, Version 2.0 (see LICENSE-APACHE.txt). You may implement this format
freely, including in commercial and competing products.
