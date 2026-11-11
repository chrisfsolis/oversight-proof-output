# Verify this evidence packet

This kit lets you check, offline and with only a stock Python interpreter (3.11 or newer), that the
files of the enclosed evidence packet match its integrity manifest and a root hash. It does not
re-run the tool. A root you received separately from this kit is what lets a PASS say the packet is
the one that was sent.

## What you need
Python 3.11 or newer. No third-party packages, and no network connection.

## Run it
From this folder:

    python verify.py

If the sender gave you the root hash separately (by email, on a ticket, in a contract), check
against it:

    python verify.py --expect-root <root you received>

Or point it at this folder explicitly, and add --json for machine-readable output:

    python verify.py <path-to-this-kit> --json

The command exits 0 on PASS, 1 on FAIL, and 2 when the command line itself is wrong.

## What PASS means
verify.py recomputed a SHA-256 hash chain over every file in packet/ (sorted by path, excluding only
the manifest at the packet root) and the root matched the manifest's stored root and the expected
root in provenance.json. A single changed byte, a deleted file, an added file, or an empty packet
would each produce a FAIL that names the problem.

Without --expect-root, PASS says the kit is internally consistent: the manifest and provenance.json
travel in this kit, so someone who changed a file could change them too. With --expect-root and a
root you received separately, PASS says the packet matches that root.

Expected root hash: ce699c8ef1c4b717de1f585ded9eba7b1a03388fc8c388446a49a03c19b57280
Files covered: 75

## What this does and does not check
It checks the packet's files against the manifest and a root hash. It does not re-run the tool, so
it does not show that the reports follow from the recorded input; `oversight verify` does that
where the tool is installed. It is not a legal or regulatory compliance determination, and it does
not judge whether the underlying human review was adequate. Those remain the responsibility of the
accountable owner.

## License
verify.py is licensed under the Apache License, Version 2.0 (the full text is the LICENSE file in
this kit). You may run, copy, and redistribute it freely, including to verify this packet
independently or to hand it to someone else to do the same.

## Files in this kit
- packet/ : the delivered reports and the integrity manifest.
- provenance.json : the tool version recorded in the packet, the command, the input canonical hash,
  the expected root hash, the as_of anchor, and the offline attestation.
- verify.py : this standalone checker; it imports nothing beyond the Python standard library, and is
  licensed under the Apache License, Version 2.0 (see LICENSE).
- LICENSE : the Apache License, Version 2.0, the license grant for verify.py.
