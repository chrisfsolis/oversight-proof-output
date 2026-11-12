# Security policy

## Reporting a vulnerability

If you find a security problem in this repository, please report it privately. Do not open a
public issue or pull request.

- Preferred: GitHub's "Report a vulnerability" button on this repository's Security tab.
- Or email: **info@oversightproof.com**

Please include:

- what you found, and which file it affects (`verify.py`, a format document, a schema, or a
  vector);
- the steps to reproduce it, ideally with a small packet or kit that shows it;
- the result you expected and the result you got.

We aim to acknowledge reports and keep you informed while we work on a fix, and to agree a
disclosure date with you before anything is made public. We read every report, but may not reply
individually to duplicates, out-of-scope reports, or automated scanner output. We will credit you
in the fix unless you ask us not to.

There is no bug bounty, and reports are not paid.

## What is in scope

- `verify.py`: anything that makes it report PASS for a packet that does not match its manifest
  or the root you supplied, that makes it read or write outside the kit folder, or that makes it
  crash or hang on a crafted input.
- The v1 format documents and JSON Schemas: anything that lets two different packets produce the
  same root, or lets a conforming verifier be misled.

## What is not in scope

- The examples and vectors in this repository. They are synthetic and contain no real data.
- The licensed OversightProof engine and apps, which are not published here. Reports about them
  are welcome at the same address.
