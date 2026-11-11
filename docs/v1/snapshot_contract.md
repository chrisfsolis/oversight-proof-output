# The snapshot envelope — shared input contract

Every Oversight Proof subcommand reads the same point-in-time **snapshot envelope**: one JSON
object describing review items, the people who review them, and (depending on the tool) the
decisions made and the work queued. The six predecessor tools had each grown their own copy of
this schema; v1 has **one canonical definition** (`oversight_proof.core.contract`), modeled on
how the tools actually consume it.

`schema_version` for v1 is `"1.0.0"`.

## Two rules that hold everywhere

- **Anchoring.** `as_of` (an ISO-8601 timestamp with a trailing `Z`) is the **only** time
  anchor. There is no wall-clock `now()` anywhere in the product. Other timestamps
  (`decided_at`, `arrival_ts`) are *data*: they are stored as raw strings and parsed only on
  demand, so a round-trip reproduces them exactly.
- **Tolerance.** Unknown fields are preserved, not dropped. Each record keeps an `extra` bag
  and the envelope keeps a `raw` copy, so a parse → serialize round-trip reproduces your
  input. Tool-specific policy blocks are carried verbatim (see below).

## Top-level envelope

| Field | Type | Notes |
| --- | --- | --- |
| `schema_version` | string | `"1.0.0"` in v1. |
| `as_of` | string | ISO-8601 `Z`. The sole time anchor. |
| `scenario` | string? | Optional label, echoed into the run manifest. |
| `agent_identity` | object? | Optional. One entry per `run_id`, each with `model`, `model_version`, `prompt_sha256`, `toolset_sha256` and an optional `note`. Carried verbatim; the format is defined and enforced on the way in by `core/agent_identity.py`. |
| `input_kind` | string? | Optional. `"decision_log"` (the default when absent) or `"agent_action_log"`. Chooses the nouns the packet uses -- decisions and reviewers, or actions and approvers. No number depends on it. |
| `review_items[]` | list | The timeless, decision-free items (below). |
| `decision_log[]` | list | Reviewer decision events (below). |
| `reviewer_roster[]` | list | The people who review (below). |
| `review_work_items[]` | list | Queued/forecast work units (forecaster). |
| *policy blocks* | objects | Carried verbatim; typed parsers live in `core.policy`. |

The preserved policy blocks are: `oversight_policy`, `article14_mapping`, `similarity`,
`irr_policy`, `drift_policy`, `rubber_stamp_policy`, `calibration_policy`, `inbound_model`,
and `sla_policy`. A handful of tools also read their own companion records and policy blocks
(e.g. `assignments` / `routing_rules` / `escalation_policy` for `audit-routing`;
`dispositions` / `auto_approval_rules` / `bypass_policy` / `sampling_policy` / `escape_policy`
for `audit-sampling`). Those are typed *inside* the owning tool and likewise round-trip
verbatim; each method doc (part of the licensed engine documentation, not published here)
documents the ones it consumes.

### A policy block is layered over the defaults, one key at a time

A policy block you supply does not replace the engine's default block; it is merged over it per
key, and the merge reaches one level inside each key. So a block that states

```json
"oversight_policy": { "in_scope": { "high_risk_use": true } }
```

is read as `{"high_risk_use": true, "ai_assisted": true}`, because `ai_assisted: true` is in the
default `in_scope` and your block did not say otherwise.

**Omitting a flag does not remove it.** This matters most for `in_scope`, which decides what the
coverage metrics have a population over at all: an export whose items are not marked `ai_assisted`
will show an empty in-scope population, and the reading will be a coverage figure over nothing
rather than an error. **State every `in_scope` flag you mean, including the ones you mean to be
false.** Writing `"ai_assisted": false` is how you say a flag does not apply to your population;
leaving it out says nothing and inherits `true`.

The same layering applies to every other key of the block -- `two_person_required`,
`expected_signals`, `fail_threshold` -- so a partial `two_person_required` keeps the default
`min_verifiers` unless you state your own.

## Companion records

### `ReviewItem` — a human-review item (timeless, decision-free)

`item_id` (required), `item_type`, `value_band`, `urgency_band`, `age_band`,
`risk_categories[]`, `ai_assisted`, `high_risk_use`, plus any `extra`. Bands are short ordered
labels (e.g. value `low < medium < high < strategic`). This record carries **no** timestamps
and **no** decisions — that is what keeps it reusable across all six tools.

### `DecisionRecord` — one reviewer decision event

`decision_id`, `item_id`, `reviewer_id`, `outcome`, `decided_at` (all required), then
`decision_latency_minutes`, `edited`, `edit_magnitude`, `override`, `prior_recommendation`,
`verifier_ids[]`, `stop_invoked`. Joins to a `ReviewItem` on `item_id`. The outcome vocabulary
is `approve | reject | request_changes | escalate | stop`; edit magnitude is
`none | minor | major`.

### `Reviewer` — a roster row

`reviewer_id` (required), then `roles[]`, `team`, `competent_for[]`, `active`, and the
forecaster's capacity fields `capacity_minutes_per_day`, `working_days[]`, `throughput_factor`.
IDs and teams are opaque strings; the tools never resolve them against any directory.

### `ReviewWorkItem` — a unit of queued/forecast work (forecaster)

`item_id`, `required_role`, `arrival_ts`, `effort_minutes` (required), then
`sla_target_minutes`, `revenue_at_risk`. Joins to a `ReviewItem` on `item_id`.

## Two constructors, two behaviors (both preserved)

- **Tolerant** (`Snapshot.from_dict`) — `as_of` defaults to `""` and the `decision_log` is
  kept in **input order**; malformed values are tolerated so a downstream `validate` step can
  report them. Used by the forecaster, oversight-evidence, and sampling tools.
- **Strict** (`Snapshot.from_envelope`) — `as_of` is **required**, and the `decision_log` is
  sorted by `(decided_at, decision_id)` for a stable canonical order. Used by the
  consistency tool.

Both are deterministic. Combined with the no-`now()` rule, that is what makes every report a
pure function of `(input, as_of)` — re-running the same snapshot reproduces the same bytes, so
reports are safe to diff, archive, and audit.

## Minimal example (illustrative, synthetic)

```json
{
  "schema_version": "1.0.0",
  "as_of": "2026-01-15T09:00:00Z",
  "scenario": "example",
  "review_items": [
    {"item_id": "IT-001", "item_type": "exception", "value_band": "high",
     "urgency_band": "urgent", "risk_categories": ["pricing_commitment"]}
  ],
  "reviewer_roster": [
    {"reviewer_id": "R-1", "roles": ["finance_pricing_review"], "active": true}
  ]
}
```

Each subcommand reads the subset of records it needs and ignores the rest. See the per-tool
method docs (part of the licensed engine documentation, not published here) for exactly which
records and policy blocks a given subcommand consumes.

## License
SPDX-License-Identifier: Apache-2.0
Copyright (c) 2026 Oversight Proof LLC. This specification is licensed under the
Apache License, Version 2.0 (see LICENSE-APACHE.txt). You may implement this format
freely, including in commercial and competing products.
