# Oversight Proof evidence packet — Consumer lending - loan application review

> Advisory evidence only. This packet compiles deterministic, local audit outputs over synthetic or supplied data. It is not a compliance determination or legal advice; the accountable owner (and, where relevant, qualified counsel) remains the source of truth. Each metric is shown with how completely its source data carried the field it reads.

_As of (input anchor): 2026-05-20T00:00:00Z_

## What this packet shows

20 review items were recorded over Consumer lending - loan application review, as of 2026-05-20.

All 20 review items have at least one recorded decision (100%). 14 of 40 decisions changed the AI's output in some way (35%). 0 of 29 auto-approved items later turned out to need a person.

No governance action is recommended by this packet.

No escalating findings across the audited areas; review the detail before relying.

| Area | Status |
| --- | --- |
| Oversight evidence | Evidence present |
| Reviewer consistency | Informational |
| Auto-approval safety | High attention |
| Evidence integrity | Tamper evident manifest |

## What to do first

Prioritized and owner-assignable; advisory — the owner decides what to act on.

| Priority | Area | Gap | Suggested action | Owner |
| --- | --- | --- | --- | --- |
| P2 | audit-oversight | Decisions below the minimum plausible review time | 2 decisions were made faster than your policy's minimum review time. Ask the reviewers whether those items were simple, or whether the review step is being skipped. | AI governance owner |
| P2 | audit-sampling | Item TF-AUTO-RISK1 bypassed review but should not have | TF-AUTO-RISK1 was auto-approved even though your own rule required a person for it. Have someone review it now, and check why the rule let it through. | Trust & safety owner |

## Human review of each decision

Each row states its value, the evidence status, how completely your data carried the field, and one sentence saying what the records show.

| Metric | Value | Evidence status | Data completeness |
| --- | --- | --- | --- |
| Oversight coverage | 100% | Evidenced | High completeness |
| *All 20 review items have at least one recorded decision (100%).* |  |  |  |
| Override rate | 15% | Evidenced | High completeness |
| *6 of 40 decisions that recorded the override field overrode the AI's recommendation (15%).* |  |  |  |
| Intervention rate | 35% | Evidenced | High completeness |
| *14 of 40 decisions changed the AI's output in some way (35%).* |  |  |  |
| Edit rate | 20% | Evidenced | High completeness |
| *8 of 40 decisions that recorded it were edited by the reviewer (20%).* |  |  |  |
| Stop rate | 5% | Evidenced | High completeness |
| *2 of 40 decisions invoked a stop (5%).* |  |  |  |
| Two-person coverage | 100% | Evidenced | High completeness |
| *All 20 items that required two reviewers got them (100%).* |  |  |  |
| Inter-rater reliability | 0.829 | Evidenced | High completeness |
| *Reviewers who saw the same items agreed on nearly all of them.* |  |  |  |
| Auto-approval escape rate | 0% | Evidenced | High completeness |
| *0 of 29 auto-approved items later turned out to need a person.* |  |  |  |

## What this packet measured against

Every evidence status above is judged against a number. These are those numbers, in the unit the metric is measured in, with who set each one.

| Metric | What it is | Value | Set by | What crossing it means |
| --- | --- | --- | --- | --- |
| Oversight coverage | the share of in-scope decisions your policy expects a person to have reviewed | 100% | your policy | fully evidenced from partially evidenced |
| Oversight coverage | below this share of your decisions reviewed, coverage counts as under floor | 50% | this tool's default | partially evidenced from under floor |
| Two-person coverage | how many people your policy requires on an item in a two-person category | 2 | your policy | items that needed two approvers from items that did not |
| Inter-rater reliability | how many reviewers must both have seen an item before agreement can be measured on it | 2 | your policy | measurable from too sparse to measure |
| Inter-rater reliability | below this, reviewers agree too little for the review to evidence much | 0.4 | this tool's default | partially evidenced from under floor |
| Inter-rater reliability | at or above this, reviewers agree enough to evidence a consistent review | 0.6 | this tool's default | fully evidenced from partially evidenced |
| Auto-approval escape rate | the share of auto-approved items your policy accepts turning out to need a person | 10% | your policy | fully evidenced from partially evidenced |
| Auto-approval escape rate | how many times your maximum the rate may reach before it counts as under floor | 2.0 | this tool's default | partially evidenced from under floor |
| Override rate | below this share, the behavior shows up too rarely to evidence much | 5% | this tool's default | partially evidenced from fully evidenced |
| Edit rate | below this share, the behavior shows up too rarely to evidence much | 5% | this tool's default | partially evidenced from fully evidenced |
| Stop rate | below this share, the behavior shows up too rarely to evidence much | 5% | this tool's default | partially evidenced from fully evidenced |
| Intervention rate | below this share, the behavior shows up too rarely to evidence much | 5% | this tool's default | partially evidenced from fully evidenced |

Every metric in the table above is judged against at least one of these numbers.

**What the evidence statuses mean**

- `evidenced` (Evidenced) — measured on complete records, and the reading is at or above every floor shown here.
- `partially_evidenced` (Partially evidenced) — measured on complete records, and the reading is between the floors shown here.
- `insufficient_evidence` (Insufficient evidence) — measured on complete records, and the reading is below the floor shown here.
- `additional_data_needed` (Additional data needed) — the field was recorded on too few records to read, so no number is given.
- `not_measured_by_this_tool` (Not measured by this tool) — nothing in this packet bears on it; the floor, if any, is someone else's to check.

## What needs attention

- **[audit-oversight] Decisions below the minimum plausible review time** (High attention) — **Next step:** 2 decisions were made faster than your policy's minimum review time. Ask the reviewers whether those items were simple, or whether the review step is being skipped.
  - 2/40 decisions (0.050) were faster than min_decision_latency_minutes=2. Implausibly fast decisions are a weak-evidence SIGNAL that review may be nominal, not proof. Affected: DEC-0001, DEC-0008.
- **[audit-sampling] Item TF-AUTO-RISK1 bypassed review but should not have** (High attention) — **Next step:** TF-AUTO-RISK1 was auto-approved even though your own rule required a person for it. Have someone review it now, and check why the rule let it through.
  - TF-AUTO-RISK1 (content_flag) was auto-approved under AR-payment but: item_type 'content_flag' is not allowed by AR-payment.
  - *Suggested action (from audit-sampling):* Route TF-AUTO-RISK1 for retrospective human review and tighten the bypass policy or rule that let it through.

## Appeal handling, as the supplied records describe it

These are counts over the appeal records you supplied: how many arrived, how many were resolved, how long resolutions took, and how often a rationale was recorded. Four thresholds are read over those counts, and two have to trip before anything is surfaced.

A tripped threshold is a statistical signal about the records supplied, warranting review. It is not evidence that any appeal went unread or unconsidered, and this product holds nothing about the people who appealed. This section is not a compliance determination.

| Appeal records | Count | What this packet has |
| --- | --- | --- |
| Appeals supplied | 8 | Review recommended |
| Resolved | 8 | |
| With a rationale digest | 7 | |
| Distinct rationale digests | 3 | |
| Resolution times read | 8 | |

The resolved appeals reach the number this measure needs, so the signals below were read against their thresholds.

Of the 8 appeals supplied, 8 name a decision this export contains and 0 name one it does not.
2 of the 8 were granted (25%). A grant rate is not a target and a low one is not a finding: it is the outcome this export recorded.
Resolution times, in hours -- minimum 1.0, median 3.5, mean 3186.0, maximum 10245.0. The mean sits above the median when a few appeals took far longer than the rest, which is what the two together are for.

Each signal, and whether it tripped:

- `resolution_times_fast` — threshold reached
- `rationale_digests_repeat` — threshold reached
- `grant_share_low` — below threshold
- `rationale_absent_often` — below threshold

Thresholds read: at least 5 resolved appeals, and 2 of 4 signals, before anything is surfaced.

## Opt-out records, as the supplied log describes them

These are counts over the opt-out records you supplied: how many requests arrived, how many carry a stop recorded against them, and how many CALENDAR DAYS apart the two timestamps are where one was recorded.

The elapsed figures are CALENDAR DAYS. The obligation behind this measure is written in business days, and this product counts no business days and takes no jurisdiction, holiday or timezone setting, so a calendar-day count is a different and stricter measure than the obligation asks for. Nothing here is compared against a day count: there is no deadline, no lateness and no timeliness in this section. A count is a fact about the records supplied and not evidence that any request went unhonored. This section is not a compliance determination.

| Opt-out records | Count | What this packet has |
| --- | --- | --- |
| Requests supplied | 8 | Review recommended |
| With a stop recorded | 3 | |
| With no stop recorded | 5 | |
| Elapsed figures read | 3 | |

The opt-out records reach the number this measure needs, so the unrecorded share below was read against its threshold.

Elapsed CALENDAR DAYS from request to recorded stop — minimum 2, median 5.0, mean 5.333333, maximum 9. A negative figure means the log records a stop before the request it answers.

Thresholds read: at least 5 records, and an unrecorded share of 0.5 or more, before anything is surfaced. No threshold is read over the elapsed figures.

## How this maps to the frameworks you named

### NIST AI RMF (AI RMF 1.0 (NIST AI 100-1))

> NIST AI RMF references and outcomes are public domain (NIST AI 100-1); descriptions are accurate own-words paraphrases. Advisory mapping only, not a compliance determination and not legal advice.

Of 6 obligations: 3 measured by this run, 1 no measurement in this run, 2 outside this tool's reach. The groups after the first are facts about the obligation, the deployment, or this tool's reach -- not shortfalls in this run.

#### Measured by this run

| Obligation | Reference | What it asks (paraphrase) | Evidence | Note |
| --- | --- | --- | --- | --- |
| govern_3_2_oversight_roles | NIST AI RMF GOVERN 3.2 | Define and differentiate the roles and responsibilities for human-AI configurations and oversight of the system. | Evidenced | — |
| measure_2_4_monitor_behavior | NIST AI RMF MEASURE 2.4 | Monitor the functionality and behavior of the system and its components when in production. | Evidenced | — |
| manage_2_4_supersede_disengage | NIST AI RMF MANAGE 2.4 | Put mechanisms in place to supersede, disengage, or deactivate a system whose outcomes are inconsistent with its intended use. | Evidenced | — |

#### No measurement in this run

| Obligation | Reference | What it asks (paraphrase) | Evidence | Note |
| --- | --- | --- | --- | --- |
| govern_3_2_delegated_authority | NIST AI RMF GOVERN 3.2 | Write down which actions the system may take on its own, which need a person, and which it may never take. | No population to measure | TWO ROWS CITE GOVERN 3.2, FROM TWO KINDS OF EVIDENCE, and that is deliberate. The subcategory asks that roles and responsibilities for human-AI configurations be defined and differentiated. `govern_3_2_oversight_roles` reads the metrics: how much was overseen, and whether a second person signed off. This row reads the delegated-authority statement you supplied -- whether the actions in the run match what you said you delegated. Where you supplied no statement, this row reports no measurement rather than a gap, and nothing here assesses whether the delegation you wrote was appropriate. |

#### Outside this tool's reach

| Obligation | Reference | What it asks (paraphrase) | Evidence | Note |
| --- | --- | --- | --- | --- |
| govern_1_4_transparent_controls | NIST AI RMF GOVERN 1.4 | Establish the risk-management process and its outcomes through transparent, traceable controls. | Not measured by this tool | The obligation is to establish a risk-management process. This tool observes nothing about whether one exists: a tamper-evident packet is a traceable record of oversight outcomes, not of the process that governs them. Evidenced by the organization's own risk-management policies, procedures and controls. |
| manage_4_1_post_deployment_monitoring | NIST AI RMF MANAGE 4.1 | Implement post-deployment monitoring, including mechanisms for appeal and override of automated decisions. | Not measured by this tool | The obligation is to implement post-deployment monitoring and mechanisms for appeal and override. Where appeal records are supplied, this tool measures how those recorded appeals were handled; it does not evidence that an appeal or override mechanism exists, and implementing one is an activity the organization performs rather than an artifact this packet holds. Evidenced by the organization's monitoring, appeal and override procedures. |

### EU AI Act (Regulation (EU) 2024/1689)

> Article references are public; descriptions are paraphrased, not the regulation text. Advisory mapping only, not a compliance determination and not legal advice.

Of 9 obligations: 9 measured by this run.

#### Measured by this run

| Obligation | Reference | What it asks (paraphrase) | Evidence | Note |
| --- | --- | --- | --- | --- |
| art_11_technical_documentation | EU AI Act Art. 11 + Annex IV | Show that a dated record of the oversight that ran exists and is complete. | Evidenced | ARTICLE 11 IS THE PROVIDER'S DUTY AND THIS PACKET IS NOT THAT DOCUMENT. The Article requires technical documentation drawn up BEFORE the system is placed on the market, carrying the Annex IV elements. What this row reads is the deployer's side: that a dated, hash-chained record of the oversight that ran exists. A reader who holds an Annex IV obligation needs the provider's documentation as well as this, and the reference is kept because that is where they will look. |
| art_12_record_keeping | EU AI Act Art. 12 | Automatically record events (logs) over the lifetime of the system for traceability. | Evidenced | ARTICLE 12 IS THE PROVIDER'S DUTY: paragraph 1 requires the system to be built so that it technically allows the automatic recording of events. This row reads the integrity of the records the deployer holds, which is the same subject from the other side. The deployer's own duty to KEEP those records is Article 26(6), which has its own row in this table. |
| 14_4_a_understanding | EU AI Act Art. 14(4)(a) | Show that the people assigned to oversee the system monitored how it was operating, rather than taking its output as given. | Evidenced | Article 14(4)(a) is addressed to the PROVIDER: the system must be provided to the deployer so that the persons given oversight are enabled to understand and monitor it. This row reads the deployer's side -- what those persons did with what it produced -- and not whether the provider's enabling was adequate. |
| 14_4_b_automation_bias | EU AI Act Art. 14(4)(b) | Show that those people did not simply go along with the system, by reading where they changed or stopped what it proposed. | Evidenced | Article 14(4)(b) is addressed to the PROVIDER, in the same construction as the rest of 14(4). Automation bias is a state of mind and no record measures it directly; what this row reads is the deployer's side -- whether outputs were changed and intervened in at all, rather than passed through. |
| 14_4_c_interpretation | EU AI Act Art. 14(4)(c) | Show that they read the output closely enough to act on it, by reading the changes they made to what it proposed. | Evidenced | Article 14(4)(c) is addressed to the PROVIDER, which must supply the system so that its output can be correctly interpreted. An edit is evidence that someone engaged with the output; it is not evidence that their interpretation was correct, and no record in this packet speaks to correctness. |
| 14_4_d_override_disregard | EU AI Act Art. 14(4)(d) | Show that they disregarded, overrode or reversed the output where they judged they should. | Evidenced | Article 14(4)(d) is addressed to the PROVIDER: the ability to disregard or override must be provided with the system. This row reads the deployer's side -- that the ability was exercised. A rate of zero is not proof the ability is missing, and a high rate is not proof it is working. |
| 14_4_e_intervene_stop | EU AI Act Art. 14(4)(e) | Show that they stepped in or halted the system where they judged they should. | Evidenced | Article 14(4)(e) is addressed to the PROVIDER, which must supply the stop function or an equivalent procedure. This row reads the deployer's side -- that a stop was invoked -- and says nothing about whether the system comes to a halt in a safe state, which is the part of the sub-point only the provider can evidence. |
| 14_5_two_person | EU AI Act Art. 14(5) | For certain high-risk uses, require confirmation by at least two competent persons. | Evidenced | SCOPED TO ONE ANNEX III CATEGORY, which 'certain high-risk uses' does not say. Article 14(5) applies to the high-risk systems in point 1(a) of Annex III -- remote biometric identification -- and its second subparagraph removes even that where Union or national law treats the requirement as disproportionate for law enforcement, migration, border control or asylum. Outside that category this reading may still be one your own policy asks for, but the Article does not. |
| art_26_6_deployer_keeps_logs | EU AI Act Art. 26(6) | Keep the logs the system generated, under your control and intact, for as long as the use requires. | Evidenced | THE PACKET SPEAKS TO THE RECORDS, NOT TO HOW LONG THEY ARE KEPT. This row reads that the logs behind this run are held and intact as of the snapshot's anchor. Nothing in the packet speaks to the six-month minimum or to any retention period at all: a run is one moment, and retention is a property of your storage over time. Article 26(6) is the deployer's duty, which is why it is a row of its own rather than a note on Article 12. |

### CCPA ADMT (CCPA ADMT regulations (version unsourced))

> Requirements are stated as docs/ccpa_admt_crosswalk.md states them; references are narrative rather than section citations, because that document carries none. Descriptions are own-words paraphrases. Advisory mapping only, not a compliance determination and not legal advice.

Of 5 obligations: 4 measured by this run, 1 outside this tool's reach. The groups after the first are facts about the obligation, the deployment, or this tool's reach -- not shortfalls in this run.

#### Measured by this run

| Obligation | Reference | What it asks (paraphrase) | Evidence | Note |
| --- | --- | --- | --- | --- |
| reviewer_can_interpret_output | CCPA ADMT definition § 7001(e)(1)(A): the reviewer knows how to interpret and use the output | Show that reviewers engage with the output rather than passing it through untouched. | Evidenced | THIS AND THE TWO ROWS BELOW CITE THE DEFINITION, NOT AN EXCEPTION. The three requirements they read -- interpret, review, authority -- are the elements of 'human involvement' in the definition of ADMT at section 7001(e)(1), so they decide whether a use is in this Article's scope at all. The appeal exception at section 7221(b)(1) is a different provision with a different consequence, and these rows do not read it. |
| reviewer_actually_reviews | CCPA ADMT definition § 7001(e)(1)(B): the reviewer reviews and analyzes the output | Show that review happens across the decisions it is claimed for, not selectively. | Evidenced | — |
| reviewer_authority_to_overturn | CCPA ADMT definition § 7001(e)(1)(C): the reviewer has authority to make or change the decision | Show that reviewers can change or stop a decision, and that they do so in practice. | Evidenced | — |
| not_substantially_replacing_humans | CCPA ADMT opt-out trigger: the system replaces or substantially replaces human decision-making | Show the combined picture a reviewer-led process leaves: decisions covered, and overturning and intervention occurring rather than structurally absent. | Evidenced | `escape_rate` IS HERE BECAUSE THE DEFINITION TURNS ON THE UNGATED SIDE. Section 7001(e)(1) defines substantially replacing human decisionmaking as using the output to make a decision WITHOUT human involvement, so what was decided with nobody involved bears on this obligation as directly as what was covered. |

#### Outside this tool's reach

| Obligation | Reference | What it asks (paraphrase) | Evidence | Note |
| --- | --- | --- | --- | --- |
| risk_assessment_human_oversight_part | CCPA ADMT risk assessment for significant-decision uses | Conduct a risk assessment for uses that make significant decisions, of which human oversight is one part rather than the whole. | Not measured by this tool | The obligation is to conduct a risk assessment. This tool produces one input to the human-oversight portion of it, and holding that input is not having conducted the assessment. Evidenced by the completed risk assessment itself. |


## Appendix

Each audit's full report set is in its folder; the whole packet is hashed into a
tamper-evident integrity manifest.

- [`audit-consistency/`](audit-consistency/) — audit-consistency full output
- [`audit-oversight/`](audit-oversight/) — audit-oversight full output
- [`audit-sampling/`](audit-sampling/) — audit-sampling full output
- [`integrity_manifest.json`](integrity_manifest.json) — SHA-256 hash chain over the packet (recompute to verify)
