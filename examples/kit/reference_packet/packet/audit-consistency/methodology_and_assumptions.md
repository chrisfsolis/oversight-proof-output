# Methodology and Assumptions

> **Advisory — statistical signals, not proof.** This report surfaces statistical signals for an accountable governance owner to weigh. Findings are not conclusive proof of motive or fault. This tool is **not** a performance-management, ranking, or disciplinary instrument; human governance judgment remains the source of truth.

*Statistical signal, not proof. Not an HR or disciplinary instrument.*

_As of (input anchor): 2026-05-20T00:00:00+00:00_

## Estimators and formulas

All statistics are implemented from scratch in the Python standard library, are
fully deterministic, and use closed-form / analytic results only. No random
number generation and no resampling are used anywhere.

**Percent agreement.** Mean over items (rated by >= 2 reviewers) of the
probability that two ratings drawn without replacement agree:
`sum_k n_k(n_k-1) / (r(r-1))`.

**Cohen's kappa** (Cohen, 1960). Two raters:
`kappa = (p_o - p_e) / (1 - p_e)`, with `p_e = sum_k p_{k,a} p_{k,b}`.

**Fleiss' kappa** (Fleiss, 1971). Fixed raters per item; chance agreement from
the pooled category proportions. Unequal rater counts fall back to a defined
sentinel pointing at Krippendorff/Gwet.

**Krippendorff's alpha** (Krippendorff, 2011), nominal level. Built from the
coincidence matrix; tolerates missing ratings:
`alpha = 1 - (n-1) * sum_{c!=k} o_ck / sum_{c!=k} n_c n_k`.

**Gwet's AC1** (Gwet, 2008). Chance agreement
`p_e = 1/(q-1) sum_k pi_k (1 - pi_k)`, robust to the prevalence/kappa paradox.

**Mann-Kendall** (Mann, 1945; Kendall, 1975). `S` statistic with tie-corrected
variance, continuity-corrected `Z`, analytic two-sided p-value from the
standard-normal CDF.

**OLS slope / R^2.** Closed-form simple linear regression.

**Cohort z-score.** Value standardized against the peer mean and sample standard
deviation.

## Interpretation bands (Landis & Koch, 1977)

These are **advisory labels only**: slight `[0.0, 0.2)`, fair `[0.2, 0.4)`,
moderate `[0.4, 0.6)`, substantial `[0.6, 0.8)`, almost_perfect `[0.8, 1.01)`.
Values at or below zero are labeled `poor`.

## Degenerate inputs

Single category, perfect agreement, zero variance, a single window, a single
reviewer, and no overlap each return a defined sentinel with an explanation
rather than raising or fabricating a number.

## Caveats

Small samples make every estimator unstable; base rates distort kappa (hence
AC1 is reported alongside it); exact inter-rater reliability requires reviewer
overlap; four windows cannot reach two-sided significance under Mann-Kendall
even for a perfectly monotone series. Every output here is a statistical signal,
not a determination about any person.
