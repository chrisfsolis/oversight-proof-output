# What-If Recommendations

> Advisory only. Accountable owners remain the source of truth for auto-approval policy and outcomes. This audit sample supports retrospective human spot-check; it does not certify the whole population, and escapes are a lagging signal. All data is synthetic.

| lever | target | escapes prevented | risky removed |
| --- | --- | --- | --- |
| remove_risky_bypasses | bypass_policy.ineligible_if | 0 | 1 |

- **remove_risky_bypasses → bypass_policy.ineligible_if**: 1 auto-approved items were policy-ineligible; stop auto-approving them so they go to human review.
