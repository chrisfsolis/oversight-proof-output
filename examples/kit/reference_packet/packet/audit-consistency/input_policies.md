# Input Echo — Policies

> **Advisory — statistical signals, not proof.** This report surfaces statistical signals for an accountable governance owner to weigh. Findings are not conclusive proof of motive or fault. This tool is **not** a performance-management, ranking, or disciplinary instrument; human governance judgment remains the source of truth.

*Statistical signal, not proof. Not an HR or disciplinary instrument.*

_As of (input anchor): 2026-05-20T00:00:00+00:00_

```json
{
  "calibration_policy": {
    "leniency_z_threshold": 2.0,
    "min_decisions": 20
  },
  "drift_policy": {
    "leniency_metric": "approval_rate",
    "num_windows": 6,
    "significance_alpha": 0.05,
    "trend_method": "mann_kendall",
    "window": "by_time",
    "window_size_count": 50,
    "window_size_days": 7
  },
  "fail_threshold": {
    "high_attention_count": 5
  },
  "irr_policy": {
    "category_set": [
      "approve",
      "reject",
      "request_changes",
      "escalate"
    ],
    "interpretation_bands": {
      "almost_perfect": [
        0.8,
        1.01
      ],
      "fair": [
        0.2,
        0.4
      ],
      "moderate": [
        0.4,
        0.6
      ],
      "slight": [
        0.0,
        0.2
      ],
      "substantial": [
        0.6,
        0.8
      ]
    },
    "methods": [
      "percent_agreement",
      "cohen_kappa",
      "fleiss_kappa",
      "krippendorff_alpha",
      "gwet_ac1"
    ],
    "min_overlap": 2
  },
  "rubber_stamp_policy": {
    "approval_rate_high": 0.95,
    "edit_rate_low": 0.05,
    "latency_floor_minutes": 2.0,
    "min_decisions": 20,
    "override_rate_low": 0.02
  },
  "similarity": {
    "group_by": [
      "item_type",
      "value_band",
      "urgency_band",
      "risk_categories"
    ],
    "min_group_size": 5
  }
}
```
