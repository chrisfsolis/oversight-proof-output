# Sampling Methodology

> Advisory only. Accountable owners remain the source of truth for auto-approval policy and outcomes. This audit sample supports retrospective human spot-check; it does not certify the whole population, and escapes are a lagging signal. All data is synthetic.

Deterministic stratified **systematic** sampling. Sample size by Cochran's formula with a finite-population correction; z from the standard-normal quantile (stdlib). No RNG: re-running reselects the identical sample.

- Confidence: 0.95
- Target margin: 0.100; achieved margin: 0.179
- Population: 29; target n: 23; achieved n: 15
- Census recommended: no

## Citations

- Cochran, W. G. (1977). Sampling Techniques (3rd ed.). Wiley.
- Wilson, E. B. (1927). Probable inference, the law of succession, and statistical inference. JASA, 22(158), 209-212.
