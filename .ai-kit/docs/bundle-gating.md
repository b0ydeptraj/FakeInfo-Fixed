# bundle-gating

Round 4 tightens bundle gating so lower bundles do not spray higher-level artifacts by accident.

| Bundle | Contracts emitted | Docs emitted | References emitted |
|---|---|---|---|
| round2 | round2 base only | round2 docs only | support references |
| round3 | round2 base + round3 extras | round2 + round3 docs | support references |
| utility-providers | none by default | utility and topology docs | none |
| discipline-utilities | none by default | discipline docs only | none |
| round4 | round2 base + round3 extras + round4 extras | round2 + round3 + round4 docs | support references |
| baseline | round4 scope + approved discipline utilities | round4 docs | support references |
| baseline-next | compatibility alias for `baseline` during the promotion cycle | round4 docs | support references |

Use temporary output directories when you need to prove gating behavior without contamination from prior generated files.
