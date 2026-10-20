# Public-data experiment protocol — 2026-10-20

This is a separate public-benchmark protocol, not an exemption from the existing
double-human-annotation protocol for private deployment data. Never call public
testbed data natural traffic from our honeypots. Never insert it into production PG.

## Frozen before model fitting

1. Pin AIT-ADS v1, Zenodo 8263181, verify the publisher's checksums, and retain
   raw files. AIT-ADS is CC BY 4.0. AIT-LDSv2 (5789064) has separate
   CC BY-NC-SA 4.0 terms. Preserve source records, line identities and licenses.
2. Audit the actual label granularity first. ADS labels.csv supplies **attack
   phase intervals**, not causally verified graph edges. Interval-derived labels
   can support only a weak-label feasibility study, not attack-path recall or
   deployable model certification. Prefer publisher event annotations where
   available; do not turn unknown labels into confirmed benign labels.
3. Graph construction and sampling must not consume test labels. Labels remain
   in a separate artifact, outside node/edge features and constraints. Keep
   observed evidence edges; evaluate deletions of candidate association edges
   separately. Do not delete stored raw alerts.
4. Eight named AIT scenarios are the grouping units. Rotate an outer held-out
   test scenario and a distinct validation scenario, training on the remaining
   six. Windows from the same scenario always stay together. Repeated samples
   do not increase the independent sample size. Prefer seed list 42–46 for the
   final grouped comparison. Freeze resource-limited pilot settings separately.
5. Use the current 198-input architecture only. Train from scratch; do not load,
   reshape or pad legacy 128-input weights. Select epochs on validation only;
   never select a seed/fold for deployment because its test results look best.
6. Compare keep-all, the existing evidence rule with the SAME constraints,
   matched-compression random pruning with constraints, and path-constrained
   DQN. Report per-scenario results, scenario-level uncertainty, raw decisions,
   constraint restorations, association-edge compression, retained evidence,
   inference latency, and memory. Distinguish proxy-label metrics from independent
   event/path truth. Report negative results without tuning against test outcomes.
7. External validation on DARPA TC is a separate domain test; first audit its
   official ground truth mapping. Do not claim completion without actual data,
   verified parsing, and results. CAM-LDS supports later LLM evaluation, not a
   replacement for a normal-background pruning benchmark.

## Release gate

An experimental checkpoint is not a production release. A replacement needs a
recorded feature schema, dataset/split/label provenance, trained weight hashes,
successful strict loading, independent retention evaluation, and an acceptable
quality/cost comparison to constrained rules. Weak time-window labels alone do
not pass. Preserve a rollback backup, but serve one active checkpoint only. Do
not change existing services or pretend a rule fallback is a deployed new DQN.

## Feasibility pilot and stopping rule

Before optimization, test whether each edge can legally be removed from the full
graph. If every edge is either direct evidence or necessary for the current
modeled reachability constraints, additional removals cannot create a path:
compression is structurally impossible, independent of model weights. In this
case run only a bounded training/prediction check (seed 42, three epochs; sorted
scenario `fox` held out, `harrison` for validation, the other six for training),
retain its negative result, and stop the expensive full grid. Do not add redundant
edges merely to create a favorable compression number. A changed constraint or
graph design requires a separately documented intervention and fresh evaluation.

Pilot source subset: intranet-server authentication, audit, Apache access/error
records that can be matched exactly to paired LDSv2 lines. ADS alerts outside this
coverage stay unknown, not benign. Features and sampling exclude publisher attack
annotations. Association targets mean that both referenced events have publisher
attack labels; this is an explicitly limited proxy, not causal-link ground truth.

## Post-preflight mechanism diagnosis

After observing the zero-action-space result, run a separately labeled diagnostic
study, not a confirmatory hypothesis test: eight scenario-held-out folds, five
seeds (42–46), at most 12 epochs, validation-only early stopping with patience 5.
Train a current-architecture unconstrained DQN and evaluate its raw decisions,
direct-evidence-only filtered decisions, and full-path-guard filtered decisions.
Apply the corresponding filters to rules; include matched-random and keep-all.
Report event retention (publisher truth), all observed-evidence retention, and
modeled reachability separately. Association-label scores remain proxy metrics.
These are inference-filter ablations of an unconstrained training policy, NOT a
claim to be retrained constrained policies. Original constrained training is
covered only by the bounded pilot. The diagnostic does not authorize relaxing
the production guard, and must not be promoted even if compression improves.

Sources:
- https://github.com/ait-aecid/alert-data-set
- https://doi.org/10.5281/zenodo.8263181
- https://doi.org/10.5281/zenodo.5789064
- https://github.com/darpa-i2o/Transparent-Computing
