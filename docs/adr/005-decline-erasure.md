# ADR-005: Decline erasure coding for the 3-operator fleet (D7)

Date: 2026-09-18 · Status: Accepted

## Context

Erasure coding could cut the 3x replication overhead. The D7 spike
(`docs/D7_ERASURE_SPIKE.md`) measured reed-solomon-simd 3.1.0 at
(2,1)/(3,1)/(4,2)/(8,4)/(10,4) × 4 KiB/64 KiB/1 MiB.

## Decision

DECLINE. The codec runs GB/s, but placement counting proves no (k, m)
matches 3x durability below 3x overhead on 3 homes, and fragment
repair costs k× reads (measured 2x/4x/10x) versus replication's 1x —
failing the "without complicating repair" gate.

## Consequences

- Default stays 3x full replication.
- Revisit only with ≥5 placement homes + a large-blob tier +
  placement-aware repair.
