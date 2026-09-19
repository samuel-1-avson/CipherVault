# ADR-004: Object store engine — redb (D6)

Date: 2026-09-18 · Status: Accepted

## Context

File-per-object degrades on NTFS past ~50K objects (measured
1,300→200 puts/s) and orphans `.tmp` debris per crash-kill.

## Decision

Adopt redb 4.3.0 behind an `ObjectStore` trait, per the D6 spike
(`docs/D6_OBJECT_STORE_SPIKE.md`): 144K batched puts/s, zero crash
debris, MIT/Apache, pure Rust. Migration keeps the existing on-disk
layout readable. RocksDB was not measured (no C++ toolchain on the
spike host); the adapter exists for a Linux rerun if needed.

## Consequences

- +10 s cold build, +1 MiB binary.
- Crash probes 7/7; file baseline retained as the spike harness only.
