# Dependency audit policy

The 30 September 2026 remediation upgraded Ratatui to 0.30.2, which resolves
`lru` 0.18.5. This removes the vulnerable older LRU implementation from the
resolved workspace. Rust 1.89 is the workspace minimum; CI checks that toolchain.

The release also upgrades `rusqlite` from 0.32.1 to 0.40.2 and
`libsqlite3-sys` from 0.30.1 to 0.38.2. The bundled engine is now SQLite 3.53.2,
replacing 3.46.0. SQLite's upstream advisory identifies a rare corruption race
when separate WAL connections write/checkpoint concurrently; the fix first
shipped in 3.51.3, with backports to 3.44.6 and 3.50.7. The new bundled engine
includes that fix. [SQLite WAL-reset advisory](https://www.sqlite.org/wal.html#the_wal_reset_bug).

`fallible_uint` explicitly preserves checked `u64`/`usize` SQL conversions,
which newer Rusqlite versions make optional. Its default prepared-statement
cache remains enabled. Rusqlite 0.40.2 supports Rust 1.88, below the project's
unchanged Rust 1.89 minimum. This uses maintained upstream packages rather than
a local SQLite fork. [Rusqlite release](https://github.com/rusqlite/rusqlite/releases/tag/v0.40.2),
[feature definitions](https://github.com/rusqlite/rusqlite/blob/v0.40.2/Cargo.toml).

SQLite on-disk data is preserved; the upgrade does not replace application
databases or require exporting plaintext. Deployment still requires a verified
backup and an isolated rehearsal before swapping the production image.

CI rejects known vulnerabilities, unsound dependencies, and unmaintained
dependencies, with this single temporary maintenance exception:

| Advisory | Dependency | Reason | Review deadline |
|---|---|---|---|
| [RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436.html) | `paste` 1.0.15 | Linux `if-watch` 3.2.2 / `netlink-packet-core` 0.8.2 in libp2p still require this compile-time procedural macro. The advisory describes abandonment, with no patched release, rather than a reported exploitable vulnerability. | 31 December 2026 |

This is an unresolved dependency-maintenance risk, not a claim that the dependency
is fixed. The exception is limited to that advisory ID; it does not suppress any
future vulnerability advisory for the package. CI refuses to continue after the
deadline until the dependency is replaced or the exception is explicitly reviewed.
Do not force the newer incompatible netlink major version into the graph without
testing Linux network discovery and interface monitoring.

Reproduce the enforced audit:

```sh
cargo audit --deny unsound --deny unmaintained --ignore RUSTSEC-2024-0436
```

Run without the exception to see the outstanding maintenance warning:

```sh
cargo audit --deny unsound --deny unmaintained
cargo tree --target all -i paste
```

The last local audit used the RustSec database updated on 29 September 2026.
An audit is a point-in-time check; release CI must refresh the database.
