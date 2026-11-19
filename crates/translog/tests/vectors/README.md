# Vendored test vectors

## `transparency-dev-merkle-proofs.txt`

The inclusion and consistency proof probes of
[transparency-dev/merkle](https://github.com/transparency-dev/merkle),
`testdata/inclusion/**` and `testdata/consistency/**` (196 files), at commit
`75a6539d7b48af0d529236f24487d2814fd1dca7`. The subtree probes in the same
repository are not used, because subtree proofs are not part of RFC 9162.

Copyright Google LLC, licensed under the Apache License, Version 2.0.
The probes are reproduced here unchanged in content and re-encoded as
one line per probe, so they can be read without a JSON parser:

```text
I <name> <leaf index> <tree size> b:<root> b:<leaf hash> [<proof>] ok|err
C <name> <size1> <size2> b:<root1> b:<root2> [<proof>] ok|err
```

* `<name>` is the probe's path under `testdata/`, without `.json`.
* Every `b:` value is the probe's standard base64, possibly empty. A JSON
  `null` became an empty value; Go decodes both to an empty byte slice.
* `<proof>` is a comma-separated list of `b:` values; `[]` is an empty
  proof.
* `ok` / `err` is the probe's `wantErr` field, inverted.
* A missing number field became `0`, its Go zero value. The probe
  `desc` field was dropped; the name carries the same information.

The file's SHA-256 (after normalizing CRLF to LF) is checked by
`probe_file_is_intact` in `tests/vectors.rs`, so any change to it fails
the test suite.

All 196 probes give the expected result except one, on purpose:
`consistency/additional/sizes-are-equal-one-and-proof-is-empty` expects two
equal 12-byte "roots" to verify. The Go reference compares byte strings of
any length; this crate only takes 32-byte hashes, so that input is rejected
before verification. The test pins this as the only such probe and checks
the 32-byte equivalent separately.

## `torchwood-litewitness-mldsa.txt`

The ML-DSA-44 log key and signed checkpoint from
[FiloSottile/torchwood](https://github.com/FiloSottile/torchwood)
`cmd/litewitness/testdata/mldsa.txt` at commit
`1c05157b1fd2dadcd2bfe0ca67f46926bfcd8cb5`: the verifier key passed to
`witnessctl add-key`, a blank line, then the checkpoint note from the
`add-checkpoint` request (an ML-DSA-44 checkpoint cosignature with
timestamp 0, cosigner name = origin). The rest of that test script,
including its SSH test key, is not vendored.

Copyright 2009 The Go Authors and 2023 The Torchwood Authors, BSD-3-Clause.

## `transparency-dev-formats-mldsa.txt`

ML-DSA-44 vectors from
[transparency-dev/formats](https://github.com/transparency-dev/formats)
`note/note_cosigv1_test.go` at commit
`c8fd7e880e82895253fd8918b920ad8660706b0d`, one `-- name --` section each:

* `vkey-key-id`: the "native algMLDSA44 verifier" key (key ID only).
* `private-key`: the published test seed `PRIVATE+KEY+mldsa+6b9c8425+...`
  from `TestCosigV1_KeyHashValidation`. Deriving the public key from the
  seed must reproduce key ID `6b9c8425`, which checks FIPS 204 key
  generation against Go.
* `witness-vkey`, `checkpoint`: `TestMLDSAVerifyTorchwood`, a witness
  cosignature with a non-zero timestamp.
* `subtree-signature`: `TestMLDSAVerifySubtreeTorchwood`, a subtree
  cosignature for `[8, 16)`.

Copyright Google LLC, Apache License 2.0.

Both ML-DSA files are reproduced unchanged in content. Their SHA-256
digests (after normalizing CRLF to LF) are checked by `tests/mldsa.rs`.

## Other vectors

These are small enough to live in `tests/vectors.rs`, each with its source:

* RFC 9162 §2.1.5: the 7-leaf example tree and its proofs.
* transparency-dev/merkle `testonly/constants.go`: leaf inputs, root
  hashes for sizes 0 to 8, complete-subtree hashes and compact-range
  states.
* c2sp.org/signed-note@v1.1.0: the `example.com/foo` verifier key and
  signed note.
* c2sp.org/tlog-checkpoint@v1.1.0 and c2sp.org/tlog-cosignature@v1.1.0:
  the `example.com/behind-the-sofa` checkpoint and cosignature input.
* c2sp.org/tlog-tiles@v1.0.0: the tile index and tree-size examples.
* golang.org/x/mod `sumdb/note/note_test.go` (BSD-3-Clause): the
  `PeterNeumann` and `EnochRoot` keys, the known-answer signature, and the
  `Open` acceptance and rejection cases.
* transparency-dev/formats `note/note_cosigv1_test.go` (Apache-2.0): the
  verifier keys and the cosignature timestamp vector.

No C2SP repository publishes known-answer vectors for `cosignature/v1`
signatures. The cosignature tests therefore check the exact signed message
against the spec's example and use deterministic Ed25519 keys for
sign-and-verify round trips.
