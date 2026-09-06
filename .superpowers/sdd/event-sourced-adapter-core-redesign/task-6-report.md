# Task 6 report — readiness and encrypted secrets/plugin KV

## Changed files

- `eventstore/contracts.go`: readiness root/manifests, A6 key-source and encryption-root contracts, typed authentication/readiness/key errors, narrow secret/plugin-KV/rotation request and repository contracts. `Store` remains aggregate-only.
- `eventstore/store.go`: explicit `WithKeySource` option; configured stores use the A6 payload codec without changing the Task5 injected codec seam.
- `eventstore/task6.go`: AES-256-GCM encryption with fresh random 96-bit nonces, HKDF-SHA-256 domain separation, length-prefixed AAD, HMAC plugin-key indexing, Unix key-file checks, readiness get/set/validation and root pinning, immutable secret history/resolve APIs, bounded encrypted plugin KV exact/prefix access, and CAS-based encryption-root rotation across secret, plugin, operation-private, artifact, inbox, and outbox ciphertext rows.
- `eventstore/task6_test.go`: focused crypto authentication, secret history/wrong-key, plugin exact/prefix/isolation, readiness pinning, Unix key-file security, and rotation regressions.

## Security boundaries


No key material, ciphertext, plugin logical key/value, or secret plaintext is placed in readiness rows or typed errors. Missing sources, roots, malformed ciphertext, wrong AAD, and authentication failures fail closed. A6 uses separate fixed domains and never reuses nonces. Key-file loading rejects symlinks, non-owner files, non-0600 permissions, invalid lengths, and insecure creation rather than replacing an existing file.

Secret rows preserve `(secret_ref, secret_version)` history and CAS row versions. Plugin KV keeps exact HMAC indexes while encrypting logical keys and values separately; prefix listing decrypts bounded keys in stable key-HMAC order and filters in memory per extension. Rotation re-encrypts ciphertext with the current root and fresh nonces using row-version/key-ID CAS.

## TDD evidence

Focused tests cover AES-GCM round trips and wrong-AAD authentication failure, non-plaintext SQL storage, immutable secret versions and wrong-key failure, plugin extension isolation and prefix listing, readiness index-root pin changes, Unix key-file permission checks, and root rotation preserving secret/plugin readability. Existing Task5 tests remain green.

## Verification

```text
go test -race ./eventstore -run 'TestReadiness|TestKey|TestCrypto|TestSecret|TestPlugin|TestKV|TestRotation|TestA6|TestEncryption' -count=1
ok   Scardice-core/eventstore  1.122s

go test -count=1 ./eventstore
ok   Scardice-core/eventstore  0.731s
```

No formatter, linter, or project-wide suite was run. SQLite was exercised; remote MySQL/PostgreSQL `FOR UPDATE`, Windows ACL/DPAPI behavior, and external KMS integration remain deployment-specific limitations.

## Limitation

The narrow Task6 implementation does not wire runtime startup/provider/API integration. Stable index-root rotation remains unsupported by design; old encryption roots must remain available until all references are rotated.
