# Task 6 report — readiness and encrypted secrets/plugin KV

## Changed files

- `eventstore/contracts.go`: readiness root/manifests, explicit A6 key-source/encryption-root contracts, typed authentication/readiness/key errors, and narrow secret/plugin-KV/rotation repository contracts. `Store` remains aggregate-only.
- `eventstore/database.go`: remote databases require an explicit external key source and carry it to stores; optional configured database identity is validated at readiness.
- `eventstore/schema.go`: plugin ciphertext columns include the AES-GCM authentication tag overhead at the documented plaintext maxima.
- `eventstore/store.go` and `eventstore/task5.go`: A6 key-source precedence, bound payload codec methods, and authentication checks for supplied operation, inbox, outbox, artifact, secret, and plugin ciphertext.
- `eventstore/task6.go`: AES-256-GCM encryption with fresh random 96-bit nonces, HKDF-SHA-256 domain separation, length-prefixed row-bound AAD, HMAC plugin-key indexing, owner/mode/no-follow Unix key-file checks with explicit current-root metadata, readiness get/set/validation and root pinning, immutable secret history/resolve APIs, bounded encrypted plugin KV exact/prefix access, and CAS-based encryption-root rotation across secret, plugin, operation-private, artifact, inbox, and outbox ciphertext rows.
- `eventstore/task6_test.go`: focused crypto authentication/vector, secret history/wrong-key, direct UoW auth, plugin exact/prefix/isolation/max bounds, readiness pinning/non-empty rejection, remote source requirement, Unix current-root/security, artifact AAD binding, and rotation regressions.

## Security boundaries
No key material, ciphertext, plugin logical key/value, or secret plaintext is placed in readiness rows or typed errors. Missing sources, roots, malformed ciphertext, wrong AAD, and authentication failures fail closed. A6 uses separate fixed domains, fresh nonces, and row-bound identity/version/key-ID AAD. Key-file loading rejects symlinks/TOCTOU, non-owner files, non-regular files, non-0600 permissions, invalid lengths, and insecure creation rather than replacing an existing file.

Readiness validates mode, schema version, database identity when configured, index-root pin, manifest digest sizes, import completion/terminal positions, empty-versus-non-empty database state, and every referenced encryption root. A changed index-root ID or missing referenced encryption root returns quarantine/key-source errors rather than silently reinitializing. Fresh/import downgrade is rejected.

Secret rows preserve `(secret_ref, secret_version)` history and CAS row versions. Plugin KV keeps exact HMAC indexes while encrypting logical keys and values separately; prefix listing decrypts bounded keys in stable key-HMAC order and filters in memory per extension. Per-extension key/value/scan/result/response/aggregate limits and typed CAS conflicts are enforced. Rotation uses one captured root snapshot for every row and refreshes readiness root references after CAS updates.


## TDD evidence
Focused tests cover AES-GCM round trips and wrong-AAD authentication failure, an independently computed HMAC vector, non-plaintext SQL storage, immutable secret versions and wrong-key failure, direct wrong-key UoW rejection, plugin extension isolation/prefix listing/max ciphertext bounds, readiness index-root pin and non-empty rejection, remote key-source requirement, Unix key-file current-root/security checks, row-bound artifact swap rejection, and root rotation preserving secret/plugin readability. Existing Task5 tests remain green.

## Verification

```text
go test -race ./eventstore -run 'TestReadiness|TestKey|TestCrypto|TestSecret|TestPlugin|TestKV|TestRotation|TestA6|TestEncryption' -count=1
ok   Scardice-core/eventstore

go test -count=1 ./eventstore
ok   Scardice-core/eventstore
```

No formatter, linter, or project-wide suite was run. SQLite was exercised; remote MySQL/PostgreSQL `FOR UPDATE`, Windows ACL/DPAPI behavior, and external KMS integration remain deployment-specific limitations.

## Limitation

The narrow Task6 implementation does not wire runtime startup/provider/API integration. Stable index-root rotation remains unsupported by design; old encryption roots must remain available until all references are rotated.
