# Task 5 report — !cgo fallback

## Scope

Completed Phase 5's no-CGO native-runtime fallback. Native manifest discovery and candidate metadata registration remain available without cgo; an explicit native load/open attempt now fails with `ErrNativeRuntimeUnsupported` and never returns a provider or falls back to Goja. Missing library attempts retain both the specific `ErrMissingLibrary` category and the no-cgo unsupported sentinel. The ABI header, fake runtime fixture, Dice, QuickJS, HostBridge, `Scardice-ui`, and user `plan.md` were not modified.

## TDD red

Added `utils/jsengine/native/native_nocgo_test.go` before changing the fallback. The old fallback had no `ErrNativeRuntimeUnsupported` sentinel, so the requested no-cgo behavior test failed at compilation:

```text
CGO_ENABLED=0 go test ./utils/jsengine/native -run 'TestNoCgo' -count=1

# Scardice-core/utils/jsengine/native [Scardice-core/utils/jsengine/native.test]
utils/jsengine/native/native_nocgo_test.go:26:21: undefined: ErrNativeRuntimeUnsupported
utils/jsengine/native/native_nocgo_test.go:35:21: undefined: ErrNativeRuntimeUnsupported
utils/jsengine/native/native_nocgo_test.go:49:21: undefined: ErrNativeRuntimeUnsupported
FAIL	Scardice-core/utils/jsengine/native [build failed]
FAIL
```

## TDD green

After adding the exported sentinel, wrapping it from the no-cgo load/open path, and preserving `ErrMissingLibrary` for absent files:

```text
CGO_ENABLED=0 go test ./utils/jsengine/native -run 'TestNoCgo' -count=1
ok  	Scardice-core/utils/jsengine/native	0.002s
```

Complete focused native package under no cgo:

```text
CGO_ENABLED=0 go test ./utils/jsengine/native -count=1
ok  	Scardice-core/utils/jsengine/native	0.002s
```

Cgo implementation compatibility check:

```text
CGO_ENABLED=1 go test ./utils/jsengine/native -count=1
ok  	Scardice-core/utils/jsengine/native	0.003s
```

The focused no-cgo tests cover: an existing native library path being rejected by both `Candidate.Load` and `Provider.Open`, no provider/loop being returned, and a missing path retaining both `ErrMissingLibrary` and `ErrNativeRuntimeUnsupported`. Existing manifest discovery tests continue to pass without cgo.

## Required full-suite command

The required command was run exactly:

```text
CGO_ENABLED=0 go test ./...
```

It did not complete successfully because unrelated pre-existing no-cgo integrations are not buildable under the task's explicit QuickJS/Dice constraints. Full output:

```text
# github.com/buke/quickjs-go
../go/pkg/mod/github.com/buke/quickjs-go@v0.7.7/marshal.go:27:17: undefined: Context
../go/pkg/mod/github.com/buke/quickjs-go@v0.7.7/marshal.go:27:28: undefined: Value
../go/pkg/mod/github.com/buke/quickjs-go@v0.7.7/marshal.go:32:19: undefined: Context
../go/pkg/mod/github.com/buke/quickjs-go@v0.7.7/marshal.go:32:33: undefined: Value
../go/pkg/mod/github.com/buke/quickjs-go@v0.7.7/value_spec.go:16:19: undefined: Context
../go/pkg/mod/github.com/buke/quickjs-go@v0.7.7/value_spec.go:16:30: undefined: Value
../go/pkg/mod/github.com/buke/quickjs-go@v0.7.7/class_reflect.go:60:12: undefined: Context
../go/pkg/mod/github.com/buke/quickjs-go@v0.7.7/class_reflect.go:60:12: too many errors
FAIL	Scardice-core [build failed]
FAIL	Scardice-core/api [build failed]
FAIL	Scardice-core/dice [build failed]
ok  	Scardice-core/dice/censor	0.027s
ok  	Scardice-core/dice/docengine	0.020s
?    	Scardice-core/dice/events	[no test files]
ok  	Scardice-core/dice/imsdk/onebot	0.015s
?    	Scardice-core/dice/imsdk/onebot/schema	[no test files]
?    	Scardice-core/dice/imsdk/onebot/types	[no test files]
ok  	Scardice-core/dice/sealpack	0.015s
panic: sql: Register called twice for driver sqlite3

goroutine 1 [running]:
database/sql.Register({0xe55cdb, 0x7}, {0x1a6fc90, 0x1b5eb40})
	/usr/lib/go/src/database/sql/sql.go:61 +0x128
github.com/ncruces/go-sqlite3/driver.init.0()
	/home/lyjjl/go/pkg/mod/github.com/ncruces/go-sqlite3@v0.32.0/driver/driver.go:123 +0x34
FAIL	Scardice-core/dice/service	0.034s
ok  	Scardice-core/dice/storylog	0.026s
?    	Scardice-core/icon	[no test files]
ok  	Scardice-core/logger	0.007s
ok  	Scardice-core/message	0.012s
FAIL	Scardice-core/migrate [build failed]
FAIL	Scardice-core/migrate/v2 [build failed]
?    	Scardice-core/migrate/v2/v120	[no test files]
FAIL	Scardice-core/migrate/v2/v131 [build failed]
?    	Scardice-core/migrate/v2/v141	[no test files]
?    	Scardice-core/migrate/v2/v144	[no test files]
FAIL	Scardice-core/migrate/v2/v150 [build failed]
?    	Scardice-core/migrate/v2/v151	[no test files]
ok  	Scardice-core/migrate/v2/v160	0.038s
FAIL	Scardice-core/migrate/v2/v161 [build failed]
?    	Scardice-core/migrate/v2/v162	[no test files]
FAIL	Scardice-core/migrate/v2/v2test [build failed]
?    	Scardice-core/model	[no test files]
?    	Scardice-core/scripts/randomness	[no test files]
?    	Scardice-core/signature	[no test files]
?    	Scardice-core/signature/gen	[no test files]
?    	Scardice-core/static	[no test files]
?    	Scardice-core/static/gen	[no test files]
ok  	Scardice-core/utils	0.012s
?    	Scardice-core/utils/constant	[no test files]
?    	Scardice-core/utils/crypto	[no test files]
?    	Scardice-core/utils/dboperator	[no test files]
?    	Scardice-core/utils/dboperator/dbutil	[no test files]
?    	Scardice-core/utils/dboperator/engine	[no test files]
ok  	Scardice-core/utils/dboperator/engine/pgsql	0.006s
ok  	Scardice-core/utils/dboperator/engine/sqlite	0.036s
ok  	Scardice-core/utils/dboperator/schema	0.041s
FAIL	Scardice-core/utils/jsengine [build failed]
ok  	Scardice-core/utils/jsengine/builtin/goja	0.029s
ok  	Scardice-core/utils/jsengine/goja	0.024s
ok  	Scardice-core/utils/jsengine/native	0.017s
FAIL	Scardice-core/utils/jsengine/quickjs [build failed]
?    	Scardice-core/utils/oschecker	[no test files]
?    	Scardice-core/utils/panicHandler	[no test files]
?    	Scardice-core/utils/paniclog	[no test files]
?    	Scardice-core/utils/plugin/abort	[no test files]
ok  	Scardice-core/utils/plugin/crypto	0.196s
ok  	Scardice-core/utils/plugin/httpextra	0.108s
?    	Scardice-core/utils/plugin/structuredclone	[no test files]
ok  	Scardice-core/utils/plugin/websocket	0.050s
?    	Scardice-core/utils/procs	[no test files]
?    	Scardice-core/utils/public_dice	[no test files]
ok  	Scardice-core/utils/random	0.036s
?    	Scardice-core/utils/satori	[no test files]
?    	Scardice-core/utils/spinner	[no test files]
?    	Scardice-core/utils/throttle	0.012s
ok  	Scardice-core/utils/upgrader	0.017s
ok  	Scardice-core/utils/upgrader/store	0.017s
FAIL
```

## Findings and attribution

- `utils/jsengine/quickjs/runtime.go` and `host.go` have no `!cgo` fallback and import `github.com/buke/quickjs-go`; the dependency's cgo-disabled files omit `Context`/`Value`, causing the reported compile failures. The brief explicitly forbids changing QuickJS, so this is left for a separate QuickJS no-cgo cutover.
- `dice/service` panics during package initialization because its no-cgo test path imports `github.com/ncruces/go-sqlite3/embed`, while another imported sqlite driver registers the same `sqlite3` name. This is outside the native fallback scope and changing Dice/SQLite would violate the task constraints.
- Core Goja implementation packages and the native package itself pass under `CGO_ENABLED=0`; no native candidate is silently converted to Goja.

## Changed files

- `utils/jsengine/native/errors.go`: exported `ErrNativeRuntimeUnsupported` sentinel.
- `utils/jsengine/native/loader.go`: no-cgo diagnostic wrapper now uses the new sentinel.
- `utils/jsengine/native/native_nocgo.go`: missing paths wrap both the specific missing-library error and unsupported-runtime sentinel.
- `utils/jsengine/native/native_nocgo_test.go`: no-cgo load/open and missing-library behavior tests, written first for the red run.
- `utils/jsengine/native/loader_test.go`: skip the cgo-only missing-query-symbol assertion when the no-cgo fallback is selected.
- `.superpowers/sdd/plan/task-5-report.md`: this report.

## Commits

- Baseline: `4d13cf1ba5fc1760c73d481ab69b66dff34bee3c`.
- Task 5 implementation and focused tests: `8cf623fb` (`fix(jsengine): make no-cgo native fallback explicit`).

## Concerns

The mandated full `CGO_ENABLED=0 go test ./...` remains red for the unrelated legacy QuickJS/cgo dependency and duplicate sqlite driver registration described above. The native no-cgo package and Goja-specific packages are green, and the fallback has no usable provider or silent Goja fallback. No formatter or linter was run.
