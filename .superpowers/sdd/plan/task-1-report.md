# Phase 1 Provider Registry — Task 1 Report

## Status

Implemented the engine-neutral provider registry layer and explicit builtin Goja provider under `utils/jsengine/`. Existing Dice execution paths, QuickJS adapter, and unrelated user worktree changes were not modified.

## TDD red-green evidence

### RED

Tests were added before the production registry/provider implementation. The first focused command was:

```text
go test ./utils/jsengine/...
```

It failed because the new builtin provider package had no non-test production files yet:

```text
Scardice-core/utils/jsengine/builtin/goja: no non-test Go files in /home/lyjjl/Scardice-core/utils/jsengine/builtin/goja
FAIL	Scardice-core/utils/jsengine [build failed]
FAIL	Scardice-core/utils/jsengine/builtin/goja [build failed]
ok  	Scardice-core/utils/jsengine/goja	(cached)
ok  	Scardice-core/utils/jsengine/quickjs	(cached)
FAIL
```

This was the expected missing-functionality failure for the tests importing the new provider and registry APIs.

### GREEN

After the minimal contracts, registry, normalization, and Goja provider were implemented:

```text
go test ./utils/jsengine -run 'TestRegistry|TestNormalizeEngineID' -count=1 && go test ./utils/jsengine/builtin/goja -run 'TestProvider' -count=1
```

Output:

```text
ok  	Scardice-core/utils/jsengine	0.003s
ok  	Scardice-core/utils/jsengine/builtin/goja	0.003s
```

Required package-level verification:

```text
go test ./utils/jsengine/...
```

Output:

```text
ok  	Scardice-core/utils/jsengine	0.021s
ok  	Scardice-core/utils/jsengine/builtin/goja	(cached)
ok  	Scardice-core/utils/jsengine/goja	(cached)
ok  	Scardice-core/utils/jsengine/quickjs	(cached)
```

No formatter, linter, or project-wide test suite was run.

## Changed files

- `utils/jsengine/engine.go` — added deterministic trim/lowercase `NormalizeEngineID`; retained legacy `EngineQuickJS` and `ParseEngineID` compatibility.
- `utils/jsengine/provider.go` — added engine-neutral `Provider` and `RuntimeOptions` contracts.
- `utils/jsengine/descriptor.go` — added descriptor and discovery-only runtime manifest metadata.
- `utils/jsengine/registry.go` — added explicit registration, duplicate rejection, default Goja resolution, provider-not-found diagnostics, stable descriptor snapshots, and descriptor lookup.
- `utils/jsengine/capability.go` — added engine-neutral capability bitset and capability helpers.
- `utils/jsengine/entry.go` — added engine-neutral entry kind constants and source entry shape.
- `utils/jsengine/builtin/goja/provider.go` — added explicit `goja.Provider()` registration and opened the existing Goja adapter.
- `utils/jsengine/registry_test.go` — covered normalization, default resolution, unknown IDs, duplicate builtin/candidate conflicts, stable snapshots, lookup, and lazy candidates.
- `utils/jsengine/builtin/goja/provider_test.go` — covered builtin descriptor metadata and adapter-backed open/evaluation behavior.

## Commit IDs

- `60e89cf7` — `feat(jsengine): add provider registry`
- This report is added in the follow-up report commit.

## Concerns

- Candidate manifests intentionally retain discovery metadata only. Since native loading is out of scope for Phase 1, resolving a registered candidate returns an `ErrProviderNotFound`-wrapped diagnostic stating that the candidate is not loadable yet.
- `Loop` and the legacy QuickJS implementation remain unchanged for compatibility and for later cutover work.
- The user-modified `Scardice-ui` submodule and untracked `plan.md` remain untouched.
