# Phase 2 Runtime ABI — Task 2 Report

## Status

Implemented and froze the v1 native runtime C ABI contract, documentation, and minimal C/C++ layout fixtures. No loader, fake runtime, QuickJS implementation, or Go adapter was added. The pre-existing `Scardice-ui` submodule modification and untracked `plan.md` were left untouched.

## TDD red-green evidence

The C and C++ compile/layout fixtures were written before the public header. The required red checks failed because the header did not exist:

```text
gcc -std=c11 -Iruntimeabi/include -c runtimeabi/tests/layout.c -o /tmp/scardice-runtimeabi-layout.o
runtimeabi/tests/layout.c:4:10: fatal error: scardice_runtime_v1.h：没有那个文件或目录
compilation terminated.
```

```text
clang++ -std=c++17 -Iruntimeabi/include -c runtimeabi/tests/layout.cc -o /tmp/scardice-runtimeabi-layout-cxx.o
runtimeabi/tests/layout.cc:5:10: fatal error: 'scardice_runtime_v1.h' file not found
1 error generated.
```

These were the expected missing-header failures, before implementation.

After adding the header and documentation, all focused layout/compile checks passed (exit code 0, no diagnostics):

```text
gcc -std=c11 -Wall -Wextra -Werror -Iruntimeabi/include \
  -c runtimeabi/tests/layout.c -o /tmp/scardice-runtimeabi-layout.o
# no output

clang -std=c11 -Wall -Wextra -Werror -Iruntimeabi/include \
  -c runtimeabi/tests/layout.c -o /tmp/scardice-runtimeabi-layout-clang.o
# no output

g++ -std=c++17 -Wall -Wextra -Werror -Iruntimeabi/include \
  -c runtimeabi/tests/layout.cc -o /tmp/scardice-runtimeabi-layout-gxx.o
# no output

clang++ -std=c++17 -Wall -Wextra -Werror -Iruntimeabi/include \
  -c runtimeabi/tests/layout.cc -o /tmp/scardice-runtimeabi-layout-cxx.o
# no output
```

The fixtures assert fixed sizes/offsets for `sc_string_view`, descriptor, create-info, query, plugin, runtime API prefixes/order, Host API prefixes/order, and capability bit positions. They also compile the exact exported query function signature in both languages. No formatter, linter, or project-wide test suite was run.

## Changed files

- `runtimeabi/include/scardice_runtime_v1.h` — fixed-width types, status/capability macros, append-only v1 structs, ordered runtime/host function tables, portable export/calling-convention macros, and `scardice_runtime_query_v1`.
- `runtimeabi/README.md` — scope, frozen status, focused verification, and design rules.
- `runtimeabi/ABI.md` — normative field/order, ownership, borrowed lifetimes, caller-buffer protocol, threading, reentrancy, negotiation, statuses, value/host callback lifetime, no-unload, trust boundary, and four version domains.
- `runtimeabi/CHANGELOG.md` — v1.0.0 freeze and compatibility constraints.
- `runtimeabi/tests/layout.c` — C11 compile/layout smoke fixture.
- `runtimeabi/tests/layout.cc` — C++17 compile/layout smoke fixture.

## Commit IDs

- `7a044d26` — `feat(runtimeabi): freeze v1 C ABI`
- The report is committed in the follow-up `docs(runtimeabi): record phase 2 evidence` commit.

## Concerns

- The ABI header intentionally defines contracts only; runtime behavior such as scheduling, callback registries, and loader policy remains for later phases.
- `sc_runtime_create_info_v1` contains only `struct_size` and `options_json`; natural alignment supplies the required padding without adding an extra reserved ABI field.
- The focused fixtures compile without linking a plugin because the query symbol is supplied by a future native runtime library.
