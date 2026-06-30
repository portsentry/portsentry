## Context

PortSentry already fuzzes its packet-parsing path with two libFuzzer targets (`fuzz_sentry_pcap`, `fuzz_sentry_stealth`). The established pattern is:

- The harness lives **inside the production `.c` file**, guarded by a per-target macro (`#ifdef FUZZ_SENTRY_PCAP_PREP_PACKET`). This gives the harness access to `static` functions without changing their linkage.
- `CMakeLists.txt` adds one `add_executable` per target under `if (BUILD_FUZZER ... Clang ... Debug)`, compiles the single `.c` with `-DFUZZ_<NAME>` and `-fsanitize=fuzzer[,address]`, and links `lportsentry`.
- The harness defines any globals the linked library expects (e.g. `uint8_t g_isRunning = TRUE;`).
- `build.sh build_fuzz` / `run_fuzz` glob `fuzz_*`, so new targets are picked up with no script changes.
- Seed corpora live in `tests/fuzzing/corpus_<target>/`.

This change adds four targets following the same pattern, against text/argument parsers rather than packet parsers. The new wrinkle is that these parsers touch **global state** and **process-terminating / file-system paths** that the packet parsers do not.

## Goals / Non-Goals

**Goals:**
- Add libFuzzer targets for the config-file parser, ignore-file line parser, command-line parser, and the `SubstString` utility.
- Reuse the existing in-file-macro harness pattern and build/run tooling verbatim — no new abstractions.
- Each target runs many iterations without state leakage, without spurious `exit()`, and without touching the real filesystem or network.
- Seed each target with a small valid corpus.

**Non-Goals:**
- Refactoring parsers into pure buffer-in/struct-out functions (tempting, but a larger behavioral change — kept out of scope; harnesses adapt to current signatures).
- Fuzzing utilities already covered by unit tests (`GetLong`, `StrToUint16_t`, `SafeStrncpy`, `CreateDateTime`, `ReallocAndAppend`, substring helpers) — no redundant targets.
- Wiring fuzzers into CI (history shows fuzzing was deliberately removed from CI in #140; this change keeps them developer-run only).
- Differential/oracle fuzzing or structure-aware custom mutators.

## Decisions

### Decision 1: Keep harnesses in-file behind `-DFUZZ_*` macros
Consistent with `sentry_pcap.c`/`sentry_stealth.c`, and the only way to reach the `static` parsing functions (`SetConfiguration`, `ParsePortsList`, `IgnoreParse`, the tokenizer helpers) without changing their linkage or moving them to headers.
**Alternative considered:** Separate `tests/fuzzing/fuzz_*.c` files calling exported functions. Rejected: would force de-`static`-ing internals or duplicating them, a larger and riskier diff than the macro pattern already in use.

### Decision 2: Choose the parsing entry point per target

```
target              entry point                          notes
──────────────────  ───────────────────────────────────  ─────────────────────────────────
fuzz_configfile     SetConfiguration() / ParsePortsList   bypass fopen; feed bytes as the
                    (+ tokenizer helpers)                  key/value/line content directly
fuzz_ignore         IgnoreParse(char *buf, IgnoreIp *)     line parser; already static, takes
                                                           a NUL-terminated buffer — ideal
fuzz_cmdline        ParseCmdline(argc, argv)               split Data on NUL into argv tokens
fuzz_subststring    SubstString(find, replace, src, dst,   fixed dst buffer; carve tokens from
                    dstSize)                               Data, assert no write past dstSize
```

- **Config:** `ReadConfigFile` opens `configData.configFile` via `fopen`. Rather than write a temp file each iteration (slow, filesystem-dependent), the harness drives the line-level parser core directly with fuzzer bytes, mirroring how `ReadConfigFile` would call it per line. The exact split point (`SetConfiguration` vs. a small new `#ifdef`-guarded helper that runs the read-loop body over an in-memory buffer) is the one open question below.
- **Ignore:** `IgnoreParse` already takes a `char *buffer` + output struct and `memset`s the struct itself — the cleanest direct target. It uses `getaddrinfo` with `AI_NUMERICHOST`, so **no DNS/network** occurs; fuzz-safe.
- **Cmdline:** Split the input buffer on NUL bytes to build `argv` (with a synthetic `argv[0]`), cap argc to a sane bound, NUL-terminate the array.
- **Subststring:** Partition `Data` into find/replace/source using a delimiter scheme; call into a stack `dest[]` of fixed size; rely on ASan to catch any overflow.

### Decision 3: Reset global state every iteration
`ParseCmdline` and the config parser mutate global/`configData`-style state and `getopt`'s global cursor. Each `LLVMFuzzerTestOneInput` MUST re-initialize:
- `getopt`: set `optind = 1` (and `optreset = 1` where available) before every `ParseCmdline` call.
- config/ignore: the target struct is cleared per iteration (`IgnoreParse` already `memset`s; config harness clears its `fileConfig` before each parse).
This keeps runs deterministic and prevents one input from corrupting the next — required by the specs' "no global-state leakage" scenarios.

### Decision 4: Neutralize `exit()` paths
`ParseCmdline` calls `Exit()` on argument conflicts (and `Usage()`/`Version()` paths), which would terminate the fuzzer. Approach, in order of preference:
1. If `Exit` is already a thin wrapper, provide a `#ifdef FUZZ_*` override that `longjmp`s back to the harness (set a `setjmp` checkpoint in `LLVMFuzzerTestOneInput`) instead of calling `exit()`.
2. Failing that, restrict the harness to the non-terminating subset of options.
The mechanism is finalized during implementation against the real `Exit` definition in `io.c`.

### Decision 5: Minimal seed corpora, mirroring the existing convention
One `tests/fuzzing/corpus_fuzz_<target>/` directory per target with a handful of valid samples (config fragment, IP/CIDR/port ignore lines, an argv-encoded sample, a successful substitution). Matches the existing 4-seed convention for the packet targets.

## Risks / Trade-offs

- **Config harness fidelity** → If we target `SetConfiguration` directly rather than the full `ReadConfigFile` read-loop, we may miss bugs in the loop/tokenizer glue. Mitigation: drive the line-tokenizing helpers (`SkipSpaceAndTab`, `GetKeySize`, `GetSizeToQuote`, `StripTrailingSpace`) over raw bytes too, so the byte-walking code is exercised, not just the post-split handler.
- **`Exit()`/`longjmp` interaction with ASan** → `longjmp` out of mid-parse can leak heap allocations and surface as ASan leak reports. Mitigation: prefer option-subset restriction if leaks prove noisy; document chosen approach in tasks.
- **getopt portability** → `optreset` exists on BSD/musl but not glibc; `optind = 1` is the portable reset. Mitigation: guard `optreset` use with `#ifdef`.
- **`getaddrinfo` in ignore parser** → Even with `AI_NUMERICHOST`, confirm no resolver config files are read under the sanitizer. Mitigation: verified by the `AI_NUMERICHOST` flag; spot-check during implementation.
- **Corpus weakness** → Tiny seeds give shallow initial coverage. Accepted: libFuzzer expands corpus over time; seeds only bootstrap.
- **No CI gating** → Targets can rot. Accepted per Non-Goals; `build_fuzz` in `build.sh` keeps them compilable on demand.

## Open Questions

- For `fuzz_configfile`, do we (a) drive `SetConfiguration` + helpers directly, or (b) add a small `#ifdef FUZZ`-guarded function in `configfile.c` that runs the `ReadConfigFile` per-line body over an in-memory buffer (closer to production, more code)? Leaning (b) for fidelity if it stays under ~20 lines; otherwise (a).
- Final `Exit()` neutralization mechanism (longjmp override vs. option-subset) — decided against the real `Exit` implementation during apply.
- Whether any `util.c` routine beyond `SubstString` lacks unit coverage and merits its own target (quick audit during implementation).

## Resolutions (recorded during implementation)

These supersede the corresponding decisions/open questions above once implemented.

- **`Exit()` neutralization (Decision 4 / OQ2):** intercept libc `exit` at link time with `-Wl,--wrap=exit` on `fuzz_cmdline`; `__wrap_exit` `longjmp`s to a `setjmp` checkpoint when inside an iteration (guarded by a flag), else calls `__real_exit` (so libFuzzer's own end-of-run `exit` still works). This catches `Exit()`, `Crash()`, raw `exit()`, and `Usage()` uniformly with zero production-code change. `__lsan_disable/enable` (declared weak so the OpenBSD non-ASan build links) bracket the call to suppress intentional exit-path leaks, and `FreeConfigData(&configData)` runs each iteration to keep RSS bounded. Verified: 281K+ runs, exit 0, RSS flat ~125MB.

- **`fuzz_configfile` entry point (OQ1) — neither (a) nor (b):** routing through `ReadConfigFile`/`SetConfiguration` was rejected because (1) `SetConfiguration` calls `Exit()` on nearly every invalid value, (2) it has real filesystem side effects — `HISTORY_FILE`/`BLOCKED_FILE` call `TestFileAccess(..., createDir=TRUE)`, creating dirs/files from fuzzer-controlled paths, and (3) a `--wrap=exit`+`longjmp` route would leak `fileConfig`'s `ParsePortsList` allocations on common inputs (`TCP_PORTS="80"\n<garbage>`), growing RSS until OOM (`__lsan_disable` hides the report, not the growth). Instead the harness replicates the per-line byte-walking sequence with early returns and drives `ParsePortsList` directly, with deterministic per-iteration `free`. This is leak-free, side-effect-free, needs no linker wraps, and concentrates fuzzing on the pointer-arithmetic parsing code. Verified: 10.3M runs, RSS flat ~525MB.

- **`util.c` audit (OQ3):** `SafeStrncpy`, `GetLong`, `StrToUint16_t`, `CreateDateTime`, `ReallocAndAppend`, and `SubstString` are unit-tested; remaining routines are network/syscall/side-effecting or trivial. `SubstString` is the sole, sufficient string-utils target.

- **getopt reset:** `optind = 0` on glibc/musl (full reinitialization); `optreset = 1; optind = 1` under `#ifdef BSD`.

- **Out-of-scope build unblock (user-approved):** glibc's `NLMSG_DATA` drops `const`, failing `kernelmsg_linux.c` under clang 19 + `-Werror -Wcast-qual` and breaking the shared `lportsentry` build. Fixed by laundering `nh` through `uintptr_t` at the three call sites (preserves the `const` API). Also: building in this environment requires `-D SYSTEMD_SYSTEM_UNIT_DIR=/lib/systemd/system`.
