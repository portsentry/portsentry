## Why

PortSentry currently fuzzes only the network packet-parsing path (`fuzz_sentry_pcap`, `fuzz_sentry_stealth`). Several other untrusted-input surfaces — the config file, the ignore file, command-line arguments, and the shared string-manipulation utilities — are parsed by hand-written C with no continuous fuzz coverage. These paths process attacker-influenced or operator-supplied text into fixed-size buffers and global state, exactly the kind of code where off-by-one and unbounded-copy bugs hide. Broadening fuzz coverage now, while the harness pattern is fresh and the corpus tooling already exists, is cheap insurance against memory-safety regressions.

## What Changes

- Add a **config-file** fuzz target exercising the line tokenizer, key/value parser, quote handling, and ports-list parser (`ReadConfigFile` core: `SetConfiguration`, `ParsePortsList`, and the `SkipSpaceAndTab` / `GetKeySize` / `StripTrailingSpace` / `GetSizeToQuote` helpers).
- Add an **ignore-file** fuzz target exercising the per-line address/netmask/port parser (`IgnoreParse`) and, where feasible, the file loader (`InitIgnore`).
- Add a **cli-args** fuzz target exercising `ParseCmdline`, including `getopt` global-state reset and neutralizing process-terminating paths (`Exit`/`Usage`) so the fuzzer can continue.
- Add a **string-utils** fuzz target exercising the token-replacement and buffer-building helpers, primarily `SubstString` (and any util.c routines not already covered by unit tests).
- Extend the build/run tooling (`CMakeLists.txt` `BUILD_FUZZER` block, `build.sh`) to compile and run the new targets, and add seed corpora for each under `tests/fuzzing/`.

## Capabilities

### New Capabilities
- `fuzz-config-file`: Fuzz harness and corpus covering configuration-file text parsing.
- `fuzz-ignore-file`: Fuzz harness and corpus covering ignore-file line/address parsing.
- `fuzz-cli-args`: Fuzz harness and corpus covering command-line argument parsing.
- `fuzz-string-utils`: Fuzz harness and corpus covering shared string-manipulation utilities.

### Modified Capabilities
<!-- None. No existing runtime behavior or requirements change; this adds test-only harnesses. -->

## Impact

- **Build system**: `CMakeLists.txt` (new `add_executable` targets and `-DFUZZ_*` compile definitions under the existing `BUILD_FUZZER` guard); `build.sh` (`build_fuzz` / `run_fuzz` already glob `fuzz_*`, so new targets are picked up automatically).
- **Source files**: `src/configfile.c`, `src/ignore.c`, `src/cmdline.c`, `src/io.c` (and possibly `src/util.c`) gain `#ifdef FUZZ_*`-guarded `LLVMFuzzerTestOneInput` harnesses, following the existing in-file macro pattern used by `sentry_pcap.c` / `sentry_stealth.c`. No non-fuzz runtime behavior changes.
- **Corpus**: New seed directories under `tests/fuzzing/` (e.g. `corpus_fuzz_configfile`, etc.).
- **Dependencies**: None new — relies on existing Clang + libFuzzer/ASan toolchain already required by `BUILD_FUZZER`.
- **Risk**: Harnesses must avoid global-state leakage between iterations (config globals, `getopt` `optind`) and must not call `exit()`; this is the main implementation hazard, addressed in design.
