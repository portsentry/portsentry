## 1. Groundwork

- [x] 1.1 Audit `Exit()`/`Crash()` in `src/io.c` to choose the `longjmp`-override vs. option-subset approach for terminating paths (Design Decision 4).
  - Finding: `Exit()` (io.c:121) calls libc `exit()`; `Crash()`→`Exit()`. `ParseCmdline` reaches `Exit()` at many sites, a raw `exit(EXIT_SUCCESS)` (version, cmdline.c:145), and `Usage()`→`Exit()`. `ReadConfigFile`/`SetConfiguration`/`ParsePortsList` reach `Exit()` extensively.
  - Decision: intercept libc `exit` via linker `-Wl,--wrap=exit` on the cmdline + configfile targets; `__wrap_exit` `longjmp`s to a `setjmp` checkpoint when inside an iteration, else calls `__real_exit`. Catches every termination path with zero production-code change. Wrap the parse region in `__lsan_disable()/__lsan_enable()` to suppress intentional exit-path leaks.
- [x] 1.2 Audit `util.c` against existing unit tests to confirm `SubstString` is the right utility target and no other uncovered routine needs one (Design Open Question 3).
  - Finding: unit-tested already = SafeStrncpy, GetLong, StrToUint16_t, CreateDateTime, ReallocAndAppend, SubstString. Remaining util.c routines are network/syscall/side-effecting (ResolveAddr, DisposeTarget, SetupPort, IsPortInUse, XmitBanner) or trivial (GetProtocolString, GetFamilyString, ErrnoString).
  - Decision: `SubstString` is the right and sufficient string-utils target; fuzzing complements its unit test by exploring arbitrary find/replace/source/destSize. No additional util target.
- [x] 1.3 Confirm the `getopt` reset approach (`optind = 1`, `#ifdef`-guarded `optreset`) compiles on the project toolchain.
  - Decision: `optind = 1` before each `ParseCmdline` (portable); on BSD also `optreset = 1` guarded with the project's existing `#ifdef BSD`.

## 2. Ignore-file fuzz target (`fuzz_ignore`)

- [x] 2.1 Add `#ifdef FUZZ_IGNORE_PARSE`-guarded `LLVMFuzzerTestOneInput` to `src/ignore.c` that NUL-terminates `Data` into a buffer and calls `IgnoreParse`, defining any required globals. (No extra globals needed; `g_isRunning` not referenced on this link path.)
- [x] 2.2 Add the `fuzz_ignore` executable + compile/link options to the `BUILD_FUZZER` block in `CMakeLists.txt`.
- [x] 2.3 Create `tests/fuzzing/corpus_fuzz_ignore/` with valid seeds. (Parser supports IP + optional `/netmask`, not ports — seeded ipv4/ipv6 plain + CIDR.)
- [x] 2.4 Build with `./build.sh build_fuzz` and run briefly to confirm it executes and reaches `IgnoreParse` without immediate crash. (5.6M runs in 11s, ASan clean, +52 corpus units. Required a one-line-per-site `kernelmsg_linux.c` const-launder fix to unblock the shared `lportsentry` build under clang 19 — see task 6.5.)

## 3. String-utility fuzz target (`fuzz_subststring`)

- [x] 3.1 Add `#ifdef FUZZ_SUBSTSTRING`-guarded `LLVMFuzzerTestOneInput` to `src/io.c` that partitions `Data` into find/replace/source tokens and calls `SubstString` into a fixed-size `dest[]`. (Data[0] = destSize 0-255 < sizeof(dest); rest split on NUL into replace/find/source.)
- [x] 3.2 Add the `fuzz_subststring` executable + options to the `BUILD_FUZZER` block in `CMakeLists.txt`.
- [x] 3.3 Create `tests/fuzzing/corpus_fuzz_subststring/` with seeds exercising a successful replacement and a no-match case. (Added basic_replace, no_match, overflow_small_dest.)
- [x] 3.4 Build and run briefly; confirm ASan stays clean on the seed corpus. (4.5M runs in 11s, ASan clean, +291 corpus units.)

## 4. Config-file fuzz target (`fuzz_configfile`)

- [x] 4.1 Decide config entry point per Design Open Question 1. **Resolved differently than either documented option** (see design update): route through neither `ReadConfigFile` nor `SetConfiguration`. Both call `Exit()` on nearly every invalid value AND `SetConfiguration` has filesystem side effects (`TestFileAccess(..., createDir=TRUE)` for HISTORY_FILE/BLOCKED_FILE) — and a `--wrap=exit`+`longjmp` route would leak `fileConfig` port allocations on common inputs (`TCP_PORTS="80"\n<garbage>`), growing RSS until OOM. Instead the harness replicates the per-line byte-walking sequence with early returns and drives `ParsePortsList` directly.
- [x] 4.2 Add `#ifdef FUZZ_CONFIGFILE`-guarded `LLVMFuzzerTestOneInput` to `src/configfile.c`, clearing config state each iteration. (Self-contained; frees `ports` each iteration — no shared global state touched, no leaks.)
- [x] 4.3 Ensure quote handling and `ParsePortsList` are reachable from the harness input. (Replicated StripTrailingSpace → GetKeySize → SkipSpaceAndTab → `=` → quote → GetSizeToQuote → ParsePortsList.)
- [x] 4.4 Add the `fuzz_configfile` executable + options to the `BUILD_FUZZER` block in `CMakeLists.txt`.
- [x] 4.5 Create `tests/fuzzing/corpus_fuzz_configfile/` with valid seeds (key/value lines, a quoted value, a `TCP_PORTS` list).
- [x] 4.6 Build and run briefly; confirm clean execution over seeds. (10.3M runs in 16s, ASan clean, RSS flat at 525MB confirming no leak growth, +412 corpus units.)

## 5. Command-line fuzz target (`fuzz_cmdline`)

- [x] 5.1 Add `#ifdef FUZZ_CMDLINE`-guarded `LLVMFuzzerTestOneInput` to `src/cmdline.c` that splits `Data` on NUL into an `argv` array (synthetic `argv[0]`, capped at `FUZZ_MAX_ARGS=64`, NUL-terminated).
- [x] 5.2 Reset `getopt` state before each `ParseCmdline` call. (Used `optind = 0` on glibc/musl for full reinit; `optreset = 1; optind = 1` under `#ifdef BSD`.)
- [x] 5.3 Implement the chosen `Exit()` neutralization (Task 1.1) so terminating paths return to the harness instead of calling `exit()`. (`-Wl,--wrap=exit` + guarded `setjmp`/`longjmp`; `__lsan_disable/enable` (weak) around the call; `FreeConfigData(&configData)` each iteration to bound RSS.)
- [x] 5.4 Add the `fuzz_cmdline` executable + options to the `BUILD_FUZZER` block in `CMakeLists.txt`. (Adds `-Wl,--wrap=exit` to that target's link options.)
- [x] 5.5 Create `tests/fuzzing/corpus_fuzz_cmdline/` with seeds (mode flags, config path, interface, version) in the NUL-split argv encoding.
- [x] 5.6 Build and run briefly; confirm the fuzzer survives terminating-path inputs without aborting. (281K runs/16s standalone, exit 0, RSS bounded at 125MB; survives `Exit()`/raw `exit()`/`Usage()` paths. Note: the code's own `printf`/`fprintf` error output makes this target noisy and lowers throughput — consider `-close_fd_mask` when running long campaigns.)

## 6. Integration & docs

- [x] 6.1 Run `./build.sh build_fuzz` and confirm all four new targets plus the two existing ones build under Clang Debug. (All 6 build: fuzz_sentry_pcap, fuzz_sentry_stealth, fuzz_ignore, fuzz_subststring, fuzz_configfile, fuzz_cmdline.)
- [x] 6.2 Run `./build.sh run_fuzz` (or per-target) for a short bounded run on each new target; confirm no immediate findings on seeds. (All 6 ran ~5s each via `run_fuzz`; 0 sanitizer errors / crashes / leaks; no crash artifacts.)
- [x] 6.3 Verify a non-fuzzer build (`BUILD_FUZZER=OFF`) is unaffected — the `#ifdef FUZZ_*` guards compile out cleanly. (`./build.sh release` with gcc + `-Werror` built lportsentry/portsentry/portcon cleanly.)
- [x] 6.4 Note the new targets and how to run them in the fuzzing docs/README section if one exists. (Added a "Fuzzing" section to `docs/Contributing.md` with a target table and notes.)
- [x] 6.5 Out-of-scope unblock (user-approved): fix pre-existing `kernelmsg_linux.c` `-Wcast-qual` failure (glibc `NLMSG_DATA` drops `const`) by laundering `nh` through `uintptr_t` at the 3 call sites; keeps the `const` API. Note: build in this env requires `CMAKE_OPTS="-D SYSTEMD_SYSTEM_UNIT_DIR=/lib/systemd/system"`.
