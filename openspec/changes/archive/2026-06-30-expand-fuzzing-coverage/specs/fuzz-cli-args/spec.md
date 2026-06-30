## ADDED Requirements

### Requirement: Command-line argument parsing fuzz target

The project SHALL provide a libFuzzer target `fuzz_cmdline` that drives `ParseCmdline` with an arbitrary argument vector derived from the fuzz input, following the existing in-file `#ifdef FUZZ_*` harness pattern. The target SHALL be built only when `BUILD_FUZZER=ON` under a Clang Debug build and SHALL link against `lportsentry`.

#### Scenario: Arbitrary argv parsed without memory errors
- **WHEN** the fuzzer splits `Data`/`Size` into an `argv`-style token array and passes it to the command-line parser
- **THEN** the parser processes the arguments and returns without triggering an AddressSanitizer or libFuzzer-detected memory error

#### Scenario: getopt global state reset each iteration
- **WHEN** the harness runs many consecutive iterations
- **THEN** the `getopt` parsing index is reset before each invocation so that option parsing is deterministic and not contaminated by prior iterations

#### Scenario: Process-terminating paths neutralized
- **WHEN** an input triggers a path that would normally call `exit()` (e.g. usage/version/error exit)
- **THEN** the harness prevents process termination so the fuzzer can continue exploring inputs rather than aborting the run

### Requirement: Command-line seed corpus

The project SHALL provide a seed corpus directory for `fuzz_cmdline` under `tests/fuzzing/` containing representative valid argument combinations encoded in the harness's argv-splitting format.

#### Scenario: Corpus present and well-formed
- **WHEN** the fuzz target is run
- **THEN** a corpus directory exists containing at least one valid argument sample (e.g. a mode flag and a config-file path)
