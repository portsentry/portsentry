# fuzz-config-file Specification

## Purpose

Provide continuous fuzz-testing coverage of PortSentry's configuration-file parsing so that malformed config input cannot cause memory-safety errors.

## Requirements

### Requirement: Config-file parsing fuzz target

The project SHALL provide a libFuzzer target `fuzz_configfile` that drives the configuration-file parsing logic with arbitrary byte input, following the existing in-file `#ifdef FUZZ_*` harness pattern. The target SHALL be built only when `BUILD_FUZZER=ON` under a Clang Debug build and SHALL link against `lportsentry`.

#### Scenario: Arbitrary bytes parsed without memory errors
- **WHEN** the fuzzer feeds an arbitrary `Data`/`Size` buffer into the config parsing entry point
- **THEN** the parser processes the input and returns without triggering an AddressSanitizer or libFuzzer-detected memory error (buffer overflow, use-after-free, etc.)

#### Scenario: Quote and ports-list handling exercised
- **WHEN** the input contains quoted values, unterminated quotes, and `TCP_PORTS`/`UDP_PORTS`-style comma-separated port lists
- **THEN** the quote-size, key-size, trailing-space, and ports-list helpers run over the bytes without out-of-bounds access

#### Scenario: No global-state leakage between iterations
- **WHEN** the harness runs many consecutive iterations on different inputs
- **THEN** each iteration starts from a clean configuration state so that results are deterministic and earlier inputs cannot corrupt later ones

### Requirement: Config-file seed corpus

The project SHALL provide a seed corpus directory for `fuzz_configfile` under `tests/fuzzing/` containing representative, valid configuration fragments to bootstrap coverage.

#### Scenario: Corpus present and well-formed
- **WHEN** the fuzz target is run
- **THEN** a corpus directory exists containing at least one valid config sample (e.g. key/value lines, a quoted value, and a ports list)
