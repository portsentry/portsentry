## ADDED Requirements

### Requirement: Ignore-file parsing fuzz target

The project SHALL provide a libFuzzer target `fuzz_ignore` that drives the ignore-file line parser (`IgnoreParse`) with arbitrary byte input, following the existing in-file `#ifdef FUZZ_*` harness pattern. The target SHALL be built only when `BUILD_FUZZER=ON` under a Clang Debug build and SHALL link against `lportsentry`.

#### Scenario: Arbitrary line parsed without memory errors
- **WHEN** the fuzzer feeds an arbitrary NUL-terminated line buffer into the ignore-line parser
- **THEN** the parser processes the input and returns without triggering an AddressSanitizer or libFuzzer-detected memory error

#### Scenario: Address, netmask, and port forms exercised
- **WHEN** the input contains IPv4/IPv6 literals, CIDR netmask suffixes, port suffixes, comments, and malformed mixtures
- **THEN** the address-character validation and field splitting run over the bytes without out-of-bounds access

#### Scenario: Per-iteration output struct isolation
- **WHEN** the harness runs many consecutive iterations
- **THEN** the `IgnoreIp` output structure is reset each iteration so that parsing results are deterministic and independent of prior inputs

### Requirement: Ignore-file seed corpus

The project SHALL provide a seed corpus directory for `fuzz_ignore` under `tests/fuzzing/` containing representative valid ignore-file entries.

#### Scenario: Corpus present and well-formed
- **WHEN** the fuzz target is run
- **THEN** a corpus directory exists containing at least one valid ignore entry (e.g. a plain IP, a CIDR entry, and an entry with a port)
