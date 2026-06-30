## ADDED Requirements

### Requirement: String-utility fuzz target

The project SHALL provide a libFuzzer target `fuzz_subststring` that drives the token-replacement helper `SubstString` with fuzz-derived inputs, following the existing in-file `#ifdef FUZZ_*` harness pattern. The target SHALL be built only when `BUILD_FUZZER=ON` under a Clang Debug build and SHALL link against `lportsentry`.

#### Scenario: Arbitrary substitution inputs handled without memory errors
- **WHEN** the fuzzer derives the find-token, replace-token, and source string from the input and invokes the substitution into a fixed-size destination buffer
- **THEN** the routine processes the input and returns without writing past the destination buffer or triggering any AddressSanitizer or libFuzzer-detected memory error

#### Scenario: Destination bound respected for overflowing inputs
- **WHEN** the input would expand the source beyond the destination buffer capacity
- **THEN** the routine reports truncation/failure rather than overflowing the destination

#### Scenario: Reuse existing unit-tested boundary as oracle
- **WHEN** selecting which utility to fuzz
- **THEN** the target focuses on `SubstString` (already exercised by `tests/test_io_subststring.c`) and other util routines not already covered by unit tests, avoiding redundant targets for fully unit-tested helpers

### Requirement: String-utility seed corpus

The project SHALL provide a seed corpus directory for `fuzz_subststring` under `tests/fuzzing/` containing representative inputs in the harness's encoding.

#### Scenario: Corpus present and well-formed
- **WHEN** the fuzz target is run
- **THEN** a corpus directory exists containing at least one valid sample exercising a successful token replacement
