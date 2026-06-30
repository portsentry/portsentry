# Contribute to Portsentry

## Coding Style

+ Use the ``clang-format`` tool to format the code according to the ``.clang-format`` config file
+ Use the ``cpplint`` tool using the ``CPPLINT.cfg`` config to make sure you follow the project style.

## Development Environment Setup

+ Install the following formatter/linting tools
  - clang-format
  - cpplint
+ Review [HOWTO-Compile.md](HOWTO-Compile.md) for compilation requirements.
+ (optional) Install [CodeQL](https://codeql.github.com) in order to be able to run it locally.

## Pull Requests

Before submitting a pull request, please make sure that you do the following:

+ Make sure that you have run ``clang-format`` using the ``.clang-format`` config file
+ Make sure the code compiles without Warnings or Errors
+ (optional) Run [CodeQL](https://codeql.github.com) locally if you have it installed
+ Run the fuzzers: ``./build.sh build_fuzz ; ./build.sh run_fuzz``
+ Run the integration tests: ``cd system_test ; ./run_all_tests.sh``. Consider running the tests in a VM. It would be greatly appreciated if you could run the tests on Linux, NetBSD, FreeBSD and OpenBSD but it's not a requirement.
  - Note: The shell script build_and_test.sh can be used in order to build and run the tests on several VMs at the same time

## Fuzzing

Fuzz targets are built with clang + libFuzzer (and AddressSanitizer, except on OpenBSD) when configuring with ``BUILD_FUZZER=ON``. ``./build.sh build_fuzz`` builds every target and ``./build.sh run_fuzz [seconds]`` runs each one against its seed corpus under ``tests/fuzzing/corpus_<target>/``. New targets are picked up automatically (the scripts glob ``fuzz_*``).

Current targets:

| Target | Exercises |
| --- | --- |
| ``fuzz_sentry_pcap`` | Packet parsing via ``PrepPacket`` |
| ``fuzz_sentry_stealth`` | Packet parsing via ``SetPacketInfoFromPacket`` |
| ``fuzz_ignore`` | Ignore-file line parser (``IgnoreParse``) |
| ``fuzz_subststring`` | Token-replacement helper (``SubstString``) |
| ``fuzz_configfile`` | Config-file line tokenizer + ports-list parser |
| ``fuzz_cmdline`` | Command-line parser (``ParseCmdline``) |

Notes:

+ Harnesses live inside the production ``.c`` files behind ``#ifdef FUZZ_*`` guards, matching the existing pattern, so they compile out of normal builds.
+ ``fuzz_cmdline`` wraps libc ``exit`` (``-Wl,--wrap=exit``) so the many ``Exit()``/``exit()`` paths in ``ParseCmdline`` return to the harness instead of terminating the run. It is intentionally noisy (the parser prints usage/error text); pass ``-close_fd_mask=3`` to mute stdout/stderr during long campaigns.
+ ``fuzz_configfile`` deliberately drives the parsing primitives directly rather than ``ReadConfigFile``/``SetConfiguration`` to avoid filesystem side effects and process termination.

## Documentation

Make sure to update the documentation when needed. All documentation is in the docs/ folder. Pay special attention to:

+ Keep examples/portsentry.conf in sync with docs/portsentry.conf.md

## Issue Reporting

When reporting issues:
+ Check if the issue has already been reported in the issue tracker
+ Provide detailed information:
  - Operating system and version
  - Portsentry version
  - Steps to reproduce
  - Expected vs actual behavior
  - Relevant logs or error messages

## Code Review Process

+ Pull requests will be reviewed by maintainers
+ Be responsive to feedback and requested changes
+ Keep pull requests focused and manageable in size
+ Include tests for new features or bug fixes
+ Update documentation as needed
