# Contribute to Portsentry

## Coding Style

+ Use ``clang-format`` tool to format the code according to the ``.clang-format`` config file
+ Use the ``cpplint`` tool using the ``CPPLING.cfg`` config to make sure you follow the project style.

## Development Environment Setup

+ Install required dependencies:
  - CMake (version 3.10 or higher)
  - C++ compiler (GCC or Clang)
  - clang-format
  - cpplint
  - libpcap
+ For development, you can use the provided Docker environment in the ``docker/`` directory

## Pull Requests

Before submitting a pull request, please make sure that you do the following:

+ Make sure that you have run ``clang-format`` using the ``.clang-format`` config file
+ Make sure the code compiles without Warnings or Errors
+ Run the fuzzers: ``./build.sh build_fuzz ; ./build.sh run_fuzz``
+ Run the integration tests: ``cd system_test ; ./run_all_tests.sh``. Consider running the tests in a VM. It would be greatly appreciated if you could run the tests on Linux, NetBSD, FreeBSD and OpenBSD but it's not a requirement.
  - Note; The shell script build_and_test.sh can be used in order to build and run the tests on several VM's at the same time

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
