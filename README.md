<div id="header" align="center">
  <img src="https://portsentry.xyz/img/portsentry.png" width="200" />
</div>

<div id="badges" align="center">
  <img src="https://komarev.com/ghpvc/?username=portsentry&style=flat-square&color=blue" alt=""/>
  <img src="https://github.com/portsentry/portsentry/actions/workflows/github-code-scanning/codeql/badge.svg" alt="" />
  <img src="https://img.shields.io/github/v/release/portsentry/portsentry" alt="" />
  <img src="https://img.shields.io/github/last-commit/portsentry/portsentry" alt="" />
</div>

# Portsentry
**Portsentry is a tool to detect and respond to port scans against a target host in real-time.**

## Quickstart
Most package managers should have a copy of Portsentry. Check with your OS/distribution.

If you need to compile and install manually, review the [Building](https://github.com/portsentry/portsentry/edit/master/README.md#building) section below.

## What is this?
This repo contains a continuation of Psionic's Portsentry tool. Portsentry was abandoned in 2003 at version 1.2. This project aim to continue developing new and improved versions of Portsentry. The initial check in (tag v1.2) is the old, original code from 2003. All other commits are the project continuation.

## What's on the agenda?
We aim to accomplish 3 things in this project:
1. Fix the various long standing bugs in the code
2. Modernize the code in order to make it more efficient, readable and easier to work on
3. Implement new features

## Building
- Use a tag to build an official release
- Use the master branch to build the latest version (not recommended for production)

The build.sh script provides a convenient way to build, clean and run tests:

- ./build.sh debug - Build debug version w/ reasonable defaults
- ./build.sh release - Build release version
- ./build.sh clean - Remove all builds
- ./build.sh sast - Run sast scanners

### Running CMake manually
Required flag is: **CMAKE_BUILD_TYPE**. It should be set to either **Debug** or **Release**.

#### Compilation Examples

**Compiling for release**
```
mkdir release
cd release
cmake .. -D CMAKE_BUILD_TYPE=Release
cmake --build . -v
```

**Compiling with debug symbols**
```
mkdir debug
cd debug
cmake .. -D CMAKE_BUILD_TYPE=Debug
cmake --build . -v
```

**Compiling old version (v1.2)**

Tag v1.2 is the release from 2003, before the project was orphaned and uses a different build method, execute _make_ in order to see compilation instructions.

## Supported Platforms
### Verified
- Linux
- OpenBSD
- FreeBSD
- NetBSD

### To be tested
- OSX
