# Portsentry

**IMPORTANT! TL;DR: If you pull this code with the intent to use it in prod, then BUILD FROM tag v1.2. Tag v1.2 is the original Portsentry code, as it where when it was orphaned in 2003. The new version is _not_ complete yet. Many linux distributions also provide precomiled binaries in their package managers**

## What is this?
This repo contains a continuation of Psionic's sentrytools/portsentry code. Portsentry was abandoned in 2003 at version 1.2. This project aim to continue developing new and improved versions of Portsentry. The initial check in (tag v1.2) is the old, original code from 2003. All other commits are the project continuation.

## What's on the agenda?
We aim to accomplish 3 things in this project:
1. Fix the various long standing bugs in the code
2. Modernize the code in order to make it more efficient, readable and easier to work on
3. Implement new features

## Compiling
Checkout a specific tag to compile stable releases, or use the master branch for the latest, unstable version. There are a number of compile-time options which can be specified.

The most import (and required flag is) **CMAKE_BUILD_TYPE**. It should be set to either **Debug** or **Release**.

Two other very important (recommended) flags are: **NODAEMON** and **SUPPORT_STEALTH**. Set NODAEMON to ON if you plan on running via a daemon service like systemd. In addition, you will in 99% of cases want to set SUPPORT_STEALTH to ON.

### Compilation Examples

**Compiling for release**
```
mkdir release
cd release
cmake .. -D CMAKE_BUILD_TYPE=Release -D NODAEMON=ON -D SUPPORT_STEALTH=ON
cmake --build . -v
```

**Compiling for debugging (mostly for developing)**
```
mkdir debug
cd debug
cmake .. -D CMAKE_BUILD_TYPE=Debug -D NODAEMON=ON -D SUPPORT_STEALTH=ON
cmake --build . -v
```

**Compiling old version (v1.2)**

Tag v1.2 is the release from 2003, before the project was orphaned and uses a different build method, execute _make_ in order to see compilation instructions. All versions after v1.2, see instructions below.

