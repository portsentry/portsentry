# HOWTO Compile Portsentry

## Requirements

Portsentry requires **CMake (version 3.10 or higher)**, **GCC or Clang** and **libpcap** in order to compile

## Quickstart

The build.sh convenience script can be used in order to build Portsentry

To build a debug version:

```
./build.sh debug
```

To build a release version

```
./build.sh release
```

## Running CMake manually

In order to compile, you must supply the **CMAKE_BUILD_TYPE** flag to CMake (see below). It should be set to either **Debug** or **Release**.

Portsentry accepts one additional flag:

**USE_PCAP=ON|OFF** (default: ON)

If used with **USE_PCAP=OFF** set, all pcap code is excluded and Portsentry will not link to libpcap. This option can be used where libpcap is not desired and/or available.

### Compilation Examples

**Compiling for release**
```
  cmake -B release -D CMAKE_BUILD_TYPE=Release
  cmake --build release -v
```

**Compiling with debug symbols**
```
  cmake -B debug -D CMAKE_BUILD_TYPE=Debug
  cmake --build debug -v
```

**Compiling without LIBPCAP**
```
  cmake -B release -D CMAKE_BUILD_TYPE=Release -DUSE_PCAP=OFF
  cmake --build release -v
```

**Compiling old version (v1.2)**

Tag v1.2 is the release from 2003, before the project was orphaned and uses a different build method, execute _make_ in order to see compilation instructions.

## Supported Platforms
- Linux
- OpenBSD
- FreeBSD
- NetBSD >= 8.0
