# HOWTO Compile Portsentry

## Requirements

In order to compile, Portsentry requires:

* **CMake (version 3.10 or higher)**
* **GCC or Clang**
* **libpcap** (including headers, often packaged as libpcap-dev)

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

In order to compile, you should supply the **CMAKE_BUILD_TYPE** flag to CMake (see below). It should be set to either **Debug** or **Release**.

Portsentry accepts these flags:

| Flag | Default | Description |
| ---- | ------- | ----------- |
| CMAKE_BUILD_TYPE | Release | Should be set to either Debug or Release |
| USE_PCAP | ON | If used with **USE_PCAP=OFF** set, all pcap code is excluded and Portsentry will not link to libpcap. This option can be used where libpcap is not desired and/or available. |
| BUILD_FUZZER | OFF | If used with **BUILD_FUZZER=ON**, the clang fuzzer tests are built. |
| BUILD_TESTS | OFF | If used with **BUILD_TESTS=ON**, unit tests are built and can be run with the ctest suit. |
| INSTALL_LICENSE | ON | When **INSTALL_LICENSE=ON** the LICENSE file will be included in the generated install files. However, some package managers (like debian and red hat for example) handle license installations separately. In these cases (when building distro packages), you might want to set **INSTALL_LICENSE=OFF**. |

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
