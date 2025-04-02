cmake_minimum_required(VERSION 3.10)
project(Portsentry VERSION 2.0)

option(BUILD_FUZZER "Build fuzzer tests" OFF)
option(USE_PCAP "Build with pcap code and link with libpcap" ON)

set(CONFIG_FILE "\"/etc/portsentry/portsentry.conf\"" CACHE STRING "Path to portsentry config file")
set(WRAPPER_HOSTS_DENY "\"/etc/hosts.deny\"" CACHE STRING "Path to hosts.deny file")

set(STANDARD_COMPILE_OPTS -Wall -Wextra -pedantic -Werror -Wformat -Wformat-security -Wstack-protector -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2)
set(CORE_SOURCE_FILES src/config_data.c src/configfile.c src/io.c src/util.c src/state_machine.c src/cmdline.c src/sentry_connect.c src/sighandler.c src/port.c src/packet_info.c src/ignore.c src/sentry.c src/block.c)

if (USE_PCAP)
  set(CORE_SOURCE_FILES ${CORE_SOURCE_FILES} src/pcap_listener.c src/pcap_device.c src/sentry_pcap.c)
  set(STANDARD_COMPILE_OPTS ${STANDARD_COMPILE_OPTS} -DUSE_PCAP)
endif()

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(CORE_SOURCE_FILES ${CORE_SOURCE_FILES} src/sentry_stealth.c)
endif()

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(CORE_SOURCE_FILES ${CORE_SOURCE_FILES} src/kernelmsg_linux.c)
elseif (CMAKE_SYSTEM_NAME STREQUAL "NetBSD") 
  set(CORE_SOURCE_FILES ${CORE_SOURCE_FILES} src/kernelmsg_netbsd.c)
elseif (CMAKE_SYSTEM_NAME STREQUAL "FreeBSD")
  set(CORE_SOURCE_FILES ${CORE_SOURCE_FILES} src/kernelmsg_freebsd.c) 
elseif (CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  set(CORE_SOURCE_FILES ${CORE_SOURCE_FILES} src/kernelmsg_openbsd.c)
else()
  message(FATAL_ERROR "Unsupported operating system ${CMAKE_SYSTEM_NAME}")
endif()

configure_file(config.h.in config.h)


# LIBPORTSENTRY - Static lib of the portsentry functionallity
add_library(lportsentry STATIC ${CORE_SOURCE_FILES})
target_compile_options(lportsentry PRIVATE ${STANDARD_COMPILE_OPTS})
target_include_directories(lportsentry PRIVATE "${PROJECT_BINARY_DIR}")
if (USE_PCAP)
  target_link_libraries(lportsentry INTERFACE pcap)
endif()


# PORTSENTRY - main program
add_executable(portsentry src/portsentry.c)
target_compile_options(portsentry PRIVATE ${STANDARD_COMPILE_OPTS})
target_include_directories(portsentry PRIVATE "${PROJECT_BINARY_DIR}")
target_link_options(portsentry PRIVATE -pie)
target_link_libraries(portsentry PRIVATE lportsentry)
if (USE_PCAP)
  target_link_libraries(portsentry PRIVATE pcap)
endif()

# INSTALL TARGETS for portsentry program
install(TARGETS portsentry DESTINATION usr/sbin)
install(FILES examples/portsentry.conf DESTINATION etc/portsentry)
install(FILES examples/portsentry.ignore DESTINATION etc/portsentry)


# PORTCON - helper test program used in system tests
add_executable(portcon portcon/main.c)
target_compile_options(portcon PRIVATE ${STANDARD_COMPILE_OPTS})
target_include_directories(portcon PRIVATE "${PROJECT_BINARY_DIR}")
target_link_options(portcon PRIVATE -pie)


# FUZZER - fuzzer tests
if (CMAKE_C_COMPILER_ID STREQUAL "Clang" AND CMAKE_BUILD_TYPE STREQUAL "Debug" AND BUILD_FUZZER STREQUAL "ON")
  if (CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
    set(FUZZER_OPTS -fsanitize=fuzzer)
  else()
    set(FUZZER_OPTS -fsanitize=fuzzer,address)
  endif()

  add_executable(fuzz_sentry_pcap src/sentry_pcap.c)
  target_compile_options(fuzz_sentry_pcap PUBLIC -O1 -DFUZZ_SENTRY_PCAP_PREP_PACKET ${FUZZER_OPTS})
  target_include_directories(fuzz_sentry_pcap PRIVATE "${PROJECT_BINARY_DIR}")
  target_link_options(fuzz_sentry_pcap PRIVATE ${FUZZER_OPTS})
  target_link_libraries(fuzz_sentry_pcap PRIVATE lportsentry)
  if (USE_PCAP)
    target_link_libraries(fuzz_sentry_pcap PRIVATE pcap)
  endif()

  add_executable(fuzz_sentry_stealth src/sentry_stealth.c)
  target_compile_options(fuzz_sentry_stealth PUBLIC -O1 -DFUZZ_SENTRY_STEALTH_PREP_PACKET ${FUZZER_OPTS})
  target_include_directories(fuzz_sentry_stealth PRIVATE "${PROJECT_BINARY_DIR}")
  target_link_options(fuzz_sentry_stealth PRIVATE ${FUZZER_OPTS})
  target_link_libraries(fuzz_sentry_stealth PRIVATE lportsentry)
  if (USE_PCAP)
    target_link_libraries(fuzz_sentry_stealth PRIVATE pcap)
  endif()
endif()

# UNIT TEST MOCK EXEC
add_executable(listener_test tests/listener_test.c)
target_compile_options(listener_test PRIVATE ${STANDARD_COMPILE_OPTS})
target_include_directories(listener_test PRIVATE "${PROJECT_BINARY_DIR}")
target_link_options(listener_test PRIVATE -pie)
target_link_libraries(listener_test PRIVATE lportsentry)
if (USE_PCAP)
  target_link_libraries(listener_test PRIVATE pcap)
endif()

# UNIT TESTS
enable_testing()
add_test(NAME listener_auto COMMAND $<TARGET_FILE:listener_test> -stcp)
