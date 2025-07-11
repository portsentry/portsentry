cmake_minimum_required(VERSION 3.10)
project(portsentry VERSION 2.0.2)
include(CheckCCompilerFlag)

option(BUILD_FUZZER "Build fuzzer tests" OFF)
option(BUILD_TESTS "Build unit tests" OFF)
option(USE_PCAP "Build with pcap code and link with libpcap" ON)

set(CONFIG_FILE "\"/etc/portsentry/portsentry.conf\"" CACHE STRING "Path to portsentry config file")
set(WRAPPER_HOSTS_DENY "\"/etc/hosts.deny\"" CACHE STRING "Path to hosts.deny file")

set(STANDARD_COMPILE_OPTS -Wall -Wextra -pedantic -Werror -Wformat -Wformat-security -Wstack-protector -Wshadow -Wredundant-decls -Wdisabled-optimization -Wnested-externs -Wstrict-overflow=2 -Wconversion -fPIE -fstack-protector-strong -fstrict-aliasing -fno-common -fno-strict-overflow -D_FORTIFY_SOURCE=2)

check_c_compiler_flag("-fcf-protection=full" COMPILER_SUPPORTS_CFI_PROTECTION)

if (COMPILER_SUPPORTS_CFI_PROTECTION)
  set(STANDARD_COMPILE_OPTS ${STANDARD_COMPILE_OPTS} -fcf-protection=full)
endif()

set(STANDARD_LINK_OPTS -pie -Wl,-z,noexecstack -Wl,-z,now -Wl,-z,relro -Wl,-z,defs -Wl,--no-undefined)
set(CORE_SOURCE_FILES src/config_data.c src/configfile.c src/io.c src/util.c src/state_machine.c src/cmdline.c src/sentry_connect.c src/sighandler.c src/port.c src/packet_info.c src/ignore.c src/sentry.c src/block.c)

execute_process(COMMAND git log -1 --format=%h WORKING_DIRECTORY ${CMAKE_SOURCE_DIR} OUTPUT_VARIABLE GIT_COMMIT_HASH OUTPUT_STRIP_TRAILING_WHITESPACE)
add_definitions("-DGIT_COMMIT_HASH=\"${GIT_COMMIT_HASH}\"")

if (USE_PCAP)
  set(CORE_SOURCE_FILES ${CORE_SOURCE_FILES} src/pcap_listener.c src/pcap_device.c src/sentry_pcap.c)
  set(STANDARD_COMPILE_OPTS ${STANDARD_COMPILE_OPTS} -DUSE_PCAP)
endif()

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(CORE_SOURCE_FILES ${CORE_SOURCE_FILES} src/sentry_stealth.c)
endif()

if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
  set(CORE_SOURCE_FILES ${CORE_SOURCE_FILES} src/kernelmsg_linux.c)
elseif (CMAKE_SYSTEM_NAME STREQUAL "NetBSD" OR CMAKE_SYSTEM_NAME STREQUAL "FreeBSD" OR CMAKE_SYSTEM_NAME STREQUAL "OpenBSD")
  set(CORE_SOURCE_FILES ${CORE_SOURCE_FILES} src/kernelmsg_bsd.c)
else()
  message(FATAL_ERROR "Unsupported operating system ${CMAKE_SYSTEM_NAME}")
endif()

configure_file(config.h.in config.h)

# CPack configuration
set(CPACK_PACKAGING_INSTALL_PREFIX ${CMAKE_INSTALL_PREFIX})
set(CPACK_DEBIAN_PACKAGE_NAME "portsentry")
set(CPACK_DEBIAN_PACKAGE_DEPENDS "libc6 (>= 2.36), libpcap0.8 (>= 1.10.3)")
set(CPACK_DEBIAN_PACKAGE_SECTION "net")
set(CPACK_DEBIAN_PACKAGE_PRIORITY "optional")
set(CPACK_DEBIAN_PACKAGE_MAINTAINER "Marcus Hufvudsson <mh@protohuf.com")
set(CPACK_DEBIAN_PACKAGE_HOMEPAGE "https://portsentry.xyz")
set(CPACK_DEBIAN_PACKAGE_RECOMMENDS "fail2ban")
set(CPACK_DEBIAN_PACKAGE_DESCRIPTION "A port scanning detection tool")

include(CPack)

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
target_link_options(portsentry PRIVATE ${STANDARD_LINK_OPTS})
target_link_libraries(portsentry PRIVATE lportsentry)
if (USE_PCAP)
  target_link_libraries(portsentry PRIVATE pcap)
endif()

# Check for pandoc and generate man pages if available
find_program(PANDOC_EXECUTABLE pandoc)
if(PANDOC_EXECUTABLE)
    add_custom_command(
        OUTPUT
            ${CMAKE_SOURCE_DIR}/man/portsentry.8
            ${CMAKE_SOURCE_DIR}/man/portsentry.conf.8
        COMMAND ${PANDOC_EXECUTABLE} --standalone --to man ${CMAKE_SOURCE_DIR}/docs/Manual.md -o ${CMAKE_SOURCE_DIR}/man/portsentry.8
        COMMAND ${PANDOC_EXECUTABLE} --standalone --to man ${CMAKE_SOURCE_DIR}/docs/portsentry.conf.md -o ${CMAKE_SOURCE_DIR}/man/portsentry.conf.8
        COMMENT "Generating man pages using pandoc"
    )
    add_custom_target(generate_man_pages DEPENDS
        ${CMAKE_SOURCE_DIR}/man/portsentry.8
        ${CMAKE_SOURCE_DIR}/man/portsentry.conf.8
    )
    add_dependencies(portsentry generate_man_pages)
endif()

# INSTALL TARGETS for portsentry program
include(GNUInstallDirs)

configure_file(init/portsentry.service.in init/portsentry.service @ONLY)

install(TARGETS portsentry DESTINATION ${CMAKE_INSTALL_SBINDIR})
install(FILES examples/portsentry.conf DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/portsentry)
install(FILES examples/portsentry.ignore DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/portsentry)
install(FILES examples/logrotate.conf DESTINATION ${CMAKE_INSTALL_SYSCONFDIR}/logrotate.d RENAME portsentry)
install(FILES man/portsentry.8 DESTINATION ${CMAKE_INSTALL_MANDIR}/man8)
install(FILES man/portsentry.conf.8 DESTINATION ${CMAKE_INSTALL_MANDIR}/man8)
install(DIRECTORY docs/ DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(FILES Changes.md README.md LICENSE DESTINATION ${CMAKE_INSTALL_DOCDIR})
install(FILES ${CMAKE_CURRENT_BINARY_DIR}/init/portsentry.service DESTINATION ${CMAKE_INSTALL_LIBDIR}/systemd/system)

# PORTCON - helper test program used in system tests
add_executable(portcon portcon/main.c)
target_compile_options(portcon PRIVATE ${STANDARD_COMPILE_OPTS})
target_include_directories(portcon PRIVATE "${PROJECT_BINARY_DIR}")
target_link_options(portcon PRIVATE ${STANDARD_LINK_OPTS})

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

# UNIT TESTS
if(BUILD_TESTS)
  set(UNIT_TEST_COMPILE_OPTS ${STANDARD_COMPILE_OPTS} -Wno-unused-result -Wno-unused-value -Wno-unused-variable -Wno-unused-but-set-variable)

  add_executable(test_util_safestrncpy tests/test_util_safestrncpy.c)
  target_compile_options(test_util_safestrncpy PRIVATE ${UNIT_TEST_COMPILE_OPTS})
  target_include_directories(test_util_safestrncpy PRIVATE "${PROJECT_BINARY_DIR}")
  target_link_options(test_util_safestrncpy PRIVATE ${STANDARD_LINK_OPTS})
  target_link_libraries(test_util_safestrncpy PRIVATE lportsentry)

  add_executable(test_util_getlong tests/test_util_getlong.c)
  target_compile_options(test_util_getlong PRIVATE ${UNIT_TEST_COMPILE_OPTS})
  target_include_directories(test_util_getlong PRIVATE "${PROJECT_BINARY_DIR}")
  target_link_options(test_util_getlong PRIVATE ${STANDARD_LINK_OPTS})
  target_link_libraries(test_util_getlong PRIVATE lportsentry)

  add_executable(test_util_createdatetime tests/test_util_createdatetime.c)
  target_compile_options(test_util_createdatetime PRIVATE ${UNIT_TEST_COMPILE_OPTS})
  target_include_directories(test_util_createdatetime PRIVATE "${PROJECT_BINARY_DIR}")
  target_link_options(test_util_createdatetime PRIVATE ${STANDARD_LINK_OPTS})
  target_link_libraries(test_util_createdatetime PRIVATE lportsentry)

  add_executable(test_util_strtouint16 tests/test_util_strtouint16.c)
  target_compile_options(test_util_strtouint16 PRIVATE ${UNIT_TEST_COMPILE_OPTS})
  target_include_directories(test_util_strtouint16 PRIVATE "${PROJECT_BINARY_DIR}")
  target_link_options(test_util_strtouint16 PRIVATE ${STANDARD_LINK_OPTS})
  target_link_libraries(test_util_strtouint16 PRIVATE lportsentry)

  add_executable(test_util_reallocandappend tests/test_util_reallocandappend.c)
  target_compile_options(test_util_reallocandappend PRIVATE ${UNIT_TEST_COMPILE_OPTS})
  target_include_directories(test_util_reallocandappend PRIVATE "${PROJECT_BINARY_DIR}")
  target_link_options(test_util_reallocandappend PRIVATE ${STANDARD_LINK_OPTS})
  target_link_libraries(test_util_reallocandappend PRIVATE lportsentry)

  add_executable(test_state_machine tests/test_state_machine.c)
  target_compile_options(test_state_machine PRIVATE ${UNIT_TEST_COMPILE_OPTS})
  target_include_directories(test_state_machine PRIVATE "${PROJECT_BINARY_DIR}")
  target_link_options(test_state_machine PRIVATE ${STANDARD_LINK_OPTS})
  target_link_libraries(test_state_machine PRIVATE lportsentry)

  add_executable(test_port tests/test_port.c)
  target_compile_options(test_port PRIVATE ${UNIT_TEST_COMPILE_OPTS})
  target_include_directories(test_port PRIVATE "${PROJECT_BINARY_DIR}")
  target_link_options(test_port PRIVATE ${STANDARD_LINK_OPTS})
  target_link_libraries(test_port PRIVATE lportsentry)

  # Enable testing and add test targets
  enable_testing()
  add_test(NAME test_util_safestrncpy COMMAND $<TARGET_FILE:test_util_safestrncpy>)
  add_test(NAME test_util_getlong COMMAND $<TARGET_FILE:test_util_getlong>)
  add_test(NAME test_util_createdatetime COMMAND $<TARGET_FILE:test_util_createdatetime>)
  add_test(NAME test_util_strtouint16 COMMAND $<TARGET_FILE:test_util_strtouint16>)
  add_test(NAME test_util_reallocandappend COMMAND $<TARGET_FILE:test_util_reallocandappend>)
  add_test(NAME test_state_machine COMMAND $<TARGET_FILE:test_state_machine>)
  add_test(NAME test_port COMMAND $<TARGET_FILE:test_port>)
endif()
