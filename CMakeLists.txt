cmake_minimum_required(VERSION 3.10)
project(Portsentry VERSION 1.3)

set(CONFIG_FILE "\"/etc/portsentry/portsentry.conf\"" CACHE STRING "Path to portsentry config file")
set(WRAPPER_HOSTS_DENY "\"/etc/hosts.deny\"" CACHE STRING "Path to hosts.deny file")
set(SYSLOG_FACILITY LOG_DAEMON CACHE STRING "Syslog facility to use")
set(SYSLOG_LEVEL LOG_NOTICE CACHE STRING "Syslog level to use")
set(MAXSTATE 50 CACHE STRING "Maximum number of hosts to keep in a \"previous connect\" state engine")

option(NODAEMON "Don't daemonize" OFF)
option(SUPPORT_STEALTH "Enable stealth mode" OFF)

configure_file(config.h.in config.h)

add_executable(portsentry src/config_data.c src/configfile.c  src/portsentry.c  src/portsentry_io.c  src/portsentry_util.c)
target_include_directories(portsentry PUBLIC "${PROJECT_BINARY_DIR}")

if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
  target_compile_options(portsentry PUBLIC -Wall -Wextra -pedantic)
endif()

# FIXME: Hack to get correct build conditions under linux. Platform should be evaluated/selected later
target_compile_definitions(portsentry PUBLIC LINUX)

target_compile_definitions(portsentry PRIVATE $<$<CONFIG:Debug>:DEBUG>)

target_link_libraries(portsentry PRIVATE $<$<CONFIG:Debug>:efence>)

if (NODAEMON)
  target_compile_definitions(portsentry PUBLIC NODAEMON)
endif()

if (SUPPORT_STEALTH)
  target_compile_definitions(portsentry PUBLIC SUPPORT_STEALTH)
endif()

install(TARGETS portsentry DESTINATION usr/sbin)
install(FILES examples/portsentry.conf DESTINATION etc/portsentry)
install(FILES examples/portsentry.ignore DESTINATION etc/portsentry)
