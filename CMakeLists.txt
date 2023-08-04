cmake_minimum_required(VERSION 3.10)
project(Portsentry VERSION 1.3)

set(CMAKE_C_FLAGS "-O -Wall -Wextra -pedantic -DLINUX -DSUPPORT_STEALTH")

set(CONFIG_FILE "\"/etc/portsentry/portsentry.conf\"" CACHE STRING "Path to portsentry config file")
set(WRAPPER_HOSTS_DENY "\"/etc/hosts.deny\"" CACHE STRING "Path to hosts.deny file")
set(SYSLOG_FACILITY LOG_DAEMON CACHE STRING "Syslog facility to use")
set(SYSLOG_LEVEL LOG_NOTICE CACHE STRING "Syslog level to use")
set(MAXSTATE 50 CACHE STRING "Maximum number of hosts to keep in a \"previous connect\" state engine")

option(NODAEMON "Don't daemonize" OFF)
option(DEBUG "Enable debug output" OFF)

if (DEBUG)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -DDEBUG")
endif()

if (NODAEMON)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -DNODAEMON")
endif()

configure_file(config.h.in config.h)

add_executable(portsentry src/configfile.c  src/portsentry.c  src/portsentry_io.c  src/portsentry_util.c)
target_include_directories(portsentry PUBLIC "${PROJECT_BINARY_DIR}")
