cmake_minimum_required(VERSION 3.10)
project(Portsentry VERSION 2.0)

set(CONFIG_FILE "\"/etc/portsentry/portsentry.conf\"" CACHE STRING "Path to portsentry config file")
set(WRAPPER_HOSTS_DENY "\"/etc/hosts.deny\"" CACHE STRING "Path to hosts.deny file")
set(SYSLOG_FACILITY LOG_DAEMON CACHE STRING "Syslog facility to use")
set(SYSLOG_LEVEL LOG_NOTICE CACHE STRING "Syslog level to use")
set(MAXSTATE 50 CACHE STRING "Maximum number of hosts to keep in a \"previous connect\" state engine")

configure_file(config.h.in config.h)

add_executable(portsentry src/config_data.c src/configfile.c  src/portsentry.c  src/io.c  src/util.c src/state_machine.c src/cmdline.c src/connect_sentry.c src/connection_data.c src/stealth_sentry.c src/advanced_sentry.c)

target_include_directories(portsentry PUBLIC "${PROJECT_BINARY_DIR}")

if (CMAKE_C_COMPILER_ID STREQUAL "GNU")
  target_compile_options(portsentry PUBLIC -Wall -Wextra -pedantic -Werror -Wformat-security -Wstack-protector -fstack-protector-strong -pie -fPIE -D_FORTIFY_SOURCE=2)
endif()

target_compile_definitions(portsentry PUBLIC SUPPORT_STEALTH)

target_link_libraries(portsentry PRIVATE $<$<CONFIG:Debug>:efence>)

install(TARGETS portsentry DESTINATION usr/sbin)
install(FILES examples/portsentry.conf DESTINATION etc/portsentry)
install(FILES examples/portsentry.ignore DESTINATION etc/portsentry)
