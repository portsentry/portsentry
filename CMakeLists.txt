cmake_minimum_required(VERSION 3.10)
project(Portsentry VERSION 2.0)

set(CONFIG_FILE "\"/etc/portsentry/portsentry.conf\"" CACHE STRING "Path to portsentry config file")
set(WRAPPER_HOSTS_DENY "\"/etc/hosts.deny\"" CACHE STRING "Path to hosts.deny file")
set(MAXSTATE 50 CACHE STRING "Maximum number of hosts to keep in a \"previous connect\" state engine")

# We must find the path to the static version of libefence because OpenBSD only ships the static version, so we link to it statically on all platforms for convenience.
find_library(EFENCE_LIBRARY NAMES libefence.a HINTS "/usr/lib" "/usr/local/lib" "/usr/pkg/lib")

configure_file(config.h.in config.h)

# PORTSENTRY
add_executable(portsentry src/config_data.c src/configfile.c src/portsentry.c src/io.c src/util.c src/state_machine.c src/cmdline.c src/connect_sentry.c src/connection_data.c src/stealth_sentry.c src/advanced_sentry.c src/listener.c src/device.c src/sentry_pcap.c)
target_include_directories(portsentry PUBLIC "${PROJECT_BINARY_DIR}")
target_compile_options(portsentry PUBLIC -Wall -Wextra -pedantic -Werror -Wformat-security -Wstack-protector -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2)
target_link_options(portsentry PUBLIC -pie)
target_link_libraries(portsentry pcap $<$<CONFIG:Debug>:${EFENCE_LIBRARY}>)


# PORTCON - helpter test program
add_executable(portcon portcon/main.c)
target_include_directories(portcon PUBLIC "${PROJECT_BINARY_DIR}")
target_compile_options(portcon PUBLIC -Wall -Wextra -pedantic -Werror -Wformat-security -Wstack-protector -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2)
target_link_options(portcon PUBLIC -pie)


# UNIT TESTS
add_executable(listener_test tests/listener_test.c src/config_data.c src/configfile.c src/io.c src/util.c src/state_machine.c src/cmdline.c src/connect_sentry.c src/connection_data.c src/stealth_sentry.c src/advanced_sentry.c src/listener.c src/device.c src/sentry_pcap.c)
target_include_directories(listener_test PUBLIC "${PROJECT_BINARY_DIR}")
target_compile_options(listener_test PUBLIC -Wall -Wextra -pedantic -Werror -Wformat-security -Wstack-protector -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2)
target_link_options(listener_test PUBLIC -pie)
target_link_libraries(listener_test pcap)

install(TARGETS portsentry DESTINATION usr/sbin)
install(FILES examples/portsentry.conf DESTINATION etc/portsentry)
install(FILES examples/portsentry.ignore DESTINATION etc/portsentry)

enable_testing()
add_test(NAME listener_auto COMMAND $<TARGET_FILE:listener_test> -stcp)
