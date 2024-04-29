cmake_minimum_required(VERSION 3.10)
project(Portsentry VERSION 2.0)

set(CONFIG_FILE "\"/etc/portsentry/portsentry.conf\"" CACHE STRING "Path to portsentry config file")
set(WRAPPER_HOSTS_DENY "\"/etc/hosts.deny\"" CACHE STRING "Path to hosts.deny file")
set(MAXSTATE 50 CACHE STRING "Maximum number of hosts to keep in a \"previous connect\" state engine")
add_compile_options(-Wall -Wextra -pedantic -Werror -Wformat-security -Wstack-protector -fstack-protector-strong -fPIE -D_FORTIFY_SOURCE=2)
configure_file(config.h.in config.h)


# LIBPORTSENTRY
add_library(lportsentry STATIC src/config_data.c src/configfile.c src/io.c src/util.c src/state_machine.c src/cmdline.c src/connect_sentry.c src/connection_data.c src/stealth_sentry.c src/advanced_sentry.c src/listener.c src/device.c src/sentry_pcap.c)
target_include_directories(lportsentry PRIVATE "${PROJECT_BINARY_DIR}")
target_link_libraries(lportsentry INTERFACE pcap)


# PORTSENTRY
add_executable(portsentry src/portsentry.c)
target_link_options(portsentry PRIVATE -pie)
target_link_libraries(portsentry PRIVATE pcap PRIVATE lportsentry)


# PORTCON - helpter test program
add_executable(portcon portcon/main.c)
target_include_directories(portcon PRIVATE "${PROJECT_BINARY_DIR}")
target_link_options(portcon PRIVATE -pie)


# INSTALL
install(TARGETS portsentry DESTINATION usr/sbin)
install(FILES examples/portsentry.conf DESTINATION etc/portsentry)
install(FILES examples/portsentry.ignore DESTINATION etc/portsentry)


# UNIT TEST MOCK EXEC
add_executable(listener_test tests/listener_test.c)
target_include_directories(listener_test PRIVATE "${PROJECT_BINARY_DIR}")
target_link_options(listener_test PRIVATE -pie)
target_link_libraries(listener_test PRIVATE pcap PRIVATE lportsentry)


# UNIT TESTS
enable_testing()
add_test(NAME listener_auto COMMAND $<TARGET_FILE:listener_test> -stcp)
