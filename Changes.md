# Portsentry Changelog

## 2025-05-09 2.0.0

### Bugfixes
- Fixed bug where block and ignore file would be written to even though user has configured portsentry to not do any blocking
- Fixed multiple potential race conditions which could manifest when running two portsentry instances
- Fixed potential bug in state engine which could overflow and miss reporting on packets
- Various smaller bugfixes

### Features
- Added libpcap support, which enables stealth mode on *BSD systems and increases performance
- Added IPv6 support
- Added Docker support and added portsentry registry on docker hub
- Added fail2ban integration

### Improvements
- Significant disk usage reduction after parser redesign. Code no longer continually re-reads config file
- Removed/consolidated several duplicate code/DRY violations, significantly reducing code size and potential errors
- Fixed resource leak of socket file descriptors in connect mode in certain situations
- Merged tcp/udp modes so both protocols can be monitored at the same time. No more dual processes
- General code cleanup and removal of legacy code
- Added more command line options in order to increase runtime flexibility
- Change to runtime debug/verbose log output, additionally supporting stdout instead of only syslog and added distinction between log and error messages
- Incorporated "advanced mode" features into both connect and stealth modes
- Changed to CMake instead of hand written makefiles
- Added Linting and Formating
- Added integration tests
- Added fuzzing tests
- Added SAST testing
- Added systemd unit
- Updated and increased the amount of documentation

## 2003-05-23 - 1.2
- Removed references to old psionic e-mail and changed license to Common Public License.

## 2001-06-26 - 1.1
- Added Mac OS X build support (Same as FreeBSD).
- Fixed bug for Advanced mode to properly monitor 1024 ports (it only did first 1023 before). Thanks Guido.

## 2001-03-23 - 1.1
- Fixed a bug that showed up under Linux 2.4 Kernel that would cause accept to loop. There was an error with how I used a count variable after trying to bind to ports. If the port didn't bind the count for the openSockfd would still increment and this caused the error to show up.

## 2000-09-09 - 1.1
- Finally moved resolver functions to own area.
- Made CleanAndResolve to ensure DNS records returned are sanitized correctly before being passed back.

## 2000-09-08 - 1.1
- Added in netmask support

## 2000-07-05 - 1.1
- Added iptables support (thanks Scott Catterton <scatterton@valinux.com>)
- Added Makefile support for Irix
- Put in ports for common DDOS ports

## 2000-06-21 - 1.1
- Added in feature to disable DNS host resolution by checking RESOLVE_HOST in conf file.
- Added in feature to have external command run before or after blocking has occurred as defined in KILL_RUN_CMD_FIRST option in conf file.
- Removed DoBlockTCP/UDP functions. Converted over to generic flag checker.

## 2000-06-08 - 1.1
- Fixed an error in the state engine portion that could cause an increment error under certain conditions. Thanks Peter M. Allan <peter.m.allan@hsbcgroup.com> for finding this.

## 2000-03-31 - 1.1
- Updated .conf to add ipf blocking rule. Thanks Graham Dunn <gdunn@inscriber.com>

## 1999-12-21 - 1.1
- Fixed typo in bare-bones TCP list where 524 was supposed to be for 1524.

## 1999-11-14 - 1.0
- Y2K fix in WriteBlocked functions. Now uses four digit year in .blocked and .history files. PortSentry doesn't use dates as part of its operations, however third party scripts may use the .blocked and .history files and the two digit format would roll over to 1/1/100 on Jan 1 instead of 1/1/00 causing a potential problem. Sorry about that. :(

```
    Old format:

    942286729 - 11/10/99 20:18:49 Host: 192.168.2.12/192.168.2.12 Port: 111 TCP Blocked

    New format:

    942286729 - 11/10/1999 20:18:49 Host: 192.168.2.12/192.168.2.12 Port: 111 TCP Blocked
```

## 1999-10-24 - 1.0
- Updated docs to tell users how to add LOCAL0 facility for syslog reporting.

## 1999-10-15 - 1.0
- NeverBlock() function fixed so now it actually does ignore hosts correctly. I was stripping off the EOL prematurely during a strlen check and this caused the problem. Thanks to all reporters for finding this.

## 1999-08-02 - 0.99
- WriteBlocked() now writes out packet type being blocked "TCP" or "UDP" in the log files.

## 1999-07-28 - 0.99
- Finally put back in the parts that correctly read IP options and added extra code to check for illegal sizes, etc. This has been a long time coming...sorry for the delay.

## 1999-07-27 - 0.98.1
- Fixed a nasty bug where an attacker could cause Sentry to ignore a scan if you have a specific configuration setup on your host. Bug reported by Reuven Gevaryahu <gevaryah@netaxs.com>.

## 1999-07-12 - 0.98
- Fixed IP parsing problems in .ignore and .blocked functions. Now correctly ignores blocked hosts and ignored hosts. Bug reported by <lindsey@mallorn.com>

## 1999-07-09 - 0.91
- Fixed corrupted readme.qa file

## 1999-06-03 - 0.90c
- Added ignore.csh script contributed by Christopher Lindsey.

## 1999-06-02 - 0.90b
- Added OSF build option.
- Added OSF KILL_ROUTE command in .conf file
- Fixed ipchains entry in .conf file.
- Updated conf file to warn about bogus route.
- Switched to native linux tcphdr/udphdr structs instead of BSD style.

## 1999-05-26 - 0.90a
- Applied patch from <lindsey@mallorn.com> to get new version to compile under older Linux distributions.
- Added AIX build option.

## 1999-05-12 - 0.90
- Found very subtle bug in SafeStrncpy that would overwrite last part of dest data with extra null outside of bounds and would intermittently corrupt data. This was a real pain and took almost six hours of testing on various platforms to track down as no debugger turned it up. I hope you people appreciate all the aggravation I go through to write this thing. ;)

## 1999-05-11 - 0.90
- Changed install dir to /usr/local/psionic/portsentry
- Updated docs again.
- Removed NeXTSTEP make rule because OS lacks vsnprintf() and I don't have a working version to put in.
- Re-Ordered #include files to prevent warnings/errors under BSD (OpenBSD)

## 1999-05-10 - 0.90
- QA checklist completed.
- Incremented version to 0.90
- Updated docs/spellcheck

## 1999-05-04 - 0.89a
- Added new trojan horse ports for TCP_PORTS:
  - 20034 - NetBus Pro
  - 5742 - Win Crash Trojan
  - 30303 - Socket De Troye
  - 40421 - Unknown Trojan Horse (Master's Paradise [CHR])

- The above were taken from a post on comp.security.unix by: jeromexxx@club-internet.fr on 05-03-99

## 1999-05-03 - 0.89
- Added $PORT$ option parsing to all kill options
- Added KILL_TCP/KILL_UDP option of "2" to allow for running a command, but not running other kill route/hosts.deny options
- Fixed another bug in the subst function that would return an empty string if nothing found instead of a string copy of the original. This was causing a string that didn't have the optional $PORT$ command to return empty.
- Moved check for BLOCKED_FILE into init function from the checkconfig function.
- Printed out corrupted config file warnings to screen and syslog instead of just syslog before aborting.
- Made QA checklist part of package in case people are interested.
- Added some more logging to kill* functions. Also added print out to log files of exact string run for route, hostsdeny, runcmd options.
- Changed BANNER to something a little shorter.
- Fixed NeXTSTEP route command entry.
 
## 1999-05-01 - 0.89
- All docs updated and code base given distribution version 0.89-BETA for release.

## 1999-04-30 - 0.80
- Fixed buggy string substitute function. It is now faster and more reliable. 
- Removed config file reading from all sub-functions and put it into InitConfig() in main executable. This cuts down on file IO during heavy activation of the probe scanner. 
- Lots of small code cleanups.

## 1999-04-14 - 0.80
- Added port 1524TCP (ingreslock) after several reports of ttdbserver overflows using this as the backdoor insertion point. 

## 1999-04-13 - 0.80
- Cleaned up more code. Moved packet classification to separate function. 
- Began regression testing.

## 1999-04-12 - 0.80
- Cleaned up lots of code. Reduced major redundant sections. 
- Eliminated redundant config file reads and moved code to inititialize variables at startup instead of during program loops.
- Added ports 635TCP, 12345TCP, 12346TCP, 31337UDP to port list. 
- Lines of code reduced by 20%.
- Removed hacked-in tcpip.h/ip.h header files and used proper Linux defines.
- Renamed package from "Abacus Sentry" to "PortSentry"

## 1998-05-28 - 0.61
- Added tcp/ip headers with distribution because some versions of Linux still use the "old" style and not the BSD variant.

## 1998-05-26 - 0.60
- Added "Smart-Verify" port profiling in all stealth modes to avoid blocking legitimate connections.

## 1998-05-25 - 0.60
- Added TCP SYN stealth scan detection
- Added TCP FIN stealth scan detection
- Added "Advanced" stealth scan detection mode.

## 1998-05-11 - 0.60
- Put in reverse DNS reporting on connections. Should have done this long ago..
- Changed history file and blocked file to write out resolved hostname on connects

## 1998-03-11 - 0.50
- FINALLY got back to work on this thing.
- Added/changed configuration option to not react to TCP/UDP probes (report only).
- Added history file to store permanent list of all blocked hosts.
- Changed blocked file to be truncated to 0 bytes on startup so users don't have to manually clean it out on re-start.
- Removed reporting of already blocked hosts for UDP to prevent possible denial of service attack. 
- Put in limit of 64 open sockets per instance (some systems did not have FD_SETSIZE defined correctly and this caused errors).
- Removed logging of connections from ignored hosts (why ignore them if I still report their connection??)
- Began renaming from "Abacus Sentry" to just plain "sentry" to eliminate confusion.
- Updated docs.
- Minor code cleanups.

## 1997-12-10 - 0.10
- Added alert for possible stealth scan detection.

## 1997-12-06 - 0.09
- Added option to skip blocking on UDP scans to prevent DOS attacks. 

## 1997-12-04 - 0.08
- Code cleanup and public alpha release.

## 1997-11-30 - 0.06
- Re-vamped config file options.
- Consolidated variables and added $TARGET$ macro expansion.
- Added option to run external command.

## 1997-11-04 - 0.05
- Added PORT_BANNER option

## 1997-11-02 - 0.04
- Bug fixes in state engine. 
- Speed enhancements.

## 1997-10-14 - 0.03
- Added state engine.

## 1997-10-13 - 0.02
- Multiple port binding.
- Config file added.
- TCP wrapper support added.

## 1997-10-12 - 0.01
- Project Begins.
