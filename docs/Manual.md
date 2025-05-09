% portsentry(8) | System Manager's Manual

# NAME

**portsentry** \- Detect and respond to port scans against a target host in real\-time

# SYNOPSIS

**portsentry** \[options\]

# DESCRIPTION

Portsentry does three main things:

* It listens to TCP and/or UDP ports you specify.
* It stealthily (or visibly) logs connection attempts to the ports you have specified.
* It can optionally execute scripts or applications when connection attempts are made.

The most common use\-case for Portsentry is to block unwanted service enumeration attempts against your host. This could be accomplished by simply listening to a wide variety of **unused** ports and block all connection attempts to those ports. Portsentry can also be deployed as a Network Intrusion Detection System (NIDS). By listening to unused ports on your internal networks, you will be notified as soon as a potential attacker tries to scan for services within your organization. A more detailed explanation and guide of the various uses of portsentry, refer to the [HOWTO-Use](https://github.com/portsentry/portsentry/blob/master/docs/HOWTO-Use.md) guide.



# OPTIONS

## \-\-stealth

Stealth mode **(default)** uses libpcap (or raw sockets on Linux if desired, see the **\-m** option) in order to quietly listen for incoming packets on the network. The main advantage of Stealth mode is that the system gives off no indication that it is listening for incoming packets making it very difficult (if not impossible) for an attacker to detect that Portsentry is running.

## \-\-connect
Connect mode **(legacy option)** uses the kernel socket API to listen for incoming packets. Connect mode is considered a legacy mode and is mainly preserved for users with very specific use\-cases. For example, connect mode can be used to add a "port banner", thus sending a message to anyone connecting to a specified port. Be aware however that connect mode comes with several additional security implications which must be considered. For example:

* When monitoring TCP ports, Portsentry will require a three\-way TCP handshake to be completed before Portsentry registers the connection attempt. Thus, a "stealth scan attack" will go unnoticed by Portsentry.
* Additionally, other TCP protocol attacks, such as SYN floods must be taken into consideration when using Connect Mode.
* Connect mode will require Portsentry to bind to each port to be monitored individually. If you are monitoring a large number of ports you could potentially hit the max number of file descriptors allowed by the system and could also lead to performance issues. Most modern systems will allow you to increase the number of max opened file descriptors, but this is something to be aware of.

## Stealth Mode Options

This section covers options only relevant when Stealth mode **\-\-stealth** is used.

### \-m, \-\-method=pcap|raw
**This option is only relevant on Linux**. It sets the sentry method to use in stealth mode. Can be set to use either **pcap** or Linux **raw** sockets. **(default: pcap)**

* **pcap**: Uses the libpcap library to listen for incoming packets. This is the default method and is recommended for most use-cases.
* **raw**: Uses the Linux raw socket API to listen for incoming packets. This method is less efficient than pcap and is not recommended unless you have a specific use-case where pcap is not available or not desired.

### \-i, \-\-interface=ALL|ALL_NLO|\<interface\>

**This option is only relevant when pcap mode is used**. Specify interface(s) to listen on. You can either specify an "interface alias or a specific interface:

* `ALL` - Listen on all interfaces (including the loopback interface) (Alias)
* `ALL_NLO` - Listen on all interfaces except the loopback interface (Alias)
* `any` - This is a special "interface" option, built-in to libpcap. The libpcap library will attempt to listen to "all" interfaces except some special interfaces when using this option.
* `<interface>` - Listen on the specified interface. NOTE: You can specify multiple interfaces by using multiple `--interface` switches, e.g. `--interface eth0 --interface eth1`

## Generic Options

These options can be used regardless of mode used.

### \-L, \-\-disable\-local\-check

Under normal operations; if Portsentry detects traffic with the same source and destination IP address, no logging or actions are performed. This is to prevent Portsentry from potentially taking actions on itself. This option disables this logic. I.e, logging and actions are taken on the host on which Portsentry is run. Use this option with care.

### \-l, \-\-logoutput=stdout|syslog

Portsentry can log to either `stdout` or `syslog`. The log output can be set using the `--logoutput` (or `-l`) command line option. The default log output is `stdout`.

### \-c, \-\-configfile=path

Portsentry can be configured using an alternative path for the configuration file. The configuration file can be set using the `--configfile` (or `-c`) command line option. The default configuration file is `/etc/portsentry/portsentry.conf`. See portsentry.conf(8) for more information.

### \-D, \-\-daemon

Portsentry can be run as a daemon using the `--daemon` (or `-D`) command line option. This will cause Portsentry to fork into the background and run as a daemon. By default portsentry runs in the foreground.

### \-d, \-\-debug

Enable debug output using the `--debug` (or `-d`) command line option. This will cause Portsentry to become very noisy.

### \-v, \-\-verbose

Enable verbose output using the `--verbose` (or `-v`) command line option. This will cause Portsentry to log additional information to the log output.

### \-h, \-\-help

Display command line help message

### \-V, \-\-version

Display version information

## EXAMPLES

Review the [HOWTO-Use](https://github.com/portsentry/portsentry/blob/master/docs/HOWTO-Use.md) guide for detailed setup scenarios and configuration guides.

## FILES

/etc/portsentry/portsentry.conf

/etc/portsentry/portsentry.ignore

/var/log/portsentry.log

/tmp/portsentry.blocked

## BUGS

All bugs should be reported via the portsentry github issue tracker https://github.com/portsentry/portsentry/issues

## AUTHORS

Marcus Hufvudsson <mh@protohuf.com>

## SEE ALSO

portsentry.conf(8)

## LICENSE

Portsentry is licensed under the Common Public License v1.0 
