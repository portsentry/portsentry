# Portsentry Configuration HOWTO
There are several important aspects to consider when configuring Portsentry. This document will explain the differences between the various configuration options and provide guidance on how to configure Portsentry to meet your needs.

## Optimal Linux System Configuration
In certain extreme cases when you are monitoring a large number of ports and using libpcap (the default method) you may need to increase the memory used to build the BPF filters used by portsentry in order to achieve maximum performance. Look at the log output of portsentry for the following message: "Warning: Couldn't allocate kernel memory for filter: try increasing net.core.optmem_max with sysctl". If you see this, increase the `net.core.optmem_max` value in `/etc/sysctl.conf` file until the message no longer appears.

## Command Line Options

### Modes
Portsentry can be operate in two modes: "Stealth mode" and "Connect mode". The default mode is "Stealth mode". The mode can be changed using the `--connect` or `--stealth` command line options.

#### Connect Mode [Legacy]

Connect mode uses the kernel socket API to listen for incoming packets. Connect mode is considered a legacy mode and is mainly preserved for users with very specific use-cases. For example, connect mode can be used to add a "port banner", thus sending a message to anyone connecting to a specified port. *Be aware however that Connect mode comes with several additional security implications which must be considered*. For example:
* When monitoring TCP ports, Portsentry will require a three-way TCP handshake to be completed before Portsentry registers the connection attempt. Thus, a "stealth scan attack" will go unnoticed by Portsentry.
* Additionally, other TCP protocol attacks, such as SYN floods must be taken into consideration when using Connect Mode.
* When monitoring UDP ports in connect mode, the socket API will (most likely) cause the kernel to act differently than it would when no process is bound to a port. Thus revealing the presence of Portsentry to a potential attacker. For example: Under normal circumstances, sending a UDP packet to a closed port will result in an ICMP "port unreachable" message. However, when Portsentry is running in connect mode, the kernel will not send this message. This can be used by an attacker to detect the presence of Portsentry. Note however that if a firewall is in place which will drop all unsolicited UDP packets, this might not be an issue.
* Connect mode will require Portsentry to bind to each port to be monitored individually. If you are monitoring a large number of ports you could potentially hit the max number of file descriptors allowed by the system and could also lead to performance issues. Most modern systems will allow you to increase the number of max opened file descriptors, but this is something to be aware of.

#### Stealth Mode
Stealth mode uses libpcap (or raw sockets on Linux if desired) in order to quietly listen for incoming packets on the network. The main advantage of Stealth mode is that the system gives off no indication that it is listening for incoming packets making it very difficult (if not impossible) for an attacker to detect that Portsentry is running.

#### Stealth Mode Options

##### Stealth method (libpcap vs. raw sockets)
When using Stealth mode, Portsentry can use either libpcap or raw sockets (only available on Linux). The method can be changed using the `--method` (or `-m`) command line option. The default method is libpcap. For most use-cases, libpcap is the recommended method since it takes advantage of the BSD Packet Filter (BPF) engine, which is a very efficient way to filter packets. Thus libpcap will provide you with the most efficient way to monitor incoming packets. RAW sockets (which are only available on the Linux kernel) is an alternative where libpcap is not available or not desired.

##### Libpcap Interface
When using Stealth mode with the libpcap method, Portsentry will listen on a specified network interface. The interface can be set using the `--interface` (or `-i`) command line option. The default configuration is `ALL_NLO` which is an alias which listens on all interfaces except the loopback interface. The `--interface` (or `-i`) switch will accept the following values:

* `ALL` - Listen on all interfaces (including the loopback interface) (Alias)
* `ALL_NLO` - Listen on all interfaces except the loopback interface (Alias)
* `any` - This is a special "interface" option, buil-in to libpcap. The libpcap library will attempt to listen to "all" interfaces except some special interfaces when using this option.
* `<interface>` - Listen on the specified interface. NOTE: You can specify multiple interfaces by using multipl `--interface` switches, e.g. `--interface eth0 --interface eth1`

### Logging
Portsentry can log to either `stdout` or `syslog`. The log output can be set using the `--logoutput` (or `-l`) command line option. The default log output is `stdout`.

You can enable verbose output using the `--verbose` (or `-v`) command line option. This will cause Portsentry to log additional information to the log output. You can add additional `-v` in order to increase verboseness, such as `-vvv`.

You can enable debug output using the `--debug` (or `-d`) command line option. This will cause Portsentry to become very noisy.

### Run in Background
Portsentry can be run as a daemon using the `--daemon` (or `-D`) command line option. This will cause Portsentry to fork into the background and run as a daemon. By default portsentry runs in the foreground.

### Configuration File
Portsentry can be configured using an alternative path for the configuration file. The configuration file can be set using the `--configfile` (or `-c`) command line option. The default configuration file is `/etc/portsentry/portsentry.conf`.

## Configuration File

The example portsentry configuration file (located in `examples/portsentry.conf`) contains detailed explinations of the various configuration options in the configfile.

## Ignore File

The Ignore file, `portsentry.ignore` contains a list of IP addreses and/or subnets which portsentry should **ignore** when evaluating incoming packets. See `examples/portsentry.ignore` for more information.