# Howto Install and Setup Guide

## Choosing a Deployment Method

Portsentry is available on Linux, OpenBSD, NetBSD and FreeBSD. The [../README](README.md) file lists the installation options for the various distributions and/or operating systems

## Setup

Once Portsentry is installed, you need to configure it. The configuration file is located in **/etc/portsentry/portsentry.conf**. The default configuration file provides a well rounded start position and is well documented and should be easy to understand.

More documentation and in-depth discusson on the configuration can be found in the [portsentry.conf.md](portsentry.conf.md) manual. You can also use **man portsentry.conf** to read the manual page for the configuration file.

## Running Portsentry

By default, portsentry is started via the OS init system. On Linux, this is done via _systemd_.

You can check the status of Portsentry by running:

```bash
sudo systemctl status portsentry
```

Use journalctl to view the Portsentry system log:

```bash
sudo journalctl -u portsentry
```

## Portsentry Logfile

Portsentry logs all activity to the **/var/log/portsentry.log** file. Refer to the [HOWTO-Logfile.md](HOWTO-Logfile.md) for more information on how the log file format is structured. You can view the log file by running the following command:

```bash
sudo tail -f /var/log/portsentry.log
```

## Fail2ban Integration

Fail2ban is a log-parsing tool that can be used to block IP addresses that are detected by its parsing engine. It incorporates many costomizable features which makes it a flexible and powerful tool for protecting your server from malicious activity. Portsentry can be configured to work with Fail2ban in order to take advantage of Fail2ban's excellent capabilities.

* Download fail2ban for your platform [https://github.com/fail2ban/fail2ban](https://github.com/fail2ban/fail2ban)
* Download the [portsentry fail2ban filter file](https://github.com/portsentry/portsentry/blob/master/fail2ban/portsentry.conf) and place it in the **/etc/fail2ban/filter.d/** directory.
* Download the [portsentry fail2ban jail file](https://github.com/portsentry/portsentry/blob/master/fail2ban/portsentry.local) and place it in the **/etc/fail2ban/jail.d/** directory.
* Tweak the jail file to your liking, such as setting the ban time, find time, and max retry values.
* Restart the fail2ban service to apply the changes:

```bash
sudo systemctl restart fail2ban
```
