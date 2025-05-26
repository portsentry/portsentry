# Howto Install and Setup Guide

## Choosing a Deployment Method

**At the time of writing, Portsentry has limited deployment options due to the fact that the project has just recently been relaunched. More deployment options are next on the roadmap and will be comming soon.**

Your current options are:

* Docker - This is the recommeded deployment option if you have Docker available. Refer to rhe [HOWTO-Docker.md](HOWTO-Docker.md) guide for more information.
* Precompiled Linux Binaries - Download Portsentry from the [releases](https://github.com/portsentry/portsentry/releases) page. Extract and run the installer script by typing **sudo ./install.sh**
* Compile from source - If you are using a system that is not supported by the precompiled binaries, you can compile Portsentry from source. Refer to the [HOWTO-Compile.md](HOWTO-Compile.md) guide for more information.

## Setup

Once Portsentry is installed, you need to configure it. The configuration file is located in **/etc/portsentry/portsentry.conf**. The default configuration file is well documented and should be easy to understand. More documentation and in-depth discusson on the configuration can be found in the [portsentry.conf.md](portsentry.conf.md) manual. You can also use **man portsentry.conf** to read the manual page for the configuration file.

## Running Portsentry

### Running in a Terminal

You can run Portsentry directly in your terminal to get a feel for it. Simply run the following command:

```bash
sudo portsentry
```

This will start Portsentry in the foreground and you will see the output in your terminal. You can stop Portsentry by pressing **Ctrl+C**.

### Systemd

Portsentry comes with a systemd service file which is installed during installation. To enable the Portsentry service to start on boot, you can run the following command:

```bash
sudo systemctl enable portsentry
```

You can start Portsentry by running the following command:

```bash
sudo systemctl start portsentry
```

You can check the status of Portsentry by running:

```bash
sudo systemctl status portsentry
```

You the journalctl command to view the Portsentry system log:

```bash
sudo journalctl -u portsentry
```

## Portsentry Logfile

Portsentry logs all activity to the **/var/log/portsentry.log** file. Refer to the [HOWTO-Logfile.md](HOWTO-Logfile.md) for more information on how the log file format is structured. You can view the log file by running the following command:

```bash
sudo tail -f /var/log/portsentry.log
```

## Fail2ban Integration

Fail2ban is a log-parsing tool that can be used to block IP addresses that are attempting to brute-force your services. Fail2ban incorporates many costomizable features which makes it a flexible and powerful tool for protecting your server from malicious activity. Portsentry can be configured to work with Fail2ban in order to take advantage of Fail2ban's excellent blocking capabilities.

* Download fail2ban for your platform [https://github.com/fail2ban/fail2ban](https://github.com/fail2ban/fail2ban)
* Download the [portsentry fail2ban filter file](https://github.com/portsentry/portsentry/blob/master/fail2ban/portsentry.conf) and place it in the **/etc/fail2ban/filter.d/** directory.
* Download the [portsentry fail2ban jail file](https://github.com/portsentry/portsentry/blob/master/fail2ban/portsentry.local) and place it in the **/etc/fail2ban/jail.d/** directory.
* Tweak the jail file to your liking, such as setting the ban time, find time, and max retry values.
* Restart the fail2ban service to apply the changes:

```bash
sudo systemctl restart fail2ban
```

