#!/usr/bin/env sh
PATH_BIN=${PATH_BIN:-/usr/local/sbin}
PATH_MAN=${PATH_MAN:-/usr/share/man/man8}
PATH_DOC=${PATH_DOC:-/usr/share/doc/portsentry}
PATH_ETC=${PATH_ETC:-/etc/portsentry}
PATH_SHARE=${PATH_SHARE:-/usr/local/share/portsentry}

if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

rm -f $PATH_BIN/portsentry
rm -f $PATH_MAN/portsentry.8
rm -f $PATH_MAN/portsentry.conf.8
rm -rf $PATH_DOC
rm -rf $PATH_ETC

if [ -f /etc/logrotate.d ]; then
  rm -f /etc/logrotate.d/portsentry/logrotate.conf
fi

rm -rf $PATH_SHARE

if [ -d /usr/lib/systemd/system ]; then
  rm -f /usr/lib/systemd/system/portsentry.service
fi

