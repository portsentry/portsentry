#!/usr/bin/env sh
PATH_BIN=${PATH_BIN:-/usr/local/bin}
PATH_MAN=${PATH_MAN:-/usr/share/man/man8}
PATH_DOC=${PATH_DOC:-/usr/share/doc/portsentry}
PATH_ETC=${PATH_ETC:-/etc/portsentry}
PATH_SHARE=${PATH_SHARE:-/usr/local/share/portsentry}

if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

# Install binary
install -m 755 -d $PATH_BIN
install -m 755 portsentry $PATH_BIN/portsentry

# Install man pages
install -m 644 -d $PATH_MAN
install -m 644 docs/portsentry.8 $PATH_MAN/portsentry.8
install -m 644 docs/portsentry.conf.8 $PATH_MAN/portsentry.conf.8

# Install documentation
install -m 644 -d $PATH_DOC
cp -rf docs $PATH_DOC
chown -R root:root $PATH_DOC
chmod -R 644 $PATH_DOC

# Install config files
install -m 755 -d $PATH_ETC
install -m 644 -o root -g root examples/portsentry.conf $PATH_ETC/portsentry.conf
install -m 644 -o root -g root examples/portsentry.ignore $PATH_ETC/portsentry.ignore

if [ -d /etc/logrotate.d ]; then
  install -m 644 -o root -g root examples/logrotate.conf /etc/logrotate.d/portsentry
fi

# Install fail2ban config files
install -m 644 -d $PATH_SHARE
install -m 644 -d $PATH_SHARE/fail2ban
install -m 644 fail2ban/portsentry.conf $PATH_SHARE/fail2ban/portsentry.conf
install -m 644 fail2ban/portsentry.local $PATH_SHARE/fail2ban/portsentry.local

install -m 644 Changes.md $PATH_SHARE/Changes.md
install -m 644 README.md $PATH_SHARE/README.md
install -m 644 LICENSE $PATH_SHARE/LICENSE

# Install systemd service file
if [ -d /usr/lib/systemd/system ]; then
  install -m 644 -o root -g root init/portsentry.service /usr/lib/systemd/system/portsentry.service
fi
