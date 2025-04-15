# Fail2ban Integration

Portsentry integrates will with fail2ban and it's highly recommended to use fail2ban in cases where you want to "ban" IP addresses triggering the portsentry detection engine. The directory [fail2ban](https://github.com/portsentry/portsentry/tree/master/fail2ban) contains both an example jail file [portsentry.local](https://github.com/portsentry/portsentry/blob/master/fail2ban/portsentry.local) as well as a filter definition file [portsentry.conf](https://github.com/portsentry/portsentry/blob/master/fail2ban/portsentry.conf).

Simply copy the filter file, *portsentry.conf* into /etc/fail2ban/filter.d and copy the portsentry jail file *portsentry.local* into /etc/fail2ban/jail.d and reload fail2ban.

Note that you might need to tweak the *portsentry.local* jail file in order to suit your needs.
