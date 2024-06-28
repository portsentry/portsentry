FROM debian:stable-slim
WORKDIR /usr/local/sbin

RUN apt update
RUN apt upgrade -y
RUN apt install -y rsyslog

COPY docker/syslogportsentry.conf /etc/rsyslog.d/
COPY docker/rsyslog.conf /etc/rsyslog.conf

RUN mkdir -p /etc/portsentry
RUN mkdir -p /var/run/portsentry

COPY docker/entrypoint.sh /usr/local/sbin/
COPY portsentry /usr/local/sbin/
COPY portsentry.conf /etc/portsentry/
COPY portsentry.ignore /etc/portsentry/
RUN chmod 700 /usr/local/sbin/entrypoint.sh
RUN chmod 700 /usr/local/sbin/portsentry
RUN chmod 600 /etc/portsentry/portsentry.ignore
RUN chmod 600 /etc/portsentry/portsentry.conf

ENTRYPOINT [ "./entrypoint.sh" ]
CMD [ "./portsentry", "-stcp" ]
