FROM debian:stable
WORKDIR /usr/local/psionic/portsentry

RUN apt update
RUN apt upgrade -y
RUN apt install -y rsyslog

COPY docker/syslogportsentry.conf /etc/rsyslog.d/
COPY docker/rsyslog.conf /etc/rsyslog.conf

RUN mkdir -p /usr/local/psionic/portsentry
RUN mkdir -p /var/run/portsentry

COPY docker/entrypoint.sh /usr/local/psionic/portsentry/entrypoint.sh
COPY portsentry /usr/local/psionic/portsentry/
COPY portsentry.conf /usr/local/psionic/portsentry/
COPY portsentry.ignore /usr/local/psionic/portsentry/
RUN chmod 700 /usr/local/psionic/portsentry/entrypoint.sh
RUN chmod 600 /usr/local/psionic/portsentry/portsentry.ignore
RUN chmod 600 /usr/local/psionic/portsentry/portsentry.conf
RUN chmod 700 /usr/local/psionic/portsentry/portsentry

ENTRYPOINT [ "./entrypoint.sh" ]
CMD [ "./portsentry", "-stcp" ]
