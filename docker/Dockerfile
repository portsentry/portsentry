FROM debian:stable
RUN apt update && apt install -y libpcap0.8
RUN mkdir -p /etc/portsentry
COPY release/portsentry /usr/local/sbin/portsentry
COPY examples/portsentry.conf /etc/portsentry/portsentry.conf
COPY examples/portsentry.ignore /etc/portsentry/portsentry.ignore
ENTRYPOINT ["/usr/local/sbin/portsentry", "--stcp"]
