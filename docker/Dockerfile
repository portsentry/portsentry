FROM gcc:latest AS builder
RUN apt update && apt install -y build-essential libpcap-dev cmake
WORKDIR /build
COPY . .
RUN ./build.sh clean
RUN ./build.sh release

FROM scratch AS export
COPY --from=builder /build/release/portsentry /portsentry

FROM debian:stable
RUN apt update && apt install -y libpcap0.8
RUN mkdir -p /etc/portsentry
RUN mkdir -p /var/run/portsentry
COPY --from=builder /build/release/portsentry /usr/local/sbin/portsentry
COPY --from=builder /build/examples/portsentry.conf /etc/portsentry/portsentry.conf
COPY --from=builder /build/examples/portsentry.ignore /etc/portsentry/portsentry.ignore
ENTRYPOINT ["/usr/local/sbin/portsentry"]
