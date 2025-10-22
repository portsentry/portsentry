FROM debian:stable AS builder
RUN apt update && apt install -y build-essential libpcap-dev cmake git pkg-config
WORKDIR /build
COPY . .
RUN ./build.sh clean
RUN ./build.sh release
RUN cpack --config release/CPackConfig.cmake -G DEB
RUN cpack --config release/CPackConfig.cmake -G TXZ

FROM scratch AS export
COPY --from=builder /build/release/portsentry /portsentry
COPY --from=builder /build/portsentry-*.deb /
COPY --from=builder /build/portsentry-*.tar.xz /

FROM debian:stable
RUN apt update && apt install -y libpcap0.8t64
RUN mkdir -p /etc/portsentry
RUN mkdir -p /var/run/portsentry
COPY --from=builder /build/release/portsentry /usr/local/sbin/portsentry
COPY --from=builder /build/examples/portsentry.conf /etc/portsentry/portsentry.conf
COPY --from=builder /build/examples/portsentry.ignore /etc/portsentry/portsentry.ignore
ENTRYPOINT ["/usr/local/sbin/portsentry"]
