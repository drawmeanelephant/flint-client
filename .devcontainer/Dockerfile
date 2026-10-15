FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04

ARG TARGETARCH
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 curl xz-utils ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Official Zig 0.17.0 archives and SHA-256 values from the release index.
# Fail closed on an unknown architecture or checksum mismatch.
RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) arch=x86_64; sha=1cbe9df9f27e6b78d14ccbca43b6703a404ef79ef1c463de901d7f088d4e2026 ;; \
      arm64) arch=aarch64; sha=9e8d11661d4ae3bd57702a3832781e23ad151dde5798e16a5ccd503f65234ff8 ;; \
      *) echo "Unsupported container architecture: ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    curl --fail --show-error --location --proto '=https' --tlsv1.2 \
      "https://ziglang.org/download/0.17.0/zig-${arch}-linux-0.17.0.tar.xz" -o /tmp/zig.tar.xz; \
    printf '%s  /tmp/zig.tar.xz\n' "${sha}" | sha256sum --check; \
    mkdir /opt/zig; \
    tar -xJf /tmp/zig.tar.xz --strip-components=1 -C /opt/zig; \
    rm /tmp/zig.tar.xz; \
    ln -s /opt/zig/zig /usr/local/bin/zig; \
    zig version
