# syntax=docker/dockerfile:1

FROM ubuntu:24.04 AS builder

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    ca-certificates \
    cmake \
    curl \
    liburing-dev \
    pkg-config \
    && rm -rf /var/lib/apt/lists/*

ARG LLAM_VERSION=2.0.0
ARG LLAM_BASE_URL=https://github.com/Feralthedogg/LLAM/releases/download/v2.0.0
ARG LLAM_TARGET=

RUN set -eu; \
    LLAM_INSTALL_ARGS="--version ${LLAM_VERSION} --base-url ${LLAM_BASE_URL} --prefix /usr/local"; \
    if [ -n "${LLAM_TARGET}" ]; then \
        LLAM_INSTALL_ARGS="${LLAM_INSTALL_ARGS} --target ${LLAM_TARGET}"; \
    fi; \
    curl -fsSL "${LLAM_BASE_URL}/install.sh" | sh -s -- ${LLAM_INSTALL_ARGS}

WORKDIR /src/LLPS
COPY CMakeLists.txt ./
COPY include/ ./include/
COPY src/ ./src/
COPY bench/ ./bench/
COPY config.yml ./config.yml

RUN cmake -S . -B /tmp/llps-build \
      -DCMAKE_BUILD_TYPE=Release \
      -DBUILD_TESTING=OFF \
      -DCMAKE_PREFIX_PATH=/usr/local \
    && cmake --build /tmp/llps-build -j"$(nproc)" \
    && mkdir -p /opt/llps \
    && cp /tmp/llps-build/llps /opt/llps/llps \
    && cc -O2 -Wall -Wextra -Wpedantic -Werror -o /opt/llps/native_sink bench/native_sink.c \
    && cc -O2 -Wall -Wextra -Wpedantic -Werror -o /opt/llps/native_load bench/native_load.c

FROM python:3.12-slim AS chat-target

WORKDIR /opt/llps-tools
COPY tools/chat_server.py ./chat_server.py

EXPOSE 25566/tcp

USER 10001:10001

ENTRYPOINT ["python3", "/opt/llps-tools/chat_server.py", "--host", "0.0.0.0", "--port", "25566"]

FROM python:3.12-slim AS smoke-client

WORKDIR /opt/llps-tools
COPY tools/chat_client.py ./chat_client.py

USER 10001:10001

ENTRYPOINT ["python3", "/opt/llps-tools/chat_client.py"]

FROM ubuntu:24.04 AS bench-sink

COPY --from=builder /opt/llps/native_sink /usr/local/bin/native_sink

EXPOSE 25566/tcp

USER 10001:10001

ENTRYPOINT ["/usr/local/bin/native_sink"]

FROM ubuntu:24.04 AS bench-load

COPY --from=builder /opt/llps/native_load /usr/local/bin/native_load

USER 10001:10001

ENTRYPOINT ["/usr/local/bin/native_load"]

FROM ubuntu:24.04 AS runtime

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    libc6 \
    libgcc-s1 \
    liburing2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /usr/local/lib/ /usr/local/lib/
COPY --from=builder /opt/llps/llps /opt/llps/llps
COPY config.yml /etc/llps/config.example.yml
COPY docker/entrypoint.sh /usr/local/bin/llps-docker-entrypoint

RUN groupadd --gid 10001 llps \
    && useradd --uid 10001 --gid llps --home-dir /nonexistent --shell /usr/sbin/nologin llps \
    && chmod +x /usr/local/bin/llps-docker-entrypoint \
    && ldconfig

EXPOSE 25565/tcp

USER llps:llps

HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD bash -ec 'exec 3<>/dev/tcp/127.0.0.1/${LLPS_LISTEN_PORT:-25565}' || exit 1

ENTRYPOINT ["/usr/local/bin/llps-docker-entrypoint"]
