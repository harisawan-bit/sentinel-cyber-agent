# Sentinel (unprivileged) — the agent and the native daemon.
FROM debian:bookworm-slim AS build

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
        build-essential libssl-dev ca-certificates && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .
# Reproducible: no timestamps or paths baked into the binary.
RUN make all

# Prove the binaries work in the image before shipping them.
RUN cd /tmp && SENTINEL_HOME=/tmp/st ./src/bin/sentinel localhost --stages audit --out /tmp/o.json
RUN /src/bin/sentineld --self-test

FROM debian:bookworm-slim

RUN apt-get update -qq && \
    apt-get install -y -qq --no-install-recommends \
        libssl3 ca-certificates && \
    rm -rf /var/lib/apt/lists/* && \
    useradd --system --create-home --home-dir /home/sentinel --shell /usr/sbin/nologin sentinel

COPY --from=build /src/bin/sentinel  /usr/local/bin/sentinel
COPY --from=build /src/bin/sentineld /usr/local/bin/sentineld

# Unprivileged by default: an agent that reports on a host should not be able to
# rewrite it. Privileged paths (kernel remediation, systemd install) require
# opting in explicitly.
USER sentinel
ENV SENTINEL_HOME=/var/lib/sentinel
WORKDIR /var/lib/sentinel

# The native daemon is the resident component; the agent is the CLI.
ENTRYPOINT ["/usr/local/bin/sentinel"]
CMD ["--help"]
