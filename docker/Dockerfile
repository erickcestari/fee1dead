# fee1dead image. The agent runs unrestricted inside; the only real
# restriction is the default-deny egress firewall (docker/init-firewall.sh).

# ---- builder ----------------------------------------------------------------
FROM rust:1-bookworm AS builder
WORKDIR /src
# Build deps against a dummy crate so they cache across source changes.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs && \
    echo '' > src/lib.rs && cargo build --release || true
# Copied files may be older than the dummy build; touch them so cargo rebuilds.
COPY src ./src
COPY prompts ./prompts
COPY schema ./schema
RUN find src -name '*.rs' -exec touch {} + && \
    cargo build --release && cp target/release/fee1dead /usr/local/bin/fee1dead

# ---- runtime ----------------------------------------------------------------
FROM node:22-bookworm-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git jq gosu \
      iptables ipset iproute2 dnsutils \
      build-essential \
      python3 python3-pip python3-venv \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/python3 /usr/local/bin/python

# Several Trail of Bits skills invoke `uv run`.
RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh

ARG CLAUDE_CODE_VERSION=2.1.280
RUN npm install -g @anthropic-ai/claude-code@${CLAUDE_CODE_VERSION}

ARG OPENCODE_VERSION=1.18.11
RUN npm install -g opencode-ai@${OPENCODE_VERSION}

# rtk compresses dev-command output to cut agent tokens; wired in below.
ARG RTK_VERSION=v0.43.0
RUN curl -fsSL https://raw.githubusercontent.com/rtk-ai/rtk/refs/heads/master/install.sh \
      | env RTK_INSTALL_DIR=/usr/local/bin RTK_VERSION=${RTK_VERSION} sh

# Keep GO_VERSION at or above every target's `go` directive.
ARG GO_VERSION=1.26.5
RUN ARCH=$(dpkg --print-architecture) && \
    case "${ARCH}" in \
      amd64) GOARCH=amd64 ;; \
      arm64) GOARCH=arm64 ;; \
      *) echo "unsupported arch: ${ARCH}" && exit 1 ;; \
    esac && \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" -o /tmp/go.tgz && \
    tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz
# GOTOOLCHAIN=local: a target needing a newer Go fails loudly instead of
# every hunter downloading a toolchain through the firewall.
ENV PATH="/usr/local/go/bin:/home/agent/go/bin:${PATH}" \
    GOPATH="/home/agent/go" \
    GOMODCACHE="/home/agent/go/pkg/mod" \
    GOCACHE="/home/agent/.cache/go-build" \
    GOTOOLCHAIN="local" \
    GOFLAGS="-mod=mod"

# The host's uid/gid, so files in the mounted /work/out are yours. `-o`: the
# base image's `node` user may already hold the id.
ARG HOST_UID=1000
ARG HOST_GID=1000
RUN groupadd -o -g ${HOST_GID} agent && \
    useradd -o -u ${HOST_UID} -g ${HOST_GID} --create-home --shell /bin/bash agent && \
    mkdir -p /home/agent/go/pkg/mod /home/agent/.cache/go-build && \
    chown -R agent:agent /home/agent

# Register the pipeline's skills as personal skills so `claude` exposes them by
# name. Only these: each one adds to every agent's system prompt. Keep the list
# in sync with the allow-list in prompts/recon.md (plus fp-check for validate).
COPY skills /opt/skills
RUN mkdir -p /home/agent/.claude/skills && \
    for skill in \
        audit-context-building \
        fp-check \
        sharp-edges \
        insecure-defaults \
        constant-time-analysis \
        spec-to-code-compliance \
        differential-review \
        variant-analysis \
        property-based-testing; do \
        d="$(find /opt/skills/plugins -type d -path "*/skills/$skill" -print -quit)"; \
        [ -n "$d" ] || { echo "skill not found in vendored suite: $skill" >&2; exit 1; }; \
        ln -sfn "$d" "/home/agent/.claude/skills/$skill"; \
    done && \
    chown -R agent:agent /home/agent/.claude

# Installs rtk's Bash rewrite hook into the agent's Claude Code config.
RUN gosu agent env HOME=/home/agent rtk init -g --auto-patch && \
    chown -R agent:agent /home/agent/.claude

COPY --from=builder /usr/local/bin/fee1dead /usr/local/bin/fee1dead
COPY config /opt/fee1dead/config
COPY docker/init-firewall.sh /usr/local/bin/init-firewall.sh
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/init-firewall.sh /usr/local/bin/entrypoint.sh

RUN mkdir -p /work/target /work/scratch /work/out && chown -R agent:agent /work
WORKDIR /work

# Needs `--cap-add=NET_ADMIN` for the firewall.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["run", "--config", "/opt/fee1dead/config/harness.toml"]
