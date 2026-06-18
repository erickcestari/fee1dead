# fee1dead vulnerability discovery harness.
#
# Two stages:
#   1. builder  — compiles the Rust orchestrator.
#   2. runtime  — Node + Claude Code CLI + Go + Python/uv toolchains + the Trail
#                 of Bits skills + the orchestrator binary, plus firewall
#                 tooling. The agent runs
#                 unrestricted INSIDE the container; the only real restriction
#                 is default-deny egress enforced by docker/init-firewall.sh.

# ---- builder ----------------------------------------------------------------
FROM rust:1-bookworm AS builder
WORKDIR /src
# Cache deps first.
COPY Cargo.toml Cargo.lock ./
RUN mkdir -p src && echo 'fn main() {}' > src/main.rs && \
    echo '' > src/lib.rs && cargo build --release || true
# Real sources. `touch` after COPY so cargo doesn't mistake the freshly copied
# files (which may carry older mtimes) for the cached dummy build and skip
# recompiling the crate.
COPY src ./src
COPY prompts ./prompts
COPY schema ./schema
RUN find src -name '*.rs' -exec touch {} + && \
    cargo build --release && cp target/release/fee1dead /usr/local/bin/fee1dead

# ---- runtime ----------------------------------------------------------------
FROM node:22-bookworm-slim AS runtime

# System packages: firewall tooling + minimal build/PoC toolchain + utils.
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl git jq gosu \
      iptables ipset iproute2 dnsutils \
      build-essential \
      python3 python3-pip python3-venv \
    && apt-get clean && rm -rf /var/lib/apt/lists/* \
    && ln -sf /usr/bin/python3 /usr/local/bin/python

# uv (fast Python package manager); several Trail of Bits skills invoke `uv run`.
RUN curl -LsSf https://astral.sh/uv/install.sh | env UV_INSTALL_DIR=/usr/local/bin sh

# Claude Code CLI (the default provider). Pin via build arg if you need to.
RUN npm install -g @anthropic-ai/claude-code

# Go toolchain, so hunters can compile and run PoCs against Go targets (e.g. lnd).
ARG GO_VERSION=1.23.4
RUN ARCH=$(dpkg --print-architecture) && \
    case "${ARCH}" in \
      amd64) GOARCH=amd64 ;; \
      arm64) GOARCH=arm64 ;; \
      *) echo "unsupported arch: ${ARCH}" && exit 1 ;; \
    esac && \
    curl -fsSL "https://go.dev/dl/go${GO_VERSION}.linux-${GOARCH}.tar.gz" -o /tmp/go.tgz && \
    tar -C /usr/local -xzf /tmp/go.tgz && rm /tmp/go.tgz
ENV PATH="/usr/local/go/bin:/home/agent/go/bin:${PATH}" \
    GOPATH="/home/agent/go" \
    GOCACHE="/home/agent/.cache/go-build" \
    GOFLAGS="-mod=mod"

# Non-root user the agent runs as. Built with the host's uid/gid (passed by the
# justfile) so files written to the mounted /work/out are owned by you on the
# host. `-o` allows reusing an id already taken by the base image's `node` user.
ARG HOST_UID=1000
ARG HOST_GID=1000
RUN groupadd -o -g ${HOST_GID} agent && \
    useradd -o -u ${HOST_UID} -g ${HOST_GID} --create-home --shell /bin/bash agent && \
    mkdir -p /home/agent/go /home/agent/.cache/go-build && \
    chown -R agent:agent /home/agent

# The Trail of Bits skills (vendored in the repo as a plugin marketplace:
# skills/plugins/<plugin>/skills/<skill>/SKILL.md). A bare symlink to
# ~/.claude/plugins does NOT register anything, so `claude` never exposes the
# skills and agents fall back to grepping the filesystem for SKILL.md. Instead,
# register each skill as a personal skill (~/.claude/skills/<skill>), the
# location `claude` auto-discovers, so they're invokable by name (fp-check,
# spec-to-code-compliance, …). One plugin may ship several skills.
#
# Register ONLY the skills the pipeline actually routes to: recon names
# audit-context-building/entry-point-analyzer, validate names fp-check, and the
# recon hunt allow-list (prompts/recon.md) names the rest. Every registered skill
# adds its name+description to each agent's system preamble, so keeping this list
# tight cuts per-spawn tokens and stops recon suggesting skills that don't apply.
# The full vendored suite stays in /opt/skills for reference; widen the list here
# when you widen the recon allow-list.
COPY skills /opt/skills
RUN mkdir -p /home/agent/.claude/skills && \
    for skill in \
        audit-context-building \
        entry-point-analyzer \
        fp-check \
        sharp-edges \
        insecure-defaults \
        constant-time-analysis \
        spec-to-code-compliance \
        differential-review \
        variant-analysis \
        property-based-testing; do \
        d="$(find /opt/skills/plugins -maxdepth 3 -type d -name "$skill" -print -quit)"; \
        [ -n "$d" ] || { echo "skill not found in vendored suite: $skill" >&2; exit 1; }; \
        ln -sfn "$d" "/home/agent/.claude/skills/$skill"; \
    done && \
    chown -R agent:agent /home/agent/.claude

# Orchestrator binary, prompts/schema (embedded in the binary but kept for ref),
# default config, and entry scripts.
COPY --from=builder /usr/local/bin/fee1dead /usr/local/bin/fee1dead
COPY config /opt/fee1dead/config
COPY docker/init-firewall.sh /usr/local/bin/init-firewall.sh
COPY docker/entrypoint.sh /usr/local/bin/entrypoint.sh
RUN chmod +x /usr/local/bin/init-firewall.sh /usr/local/bin/entrypoint.sh

# Work tree: mount target repo at /work/target; outputs land in /work/out.
RUN mkdir -p /work/target /work/scratch /work/out && chown -R agent:agent /work
WORKDIR /work

# Entry point runs the firewall as root, then drops to `agent` to run the
# harness. Requires `--cap-add=NET_ADMIN` at `docker run`.
ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
CMD ["run", "--config", "/opt/fee1dead/config/harness.toml"]
