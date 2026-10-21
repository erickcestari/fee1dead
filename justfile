# fee1dead task runner. Run `just` to list recipes.

# Optional .env with ANTHROPIC_API_KEY or CLAUDE_CODE_OAUTH_TOKEN.
set dotenv-load := true

image := "fee1dead"
# Mounted read-only at /work/target.
target := justfile_directory() / "target-repo"
# Mounted at /work/out.
out := justfile_directory() / "out"
# Mounted, so edits need no rebuild.
config := justfile_directory() / "config" / "harness.toml"
# `-e VAR` forwards only what is set.
auth := "-e ANTHROPIC_API_KEY -e CLAUDE_CODE_OAUTH_TOKEN"

# List available recipes.
default:
    @just --list

# --- local development -------------------------------------------------------

# Compile the orchestrator.
build:
    cargo build --release

# Run unit + offline end-to-end tests (mock provider, no network).
test:
    cargo test --features mock-runner

# Validate the config without running the pipeline.
check:
    cargo run --quiet -- check --config {{config}}

# --- docker ------------------------------------------------------------------

# opencode's credentials and cache; empty with claude-code.
opencode_mounts := '-v "$HOME/.local/share/opencode":/home/agent/.local/share/opencode -v "$HOME/.cache/opencode":/home/agent/.cache/opencode'

# Build the image with the host uid/gid, so out/ stays yours. The dirty check
# covers the same inputs as build.rs.
image:
    docker build -t {{image}} \
      --build-arg HOST_UID="$(id -u)" \
      --build-arg HOST_GID="$(id -g)" \
      --build-arg FEE1DEAD_SHA="$(git rev-parse HEAD)$(git diff --quiet HEAD -- src prompts schema Cargo.toml Cargo.lock || echo -dirty)" \
      -f docker/Dockerfile .

# Run the pipeline against `target` (default ./target-repo).
run: image
    @test -d "{{target}}" || (echo "target repo not found: {{target}}  (set with 'just run target=/path')" && exit 1)
    @mkdir -p "{{out}}" "$HOME/.local/share/opencode" "$HOME/.cache/opencode"
    docker run --rm \
      --cap-add=NET_ADMIN \
      {{auth}} \
      -v "$(realpath '{{target}}')":/work/target:ro \
      -v "$(realpath '{{out}}')":/work/out \
      -v "$(realpath '{{config}}')":/opt/fee1dead/config/harness.toml:ro \
      {{opencode_mounts}} \
      {{image}}

# Run against a repo the harness clones itself (needs [target].repo in config).
run-clone: image
    @mkdir -p "{{out}}" "$HOME/.local/share/opencode" "$HOME/.cache/opencode"
    docker run --rm \
      --cap-add=NET_ADMIN \
      {{auth}} \
      -v "$(realpath '{{out}}')":/work/out \
      -v "$(realpath '{{config}}')":/opt/fee1dead/config/harness.toml:ro \
      {{opencode_mounts}} \
      {{image}}

# Continue the last run in `out`, skipping recon. Mounts `target` if present.
resume: image
    @mkdir -p "{{out}}" "$HOME/.local/share/opencode" "$HOME/.cache/opencode"
    docker run --rm \
      --cap-add=NET_ADMIN \
      {{auth}} \
      $([ -d "{{target}}" ] && echo "-v $(realpath '{{target}}'):/work/target:ro") \
      -v "$(realpath '{{out}}')":/work/out \
      -v "$(realpath '{{config}}')":/opt/fee1dead/config/harness.toml:ro \
      {{opencode_mounts}} \
      {{image}} run --resume --config /opt/fee1dead/config/harness.toml

# Run with the egress firewall disabled (local debugging only).
run-nofw: image
    @test -d "{{target}}" || (echo "target repo not found: {{target}}" && exit 1)
    @mkdir -p "{{out}}" "$HOME/.local/share/opencode" "$HOME/.cache/opencode"
    docker run --rm \
      --cap-add=NET_ADMIN \
      {{auth}} \
      -e FEE1DEAD_SKIP_FIREWALL=1 \
      -v "$(realpath '{{target}}')":/work/target:ro \
      -v "$(realpath '{{out}}')":/work/out \
      -v "$(realpath '{{config}}')":/opt/fee1dead/config/harness.toml:ro \
      {{opencode_mounts}} \
      {{image}}

# Open an interactive shell in the image (firewall not started).
shell: image
    docker run --rm -it \
      --cap-add=NET_ADMIN \
      {{auth}} \
      -v "$(realpath '{{target}}')":/work/target:ro \
      -v "$(realpath '{{out}}')":/work/out \
      -v "$(realpath '{{config}}')":/opt/fee1dead/config/harness.toml:ro \
      {{opencode_mounts}} \
      --entrypoint /bin/bash \
      {{image}}

# Remove the built image.
clean-image:
    -docker image rm {{image}}
