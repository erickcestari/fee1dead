#!/usr/bin/env bash
# As root: run [target].setup, bring up the firewall. Then exec `fee1dead "$@"`
# as `agent`.
set -euo pipefail

export FEE1DEAD_CONFIG="${FEE1DEAD_CONFIG:-/opt/fee1dead/config/harness.toml}"

# Only before `run`: setup can take minutes.
if [[ "${1:-}" == "run" ]]; then
  started="$(mktemp)"
  # /work/target is agent-owned, so root's git would reject it as dubious.
  HOME=/home/agent \
    GIT_CONFIG_COUNT=1 GIT_CONFIG_KEY_0=safe.directory GIT_CONFIG_VALUE_0='*' \
    /usr/local/bin/fee1dead setup --config "$FEE1DEAD_CONFIG"
  # Hand what setup created back to the agent. ctime also catches extracted
  # archives; -xdev leaves bind mounts alone.
  find /work /home/agent -xdev -cnewer "$started" ! -user agent \
    -exec chown -h agent:agent {} +
  rm -f "$started"
fi

if [[ "${FEE1DEAD_SKIP_FIREWALL:-0}" != "1" ]]; then
  if /usr/local/bin/init-firewall.sh; then
    echo "[entrypoint] firewall up"
  else
    echo "[entrypoint] firewall failed (need --cap-add=NET_ADMIN?)" >&2
    exit 1
  fi
else
  echo "[entrypoint] WARNING: firewall skipped (FEE1DEAD_SKIP_FIREWALL=1)"
fi

# gosu keeps root's HOME; claude reads its config from $HOME/.claude.
export HOME=/home/agent
exec gosu agent env HOME=/home/agent /usr/local/bin/fee1dead "$@"
