#!/usr/bin/env bash
# Bring up the egress firewall as root, then drop to the unprivileged `agent`
# user to run the harness. All args are passed through to `fee1dead`.
set -euo pipefail

export FEE1DEAD_CONFIG="${FEE1DEAD_CONFIG:-/opt/fee1dead/config/harness.toml}"

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

# Drop privileges and exec the harness. gosu keeps the current environment, so
# set HOME explicitly: claude reads its config, auth, and plugins from
# $HOME/.claude, which lives under the agent user's home.
export HOME=/home/agent
exec gosu agent env HOME=/home/agent /usr/local/bin/fee1dead "$@"
