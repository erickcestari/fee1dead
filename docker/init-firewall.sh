#!/usr/bin/env bash
# Default-deny egress firewall. Only hosts in the harness config's
# [firewall].allow list are reachable. Must run as root with NET_ADMIN before
# the agent starts. Based on the Anthropic devcontainer init-firewall pattern.
set -euo pipefail

CONFIG="${FEE1DEAD_CONFIG:-/opt/fee1dead/config/harness.toml}"

echo "[firewall] resetting rules"
iptables -F
iptables -X
iptables -t nat -F || true
iptables -t mangle -F || true

# Default deny on input/forward/output.
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

# Loopback.
iptables -A INPUT  -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Established/related return traffic.
iptables -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

# DNS is needed to resolve the allow-list hosts.
iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

# Allow-list, sourced from the harness config (single source of truth).
# Capture exit code separately so a failure isn't silently read as "empty".
FEE1DEAD_BIN="${FEE1DEAD_BIN:-/usr/local/bin/fee1dead}"
set +e
hosts_raw="$("$FEE1DEAD_BIN" firewall-hosts --config "$CONFIG" 2>/tmp/fw_err)"
rc=$?
set -e
if [[ $rc -ne 0 ]]; then
  echo "[firewall] ERROR: '$FEE1DEAD_BIN firewall-hosts --config $CONFIG' failed (exit $rc):" >&2
  cat /tmp/fw_err >&2
  exit 1
fi
mapfile -t HOSTS < <(grep -v '^[[:space:]]*$' <<<"$hosts_raw")
if [[ ${#HOSTS[@]} -eq 0 ]]; then
  echo "[firewall] ERROR: allow-list is empty in $CONFIG ([firewall].allow)" >&2
  exit 1
fi

for host in "${HOSTS[@]}"; do
  echo "[firewall] allowing $host"
  # Resolve all A records and allow HTTPS to each.
  for ip in $(getent ahostsv4 "$host" | awk '{print $1}' | sort -u); do
    iptables -A OUTPUT -p tcp -d "$ip" --dport 443 -j ACCEPT
  done
done

echo "[firewall] active (default-deny + ${#HOSTS[@]} allowed hosts)"
