#!/usr/bin/env bash
# Default-deny egress: only [firewall].allow hosts are reachable. Runs as root
# with NET_ADMIN. Based on Anthropic's devcontainer init-firewall.
#
# GitHub load-balances across several /20s, so a one-shot DNS pin breaks later
# clones; its published ranges come from api.github.com/meta instead.
set -euo pipefail

CONFIG="${FEE1DEAD_CONFIG:-/opt/fee1dead/config/harness.toml}"

echo "[firewall] resetting rules"
iptables -F
iptables -X
iptables -t nat -F || true
iptables -t mangle -F || true

iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT DROP

iptables -A INPUT  -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

iptables -A INPUT  -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT

ipset create allowed_v4 hash:net family inet -exist
ipset flush allowed_v4
iptables -A OUTPUT -p tcp -m set --match-set allowed_v4 dst --dport 443 -j ACCEPT

# Capture the exit code so a failure isn't read as an empty list.
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

# Enough for anycast CDNs, whose IPs don't rotate across queries.
add_host_ips() {
  local host="$1" ip count=0
  for ip in $(dig +short A "$host" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u); do
    ipset add allowed_v4 "$ip" -exist
    count=$((count + 1))
  done
  echo "[firewall] $host -> $count A record(s)"
}

# Pin curl to an allowed api.github.com IP so default-deny doesn't drop the
# meta fetch itself.
add_github_meta() {
  local ip resolve_args=()
  for ip in $(dig +short A api.github.com | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u); do
    ipset add allowed_v4 "$ip" -exist
    resolve_args+=(--resolve "api.github.com:443:$ip")
  done
  local meta
  if meta=$(curl -fsS --retry 5 --retry-all-errors --max-time 30 \
              "${resolve_args[@]}" https://api.github.com/meta 2>/dev/null); then
    # Every array-valued key is a CIDR list; take the IPv4 ones.
    local n=0 cidr
    while read -r cidr; do
      ipset add allowed_v4 "$cidr" -exist
      n=$((n + 1))
    done < <(jq -r 'to_entries[] | select(.value | type == "array") | .value[]' <<<"$meta" \
               | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+/[0-9]+$' | sort -u)
    echo "[firewall] github meta -> $n IPv4 CIDR range(s)"
  else
    echo "[firewall] WARNING: could not fetch api.github.com/meta; falling back to one-shot DNS for GitHub (clone may be flaky)" >&2
  fi
}

if printf '%s\n' "${HOSTS[@]}" | grep -qiE '(^|\.)github\.com$'; then
  add_github_meta
fi

for host in "${HOSTS[@]}"; do
  echo "[firewall] allowing $host"
  add_host_ips "$host"
done

echo "[firewall] active (default-deny + ${#HOSTS[@]} allowed hosts)"
