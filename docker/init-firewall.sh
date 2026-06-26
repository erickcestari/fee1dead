#!/usr/bin/env bash
# Default-deny egress firewall. Only hosts in the harness config's
# [firewall].allow list are reachable. Must run as root with NET_ADMIN before
# the agent starts. Based on the Anthropic devcontainer init-firewall pattern.
#
# Allowed destinations live in an ipset (hash:net) so we can mix individual
# resolved IPs and published CIDR ranges. GitHub is the important case: it does
# DNS-based load balancing across several distinct /20 blocks, so pinning the
# single IP resolved at setup time fails when git later resolves to a different
# one in the pool (silent DROP -> connect timeout). We pull GitHub's ranges from
# api.github.com/meta instead of trusting a one-shot lookup.
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

# Single allow-set of permitted HTTPS destinations (IPs and CIDRs).
ipset create allowed_v4 hash:net family inet -exist
ipset flush allowed_v4
iptables -A OUTPUT -p tcp -m set --match-set allowed_v4 dst --dport 443 -j ACCEPT

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

# Resolve a host's A records into the allow-set. Good enough for anycast CDNs
# (Fastly, Google, Cloudflare) whose IPs don't rotate across queries.
add_host_ips() {
  local host="$1" ip count=0
  for ip in $(dig +short A "$host" | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u); do
    ipset add allowed_v4 "$ip" -exist
    count=$((count + 1))
  done
  echo "[firewall] $host -> $count A record(s)"
}

# Add GitHub's full published IPv4 ranges so clone/fetch survives GitHub's
# DNS load balancing. Bootstrap the meta fetch by pinning curl to an allowed
# api.github.com IP, so our own default-deny doesn't drop the request.
add_github_meta() {
  local ip resolve_args=()
  for ip in $(dig +short A api.github.com | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | sort -u); do
    ipset add allowed_v4 "$ip" -exist
    resolve_args+=(--resolve "api.github.com:443:$ip")
  done
  local meta
  if meta=$(curl -fsS --retry 5 --retry-all-errors --max-time 30 \
              "${resolve_args[@]}" https://api.github.com/meta 2>/dev/null); then
    # Every array-valued key (web, api, git, pages, packages, actions, ...) is
    # a list of CIDRs; take the IPv4 ones. Future-proof against new key names.
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

# Pull GitHub ranges if any GitHub host is in the allow-list.
if printf '%s\n' "${HOSTS[@]}" | grep -qiE '(^|\.)github\.com$'; then
  add_github_meta
fi

for host in "${HOSTS[@]}"; do
  echo "[firewall] allowing $host"
  add_host_ips "$host"
done

echo "[firewall] active (default-deny + ${#HOSTS[@]} allowed hosts)"
