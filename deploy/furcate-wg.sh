#!/bin/sh
# Apply an overlay peer set on behalf of an unprivileged agent.
#
# Creating a network interface is a net-admin operation. The agent does not hold
# that capability and giving it one to save a file write would repeat a mistake
# this host has now avoided five times — the energy counters, the management
# controller, the interface wake setting and the disks all went the same way.
# So the agent computes what should change and this applies it.
#
# ## The private key never leaves this side
#
# The agent writes peers, endpoints and addresses. It never writes, reads or
# holds the interface's private key: that is generated here on first run, stored
# mode 0600, and only its public half is handed back for the agent to publish.
# An agent that could read it could impersonate the node on the overlay, and
# there is no reason for it to be able to.
#
# ## Or: a key that lives for one lease and is never written
#
# With FURCATE_OVERLAY_EPHEMERAL=1 in this unit's environment there is no key
# file. The X25519 key is generated in memory when the interface is created,
# which is every boot, and again before each lease of FURCATE_OVERLAY_LEASE
# seconds (default 43200) runs out. `wg genkey` writes it into a pipe and
# `wg set ... private-key /dev/stdin` reads it from that pipe into the kernel:
# it is never a file, never an argument, and never in this script's variables.
# The kernel holds it until the next lease replaces it.
#
# The agent learns the public half, the time it was made and the lease from
# the report below, and has the node's hardware key sign a binding over them.
# Peers believe the key because of that binding, and stop believing it when
# the lease ends. The setting lives here and not in the plan, so the agent
# cannot switch a node between the two custodies. Nodes without the setting
# keep their key file exactly as before.
#
# ## Changes are applied one at a time
#
# `wg setconf` replaces the whole configuration and tears down every session on
# the interface. A node that gained one peer should not lose the others while
# that happens, so ordinary changes go through `wg set`, which does not disturb
# what it is not changing.
#
# Plan format, one directive per line, written atomically by the agent:
#   iface=<name>
#   address=<cidr>
#   port=<n>
#   peer=<pubkey> <allowed-ip> [endpoint] [keepalive]
#   remove=<pubkey>
#
# Anything else is ignored rather than guessed at.
set -eu

# Outside the agent's home, deliberately.
#
# This unit holds CAP_NET_ADMIN and nothing else, and dropping the rest of the
# bounding set costs root its CAP_DAC_OVERRIDE — so ordinary permissions apply,
# and a home directory at mode 750 is one this service genuinely cannot
# traverse. That is the confinement working, not a bug in it.
#
# The alternatives were adding CAP_DAC_OVERRIDE, which is the ability to ignore
# every permission on the system, or moving one file. This is the file moving.
PLAN="${FURCATE_WG_PLAN:-/var/lib/furcate/wg-plan}"
STATE="${FURCATE_WG_STATE:-/run/furcate/wg.json}"
# /etc/wireguard, not somewhere of our own choosing.
#
# Ubuntu confines `wg` with an AppArmor profile that permits reading key
# material from the conventional location and nothing else. A key under
# /etc/furcate is refused with `fopen: Permission denied` even as root, and the
# denial appears in the audit log rather than anywhere the operator is looking:
#   apparmor="DENIED" profile="wg" name="/etc/furcate/fur0.key" denied_mask="r"
#
# The fix is the path, not the profile. Relaxing a confinement to store a
# private key somewhere less conventional would be a poor trade, and it is the
# same trade this host has already declined for netlink, for the TPM and for
# block devices.
KEYDIR="${FURCATE_WG_KEYDIR:-/etc/wireguard}"
IFACE_DEFAULT=fur0
# Present while an approved `isolate` order is in force. The order actuator
# writes and removes it; this only reads it.
ISOLATED="${FURCATE_STATE_DIR:-/var/lib/furcate}/isolated"
EPHEMERAL="${FURCATE_OVERLAY_EPHEMERAL:-0}"
LEASE="${FURCATE_OVERLAY_LEASE:-43200}"
INTERVAL="${FURCATE_WG_INTERVAL:-5}"
# Passes before exiting; 0 is forever. For tests: a service never sets it.
PASSES="${FURCATE_WG_PASSES:-0}"

case "$EPHEMERAL" in
  0|1) ;;
  *) echo "furcate-wg: FURCATE_OVERLAY_EPHEMERAL is '$EPHEMERAL'; it must be 0 or 1, and which key custody was meant is not something to guess" >&2; exit 1 ;;
esac
case "$LEASE" in
  ''|*[!0-9]*|0) echo "furcate-wg: FURCATE_OVERLAY_LEASE is '$LEASE'; it must be a whole number of seconds above zero" >&2; exit 1 ;;
esac
# A new key goes in this long before the old lease ends, so its binding has
# spread before the old one lapses: a tenth of the lease, at most ten minutes.
AHEAD=$(( LEASE / 10 ))
[ "$AHEAD" -le 600 ] || AHEAD=600
# When the key in the kernel was made. Memory only: after a restart of this
# service it is unknown, and an unknown age is treated as due.
KEY_BORN=""

emit() {
  # /run/furcate belongs to tmpfiles (furcate-runtime.conf): root:furcate 2775. A
  # bare mkdir as root would recreate it root:root 755 and lock out every
  # User=furcate process, so it is created exactly as the rule says.
  if [ "$STATE" = /run/furcate/wg.json ]; then
    install -d -m 2775 -o root -g furcate /run/furcate
  fi
  printf '%s\n' "$1" > "$STATE".tmp && mv "$STATE".tmp "$STATE" && chmod 644 "$STATE"
}

now_ms() { echo $(( $(date +%s%N) / 1000000 )); }

have_wg() { command -v wg >/dev/null 2>&1; }

# The node's overlay identity. Generated once, never rotated automatically:
# rotating a key that peers hold would strand this node until every one of them
# learned the new one, which is isolation with a schedule attached. Rotation is
# an operator action.
ensure_key() {
  iface=$1
  install -d -m 700 "$KEYDIR"
  if [ ! -s "$KEYDIR/$iface.key" ]; then
    umask 077
    wg genkey > "$KEYDIR/$iface.key"
  fi
  wg pubkey < "$KEYDIR/$iface.key"
}

# A new key for this lease, from `wg genkey` to the kernel through a pipe.
# Run in this shell, never in a command substitution, so KEY_BORN is kept.
rotate() {
  iface=$1
  wg genkey | wg set "$iface" private-key /dev/stdin
  KEY_BORN=$(date +%s)
}

# Replace the key when its lease is about to end, or when its age is unknown.
renew_if_due() {
  iface=$1
  ip link show "$iface" >/dev/null 2>&1 || return 0
  now=$(date +%s)
  if [ -z "$KEY_BORN" ] || [ "$now" -ge $(( KEY_BORN + LEASE - AHEAD )) ]; then
    rotate "$iface"
  fi
}

apply() {
  iface=$1; address=$2; port=$3

  if [ "$EPHEMERAL" = 1 ]; then
    if ! ip link show "$iface" >/dev/null 2>&1; then
      ip link add dev "$iface" type wireguard
      rotate "$iface"
    fi
    wg set "$iface" listen-port "$port"
    ip address replace "$address" dev "$iface"
    ip link set up dev "$iface"
  elif ! ip link show "$iface" >/dev/null 2>&1; then
    ip link add dev "$iface" type wireguard
    wg set "$iface" listen-port "$port" private-key "$KEYDIR/$iface.key"
    # Replaced rather than added, so a restart with a changed address does not
    # leave the interface holding both.
    ip address replace "$address" dev "$iface"
    ip link set up dev "$iface"
  else
    wg set "$iface" listen-port "$port" private-key "$KEYDIR/$iface.key"
    ip address replace "$address" dev "$iface"
  fi

  # One peer at a time. `wg set` leaves untouched peers alone, which is the
  # whole reason this is not a `setconf`.
  while IFS= read -r line; do
    case "$line" in
      peer=*)
        # Deliberate word splitting: a peer record is space-separated fields,
        # and this is how a POSIX shell takes them apart.
        # shellcheck disable=SC2046
        set -- $(printf '%s' "${line#peer=}")
        key=${1:-}; allowed=${2:-}; endpoint=${3:-}; keep=${4:-25}
        [ -n "$key" ] && [ -n "$allowed" ] || continue
        if [ -n "$endpoint" ] && [ "$endpoint" != "-" ]; then
          wg set "$iface" peer "$key" allowed-ips "$allowed" \
            endpoint "$endpoint" persistent-keepalive "$keep"
        else
          # A peer whose location is unknown can still dial in. Passing an
          # empty endpoint would fail and take the whole reconciliation with it.
          wg set "$iface" peer "$key" allowed-ips "$allowed" \
            persistent-keepalive "$keep"
        fi
        ;;
      remove=*)
        key=${line#remove=}
        [ -n "$key" ] && wg set "$iface" peer "$key" remove
        ;;
    esac
  done < "$PLAN"

  # Peers the kernel holds that the plan no longer names.
  #
  # The agent cannot compute this: it writes what it wants and does not read the
  # interface, so only this side knows both halves. Without it a peer that local
  # policy stopped admitting stayed configured forever — the plan simply omitted
  # it and omission did nothing.
  #
  # Retention is about the coordinator going quiet, never about this node's own
  # operator changing their mind. A peer absent from the plan is absent because
  # the policy on this machine refused it, and that decision has to reach the
  # kernel or it is not a decision.
  wg show "$iface" peers 2>/dev/null | while IFS= read -r have; do
    [ -n "$have" ] || continue
    if ! grep -q "^peer=$have " "$PLAN"; then
      wg set "$iface" peer "$have" remove
    fi
  done
}

report() {
  iface=$1; pub=$2
  peers=$(wg show "$iface" peers 2>/dev/null | wc -l | tr -d ' ')
  # Handshake times say whether the overlay is actually carrying traffic, which
  # a peer count does not.
  latest=$(wg show "$iface" latest-handshakes 2>/dev/null | awk '{ if ($2 > m) m = $2 } END { print m+0 }')
  # Per peer as well, with the endpoint the kernel is actually using: the agent
  # needs both to tell a live path (keep it, including an address WireGuard
  # roamed to) from a dead one (try the next candidate). Keys and endpoints are
  # base64 and host:port, neither of which can contain a quote.
  hs=$(wg show "$iface" latest-handshakes 2>/dev/null | awk 'BEGIN{ORS=""} NF==2 { printf "%s\"%s\":%d", (n++?",":""), $1, $2 }')
  eps=$(wg show "$iface" endpoints 2>/dev/null | awk 'BEGIN{ORS=""} NF==2 && $2 != "(none)" { printf "%s\"%s\":\"%s\"", (n++?",":""), $1, $2 }')
  # The lease, on a node that runs one, so the agent can bind the key to it.
  lease=""
  if [ "$EPHEMERAL" = 1 ] && [ -n "$KEY_BORN" ]; then
    lease=",\"ephemeral\":true,\"key_born_at\":$KEY_BORN,\"lease\":$LEASE"
  fi
  emit "{\"ok\":true,\"iface\":\"$iface\",\"public_key\":\"$pub\",\"peers\":$peers,\"latest_handshake\":$latest,\"handshakes\":{$hs},\"endpoints\":{$eps}$lease,\"at_ms\":$(now_ms)}"
}

last=""
while true; do
  # Reported every pass whatever happens, including when there is nothing to do.
  # A helper that goes silent when idle is indistinguishable from one that has
  # died, and the agent above it cannot tell "no plan yet" from "this stopped
  # working an hour ago" — which is exactly the distinction the rest of this
  # system spends so much effort preserving.
  if [ -e "$ISOLATED" ]; then
    # Isolated by order: the overlay stays down until a release order, and
    # the plan is not applied, since applying it brings the interface up.
    emit "{\"ok\":false,\"why\":\"isolated by order; the overlay stays down until released\",\"at_ms\":$(now_ms)}"
    last=""
  elif ! have_wg; then
    emit "{\"ok\":false,\"why\":\"wireguard-tools not installed\",\"at_ms\":$(now_ms)}"
  elif [ ! -r "$PLAN" ]; then
    emit "{\"ok\":false,\"why\":\"no plan at $PLAN\",\"at_ms\":$(now_ms)}"
  else
    body=$(cat "$PLAN" 2>/dev/null || echo "")
    if [ -z "$body" ]; then
      emit "{\"ok\":false,\"why\":\"plan is empty\",\"at_ms\":$(now_ms)}"
    else
      iface=$(printf '%s\n' "$body" | sed -n 's/^iface=//p' | head -1)
      address=$(printf '%s\n' "$body" | sed -n 's/^address=//p' | head -1)
      port=$(printf '%s\n' "$body" | sed -n 's/^port=//p' | head -1)
      iface=${iface:-$IFACE_DEFAULT}
      port=${port:-51820}

      pub=""
      if [ "$EPHEMERAL" = 0 ]; then
        pub=$(ensure_key "$iface")
      fi
      # Compared against the peers actually configured as well as the plan
      # body, so a removal is applied even when the file that triggered it is
      # unchanged from the last pass.
      configured=$(wg show "$iface" peers 2>/dev/null | sort | tr '\n' ',')
      wanted=$(sed -n 's/^peer=\([^ ]*\) .*/\1/p' "$PLAN" | sort | tr '\n' ',')
      if [ -n "$address" ] && { [ "$body" != "$last" ] || [ "$configured" != "$wanted" ]; }; then
        if apply "$iface" "$address" "$port"; then
          last="$body"
        else
          emit "{\"ok\":false,\"why\":\"apply failed\",\"iface\":\"$iface\",\"at_ms\":$(now_ms)}"
        fi
      fi
      if [ "$EPHEMERAL" = 1 ]; then
        renew_if_due "$iface"
        pub=$(wg show "$iface" public-key 2>/dev/null || true)
      fi
      # Reported every pass, not only on change: the public key and the
      # handshake ages are what the agent publishes, and they move without the
      # plan moving.
      report "$iface" "$pub"
    fi
  fi
  if [ "$PASSES" -gt 0 ]; then
    PASSES=$(( PASSES - 1 ))
    [ "$PASSES" -gt 0 ] || exit 0
  fi
  sleep "$INTERVAL"
done
