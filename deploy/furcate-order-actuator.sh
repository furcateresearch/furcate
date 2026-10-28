#!/bin/sh
# Carry out passkey-approved orders on behalf of an unprivileged agent.
#
# The agent verifies an order and its approvals, then writes an intent here.
# It holds none of the capabilities the orders need: stopping units, changing
# the packet filter, taking an interface down, wiping a keyslot. This does,
# and reports what actually happened, so the agent's ledger records what this
# did rather than what it was asked.
#
# Apart from the power actuator on purpose. That one runs with no network and
# a narrow write set, and should keep both; isolating a node needs the network
# stack and erasing one needs its block devices.
#
# Intent format, one key=value per line, written atomically:
#   action=halt|resume|isolate|release|crypto_erase
#   iface=<overlay interface>        (isolate, release)
#   nonce=<order hash>
#
# The result echoes the nonce, so the agent can tell the report for its order
# from an earlier one. `ok` is true only when everything the action covers was
# done; otherwise `why` says what failed and the other fields say what was done.
set -u

INTENT="${FURCATE_ORDER_INTENT:-/var/lib/furcate/order}"
RESULT="${FURCATE_ORDER_RESULT:-/run/furcate/order-result.json}"
STATE="${FURCATE_STATE_DIR:-/var/lib/furcate}"
# Interfaces that stay reachable while isolated, one per line: the out-of-band
# or console path. Loopback always stays, so a person at the console can reach
# the agent and hand it a signed release order.
ISOLATE_ALLOW="${FURCATE_ISOLATE_ALLOW:-/etc/furcate/isolate-allow}"
# LUKS devices whose TPM keyslot an erase wipes, one per line.
ERASE_DEVICES="${FURCATE_ERASE_DEVICES:-/etc/furcate/erase-devices}"
# Further sealed blobs an erase destroys, one absolute path per line.
ERASE_PATHS="${FURCATE_ERASE_PATHS:-/etc/furcate/erase-paths}"

ISOLATED="$STATE/isolated"
# The units halts stopped and no resume has restarted yet, one per line. It is
# what a resume restarts, and all it restarts.
HALTED="$STATE/halted"
ERASE_LATCH="$STATE/erase-pending.json"
ERASE_ARMED="$STATE/erase-armed"

now_ms() { echo $(( $(date +%s%N) / 1000000 )); }

emit() {
  mkdir -p "$(dirname "$RESULT")"
  printf '%s\n' "$1" > "$RESULT".tmp && mv "$RESULT".tmp "$RESULT" && chmod 644 "$RESULT"
}

# A JSON array of the space-separated words given.
list() {
  out=""
  for w in $1; do out="$out${out:+,}\"$w\""; done
  printf '[%s]' "$out"
}

safe_name() {
  case "$1" in ''|-*|*[!A-Za-z0-9_.-]*) return 1 ;; esac
  [ "${#1}" -le 32 ]
}

safe_path() {
  case "$1" in /*) : ;; *) return 1 ;; esac
  case "$1" in *..*|*[!A-Za-z0-9_./-]*) return 1 ;; esac
  return 0
}

# --- halt --------------------------------------------------------------------
#
# The workloads Furcate supervises are its deployed apps, the furcate-app-*
# units. The OS, the agent, this helper and sshd are not workloads, and a halt
# that took them down would leave nobody able to undo it.
halt() {
  nonce=$1
  stopped=""; failed=""
  units=$(systemctl list-units --type=service --state=active --no-legend --plain \
            'furcate-app-*.service' 2>/dev/null | awk '{print $1}')
  for u in $units; do
    case "$u" in furcate-app-*.service) : ;; *) continue ;; esac
    case "$u" in *[!A-Za-z0-9_.@-]*) continue ;; esac
    systemctl stop -- "$u" >/dev/null 2>&1
    if systemctl is-active --quiet -- "$u"; then
      failed="$failed $u"
    else
      stopped="$stopped $u"
    fi
  done
  # Recorded before reporting, added to what an earlier halt recorded, so a
  # resume restarts exactly what halts stopped.
  recorded=true
  if [ -n "$stopped" ]; then
    { [ -r "$HALTED" ] && cat "$HALTED"; for u in $stopped; do printf '%s\n' "$u"; done; } \
      | sort -u > "$HALTED".tmp && mv "$HALTED".tmp "$HALTED" || recorded=false
  fi
  if [ -z "$failed" ] && $recorded; then
    emit "{\"ok\":true,\"action\":\"halt\",\"stopped\":$(list "$stopped"),\"recorded\":\"$HALTED\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
  elif $recorded; then
    emit "{\"ok\":false,\"why\":\"some workloads did not stop\",\"action\":\"halt\",\"stopped\":$(list "$stopped"),\"failed\":$(list "$failed"),\"recorded\":\"$HALTED\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
  else
    emit "{\"ok\":false,\"why\":\"the stopped workloads could not be recorded, so a resume cannot restart them\",\"action\":\"halt\",\"stopped\":$(list "$stopped"),\"failed\":$(list "$failed"),\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
  fi
}

# --- resume ------------------------------------------------------------------
#
# Starts the units halts recorded and nothing else: a unit an operator stopped
# by hand, or one that was not running when the halt came, stays as it is.
# A unit that will not start stays recorded, so a later resume tries it again.
resume() {
  nonce=$1
  if [ ! -s "$HALTED" ]; then
    emit "{\"ok\":false,\"why\":\"no halt is recorded on this node; nothing was restarted\",\"action\":\"resume\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"; return
  fi
  started=""; running=""; failed=""; skipped=""
  while IFS= read -r u || [ -n "$u" ]; do
    case "$u" in '') continue ;; esac
    case "$u" in furcate-app-*.service) : ;; *) skipped="$skipped $u"; continue ;; esac
    case "$u" in *[!A-Za-z0-9_.@-]*) skipped="$skipped unsafe-unit"; continue ;; esac
    if systemctl is-active --quiet -- "$u"; then
      running="$running $u"; continue
    fi
    systemctl start -- "$u" >/dev/null 2>&1
    if systemctl is-active --quiet -- "$u"; then
      started="$started $u"
    else
      failed="$failed $u"
    fi
  done < "$HALTED"
  if [ -n "$failed" ]; then
    for u in $failed; do printf '%s\n' "$u"; done > "$HALTED".tmp && mv "$HALTED".tmp "$HALTED"
    emit "{\"ok\":false,\"why\":\"some workloads did not start\",\"action\":\"resume\",\"started\":$(list "$started"),\"already_running\":$(list "$running"),\"failed\":$(list "$failed"),\"skipped\":$(list "$skipped"),\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
  else
    rm -f -- "$HALTED"
    if [ -e "$HALTED" ]; then
      emit "{\"ok\":false,\"why\":\"the workloads started but the halt record could not be cleared\",\"action\":\"resume\",\"started\":$(list "$started"),\"already_running\":$(list "$running"),\"skipped\":$(list "$skipped"),\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
    else
      emit "{\"ok\":true,\"action\":\"resume\",\"started\":$(list "$started"),\"already_running\":$(list "$running"),\"skipped\":$(list "$skipped"),\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
    fi
  fi
}

# --- isolate / release -------------------------------------------------------
#
# The packet filter is what isolates: deny everything in and out, and forward
# nothing, except loopback and the declared out-of-band interfaces. Taking the
# overlay down is on top of that, so the node also stops announcing itself.
# The overlay helper does not bring the interface back up while the latch is
# present, and if it did the filter would still drop what it carried.
apply_isolation() {
  allow_in=""; allow_out=""
  if [ -r "$ISOLATE_ALLOW" ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      case "$line" in ''|'#'*) continue ;; esac
      safe_name "$line" || continue
      allow_in="$allow_in iifname \"$line\" accept;"
      allow_out="$allow_out oifname \"$line\" accept;"
    done < "$ISOLATE_ALLOW"
  fi
  nft -f - <<NFT
table inet furcate_isolate
delete table inet furcate_isolate
table inet furcate_isolate {
  chain input { type filter hook input priority -300; policy drop; iif "lo" accept; $allow_in }
  chain output { type filter hook output priority -300; policy drop; oif "lo" accept; $allow_out }
  chain forward { type filter hook forward priority -300; policy drop; }
}
NFT
}

isolate() {
  iface=$1; nonce=$2
  if ! safe_name "$iface"; then
    emit "{\"ok\":false,\"why\":\"not an interface name\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"; return
  fi
  printf '%s\n' "$iface" > "$ISOLATED".tmp && mv "$ISOLATED".tmp "$ISOLATED"
  filter=false; overlay=absent
  if apply_isolation >/dev/null 2>&1 && nft list table inet furcate_isolate >/dev/null 2>&1; then
    filter=true
  fi
  if ip link show dev "$iface" >/dev/null 2>&1; then
    ip link set dev "$iface" down >/dev/null 2>&1
    if ip -o link show dev "$iface" 2>/dev/null | grep -q '[<,]UP[,>]'; then overlay=up; else overlay=down; fi
  fi
  if $filter && [ "$overlay" != up ]; then
    emit "{\"ok\":true,\"action\":\"isolate\",\"filter\":\"deny-all\",\"overlay\":\"$overlay\",\"iface\":\"$iface\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
  else
    emit "{\"ok\":false,\"why\":\"isolation is incomplete\",\"action\":\"isolate\",\"filter_applied\":$filter,\"overlay\":\"$overlay\",\"iface\":\"$iface\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
  fi
}

release() {
  iface=$1; nonce=$2
  if ! safe_name "$iface"; then
    emit "{\"ok\":false,\"why\":\"not an interface name\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"; return
  fi
  if nft list table inet furcate_isolate >/dev/null 2>&1; then
    nft delete table inet furcate_isolate >/dev/null 2>&1
  fi
  filter_gone=true
  nft list table inet furcate_isolate >/dev/null 2>&1 && filter_gone=false
  if $filter_gone; then
    rm -f -- "$ISOLATED"
  fi
  overlay=absent
  if ip link show dev "$iface" >/dev/null 2>&1; then
    ip link set dev "$iface" up >/dev/null 2>&1
    if ip -o link show dev "$iface" 2>/dev/null | grep -q '[<,]UP[,>]'; then overlay=up; else overlay=down; fi
  fi
  if $filter_gone && [ ! -e "$ISOLATED" ] && [ "$overlay" != down ]; then
    emit "{\"ok\":true,\"action\":\"release\",\"overlay\":\"$overlay\",\"iface\":\"$iface\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
  else
    emit "{\"ok\":false,\"why\":\"release is incomplete\",\"action\":\"release\",\"filter_removed\":$filter_gone,\"overlay\":\"$overlay\",\"iface\":\"$iface\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
  fi
}

# --- crypto_erase ------------------------------------------------------------
#
# Destroys what makes data at rest readable on this machine: the sealed node
# key, any further sealed blobs the operator declared, and the TPM keyslot of
# each declared LUKS device. Then arms early boot, which completes the erase
# (clearing the TPM's storage hierarchy, which no running OS can do on its
# own), and records completion in erase-done for the agent to acknowledge.
#
# The agent latches the erase before writing this intent. One that is not
# latched is refused, so nothing here destroys material without the agent
# having first recorded that an erase is pending.
erase_file() {
  f=$1
  [ -e "$f" ] || return 0
  shred -u -- "$f" >/dev/null 2>&1 || rm -f -- "$f"
  # rm exits 0 on some failures; what counts is whether the file is gone.
  [ ! -e "$f" ]
}

crypto_erase() {
  nonce=$1
  if [ ! -e "$ERASE_LATCH" ] || ! grep -q "\"$nonce\"" "$ERASE_LATCH"; then
    emit "{\"ok\":false,\"why\":\"no erase is latched for this order; nothing was destroyed\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"; return
  fi
  destroyed=""; failed=""
  for f in "$STATE/node-key/seal.priv" "$STATE/node-key/seal.pub"; do
    [ -e "$f" ] || continue
    if erase_file "$f"; then destroyed="$destroyed $f"; else failed="$failed $f"; fi
  done
  if [ -r "$ERASE_PATHS" ]; then
    while IFS= read -r f || [ -n "$f" ]; do
      case "$f" in ''|'#'*) continue ;; esac
      safe_path "$f" || { failed="$failed unsafe-path"; continue; }
      [ -e "$f" ] || continue
      if erase_file "$f"; then destroyed="$destroyed $f"; else failed="$failed $f"; fi
    done < "$ERASE_PATHS"
  fi
  wiped=""
  if [ -r "$ERASE_DEVICES" ]; then
    while IFS= read -r dev || [ -n "$dev" ]; do
      case "$dev" in ''|'#'*) continue ;; esac
      case "$dev" in /dev/*) : ;; *) failed="$failed unsafe-device"; continue ;; esac
      safe_path "$dev" || { failed="$failed unsafe-device"; continue; }
      systemd-cryptenroll --wipe-slot=tpm2 -- "$dev" >/dev/null 2>&1
      if cryptsetup luksDump -- "$dev" 2>/dev/null | grep -q 'systemd-tpm2'; then
        failed="$failed $dev"
      else
        wiped="$wiped $dev"
      fi
    done < "$ERASE_DEVICES"
  fi
  printf '%s\n' "$nonce" > "$ERASE_ARMED".tmp && mv "$ERASE_ARMED".tmp "$ERASE_ARMED"
  armed=false; [ -e "$ERASE_ARMED" ] && armed=true
  if [ -z "$failed" ] && $armed; then
    emit "{\"ok\":true,\"action\":\"crypto_erase\",\"destroyed\":$(list "$destroyed"),\"keyslots_wiped\":$(list "$wiped"),\"early_boot_armed\":true,\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
  else
    emit "{\"ok\":false,\"why\":\"the erase is incomplete\",\"action\":\"crypto_erase\",\"destroyed\":$(list "$destroyed"),\"keyslots_wiped\":$(list "$wiped"),\"failed\":$(list "$failed"),\"early_boot_armed\":$armed,\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
  fi
}

# An isolation outlives a restart of this helper and a reboot of the machine:
# it ends only with a release order.
if [ -e "$ISOLATED" ]; then
  iface=$(head -1 "$ISOLATED" 2>/dev/null)
  if apply_isolation >/dev/null 2>&1; then
    echo "furcate-order-actuator: isolation re-applied" >&2
  else
    echo "furcate-order-actuator: WARNING isolation latched but the filter could not be applied" >&2
  fi
  if safe_name "$iface" && ip link show dev "$iface" >/dev/null 2>&1; then
    ip link set dev "$iface" down >/dev/null 2>&1
  fi
fi

last=""
while true; do
  if [ -r "$INTENT" ]; then
    body=$(cat "$INTENT" 2>/dev/null || echo "")
    if [ -n "$body" ] && [ "$body" != "$last" ]; then
      last="$body"
      action=$(printf '%s\n' "$body" | sed -n 's/^action=//p' | head -1)
      iface=$(printf '%s\n' "$body" | sed -n 's/^iface=//p' | head -1)
      nonce=$(printf '%s\n' "$body" | sed -n 's/^nonce=//p' | head -1)
      case "$nonce" in ''|*[!0-9a-f]*) continue ;; esac
      case "$action" in
        halt) halt "$nonce" ;;
        resume) resume "$nonce" ;;
        isolate) isolate "$iface" "$nonce" ;;
        release) release "$iface" "$nonce" ;;
        crypto_erase) crypto_erase "$nonce" ;;
        *) emit "{\"ok\":false,\"why\":\"not an order this node carries out\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}" ;;
      esac
    fi
  fi
  sleep 1
done
