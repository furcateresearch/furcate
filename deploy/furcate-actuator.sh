#!/bin/sh
# Apply power levers on behalf of an unprivileged agent.
#
# The agent cannot write these files and should not be able to. Its unit sets
# ProtectKernelTunables=true, and relaxing that to let it change a CPU governor
# would hand it write access to a whole class of kernel knobs to gain three.
# So the agent writes an intent and this applies it.
#
# The property that makes the split worth anything: **the floors are enforced
# here, not there.** If this applied whatever it was handed, the sandbox would
# be decoration — a compromised agent would set max_perf_pct to 1 and the
# machine would be unusable. The same limits exist in the agent's own code, and
# they are re-derived independently at the only point where they can actually
# stop something.
#
# Intent format, one key=value per line, written atomically:
#   lever=max_perf_pct|package_cap_watts|governor
#   value=<n>|<name>
#   nonce=<opaque>
#
# The nonce is echoed in the result so the agent can tell its own request from
# a stale one, not for authentication: anyone able to write the intent file can
# already restart the agent that writes it.
set -eu

# /var/lib/furcate, not a home directory. The previous default named one
# person's account, so the helper only worked on the machine it was written on
# — and the agent it talks to could not reach it anyway once the helper dropped
# CAP_DAC_OVERRIDE and ordinary permissions started applying.
INTENT="${FURCATE_INTENT:-/var/lib/furcate/actuate}"
RESULT=/run/furcate/actuated.json
PSTATE=/sys/devices/system/cpu/intel_pstate
# Root of the kernel's power-capping framework, not one zone inside it. This
# used to name `intel-rapl:0` directly, which on a two-socket machine capped
# one package and left the other at its full nameplate -- and a management
# controller ramps its fans on the draw of the whole machine, so half a cap
# bought close to nothing. Every `package-*` zone is enumerated at apply time.
POWERCAP_ROOT=/sys/class/powercap

# Independently enforced. Deliberately duplicated from the agent rather than
# shared, because a limit that lives in one place is a limit that stops
# existing when that place is compromised.
MIN_PERF_PCT=40
MIN_CAP_FRACTION_PCT=35

# Swap bound floors, re-derived here rather than trusted from the intent.
# Zero swap for user work turns every transient spike into an instant kill;
# an unbounded one is what let a build thrash spark to death on 25 Aug 2026.
MIN_SWAP_MB=512
MAX_SWAP_MB=8192

# Work the operator has designated disposable, one id or prefix per line.
#
# Read HERE, from a root-owned file, and never taken from the intent. That is
# the whole reason `shed` is allowed to exist beside the "restart and nothing
# else" rule below: the blast radius of a stop is fixed by the operator in
# advance, on this side of the privilege boundary, so a compromised agent can
# stop only work already declared expendable and still cannot take a site
# apart. The same argument the perf and swap floors above are making.
#
# Absent or empty means nothing may be shed. Fail closed: a missing list is not
# permission, and the cost of guessing here is a site that stops the wrong
# thing during a power event.
PREEMPTIBLE="${FURCATE_PREEMPTIBLE_FILE:-/etc/furcate/preemptible}"

# The operator's authority to let the UPS ladder power this node off. Root
# owned, and read HERE for the same reason the preemptible list is: the agent
# only ever asks, and this decides. Absent, unreadable, or anything but
# `mode=enforce` means refuse. The default of a node is dry run.
UPS_SHUTDOWN="${FURCATE_UPS_SHUTDOWN:-/etc/furcate/ups-shutdown}"
POWEROFF_CMD="${FURCATE_POWEROFF_CMD:-systemctl poweroff}"
# What may be stopped on the way down, with the timeouts and grace windows the
# operator chose. Read HERE and never taken from the intent: one line per unit,
# `unit=NAME ... timeout=N grace=M [stop=/abs/path]`.
UPS_STOP_LIST="${FURCATE_UPS_STOP:-/etc/furcate/ups-stop}"
# While this file exists nothing is stopped or powered off by the ups ladder,
# whatever the arming file says.
UPS_KILL="${FURCATE_UPS_KILL:-/etc/furcate/ups-actuation-disabled}"

# Whether the operator has made this node live: `mode=enforce`, kill switch absent.
ups_armed() {
  [ ! -e "$UPS_KILL" ] && [ -r "$UPS_SHUTDOWN" ] && grep -qx 'mode=enforce' "$UPS_SHUTDOWN" 2>/dev/null
}

# --- dead man's switch -------------------------------------------------------
#
# The failure this prevents: a node throttled to 40% stays there forever if the
# thing that throttled it dies. Nothing expired, nothing checked that whoever
# asked was still alive, and the fleet sat degraded while every health check
# said it was fine. A power ladder whose descent is permanent is worse than one
# that never descends, because the second kind is visible.
#
# So the agent posts a heartbeat every cycle, and if it stops arriving this
# reverts to a level that is safe to be stuck at.
#
# Why "safe" here means full performance rather than a low cap: on this hardware
# the management controller enforces thermal limits independently of the
# operating system and survives a kernel panic, so heat is covered whatever this
# does. What is *not* covered by anything else is a machine quietly running at
# 40% for a month. A site with no independent thermal authority should lower
# this — hence the variable.
# Alongside the intent rather than under /run/furcate: that directory is
# root-owned so the privileged half can publish into it, which means the
# unprivileged agent cannot write there. The heartbeat has to come from the
# agent, so it lives where the agent already writes.
HEARTBEAT="${FURCATE_HEARTBEAT:-${INTENT}.heartbeat}"
HOLD_SECS="${FURCATE_HOLD_SECS:-90}"
SAFE_PERF_PCT="${FURCATE_SAFE_PERF_PCT:-100}"

# Whether a lever is currently held away from its safe position. Tracked here
# rather than read back from sysfs, so a revert happens exactly once and does
# not fight an operator who set the value by hand afterwards.
held=""

heartbeat_age() {
  [ -e "$HEARTBEAT" ] || { echo 999999; return; }
  now=$(date +%s)
  mtime=$(stat -c %Y "$HEARTBEAT" 2>/dev/null || echo 0)
  echo $(( now - mtime ))
}

revert_to_safe() {
  [ -n "$held" ] || return 0
  # Reverting is itself an actuation and goes through the same path, so it is
  # clamped by the same floors and reported in the same file.
  apply max_perf_pct "$SAFE_PERF_PCT" "deadman-$(now_ms)"
  held=""
  echo "furcate-actuator: heartbeat stale; reverted to max_perf_pct=$SAFE_PERF_PCT" >&2
}

emit() {
  # /run/furcate belongs to tmpfiles (furcate-runtime.conf): root:furcate 2775. A
  # bare mkdir as root would recreate it root:root 755 and lock out every
  # User=furcate process, so it is created exactly as the rule says.
  install -d -m 2775 -o root -g furcate /run/furcate
  printf '%s\n' "$1" > "$RESULT".tmp && mv "$RESULT".tmp "$RESULT" && chmod 644 "$RESULT"
}

now_ms() { echo $(( $(date +%s%N) / 1000000 )); }

apply() {
  lever=$1; value=$2; nonce=$3
  clamped=false
  applied="$value"

  case "$lever" in
    max_perf_pct)
      [ -w "$PSTATE/max_perf_pct" ] || { emit "{\"ok\":false,\"why\":\"no intel_pstate\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"; return; }
      case "$value" in ''|*[!0-9]*) emit "{\"ok\":false,\"why\":\"not a number\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"; return;; esac
      if [ "$value" -lt "$MIN_PERF_PCT" ]; then applied=$MIN_PERF_PCT; clamped=true; fi
      if [ "$applied" -gt 100 ]; then applied=100; clamped=true; fi
      echo "$applied" > "$PSTATE/max_perf_pct"
      readback=$(cat "$PSTATE/max_perf_pct")
      ;;
    package_cap_watts)
      case "$value" in ''|*[!0-9]*) emit "{\"ok\":false,\"why\":\"not a number\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"; return;; esac

      # Every package zone, not the first one. `dram` and `core` sub-zones are
      # skipped on purpose: the fan controller responds to package draw, and
      # capping memory to quieten a machine slows it for no acoustic gain.
      zones=""
      for z in "$POWERCAP_ROOT"/*/; do
        [ -r "$z/name" ] || continue
        case "$(cat "$z/name" 2>/dev/null)" in package*) : ;; *) continue ;; esac
        [ -w "$z/constraint_0_power_limit_uw" ] || continue
        zones="$zones $z"
      done
      [ -n "$zones" ] || { emit "{\"ok\":false,\"why\":\"no writable package powercap zone\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"; return; }

      # Each zone is clamped against its own ceiling. Sockets in one machine
      # are usually identical, but a floor derived from one zone and applied to
      # another is an assumption this does not need to make.
      readback=0
      count=0
      for z in $zones; do
        MAXW=$(( $(cat "$z/constraint_0_max_power_uw" 2>/dev/null || echo 0) / 1000000 ))
        [ "$MAXW" -gt 0 ] || MAXW=$value
        FLOOR=$(( MAXW * MIN_CAP_FRACTION_PCT / 100 ))
        [ "$FLOOR" -lt 1 ] && FLOOR=1
        want=$value
        if [ "$want" -lt "$FLOOR" ]; then want=$FLOOR; clamped=true; fi
        if [ "$want" -gt "$MAXW" ]; then want=$MAXW; clamped=true; fi
        echo $(( want * 1000000 )) > "$z/constraint_0_power_limit_uw" 2>/dev/null || continue
        got=$(( $(cat "$z/constraint_0_power_limit_uw" 2>/dev/null || echo 0) / 1000000 ))
        # The reported figure is the total the machine may now draw across its
        # packages, because that is the number the controller is reading and
        # the number an operator is trying to hold.
        readback=$(( readback + got ))
        count=$(( count + 1 ))
        applied=$want
      done
      [ "$count" -gt 0 ] || { emit "{\"ok\":false,\"why\":\"every package zone refused the write\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"; return; }
      ;;
    governor)
      # An unknown governor name would be written and silently rejected by the
      # kernel, so it is checked against what this CPU actually offers.
      AVAIL=$(cat /sys/devices/system/cpu/cpufreq/policy0/scaling_available_governors 2>/dev/null || echo "")
      case " $AVAIL " in *" $value "*) : ;; *) emit "{\"ok\":false,\"why\":\"governor not available\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"; return;; esac
      for p in /sys/devices/system/cpu/cpufreq/policy*/scaling_governor; do
        echo "$value" > "$p" 2>/dev/null || true
      done
      readback=$(cat /sys/devices/system/cpu/cpufreq/policy0/scaling_governor)
      applied="$value"
      ;;
    turbo)
      # The intent says what an operator means; the kernel spells it `no_turbo`
      # and inverts it. The inversion happens here, at the write, rather than
      # being carried across the process boundary in a text file where whoever
      # read it would have to already know.
      NT=/sys/devices/system/cpu/intel_pstate/no_turbo
      [ -w "$NT" ] || { emit "{\"ok\":false,\"why\":\"no intel_pstate\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"; return; }
      case "$value" in
        on)  echo 0 > "$NT" ;;
        off) echo 1 > "$NT" ;;
        *)   emit "{\"ok\":false,\"why\":\"turbo takes on or off\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"; return ;;
      esac
      # Read back in the same terms the intent used, so a human comparing the
      # two is not silently comparing a value against its own negation.
      if [ "$(cat "$NT")" = "0" ]; then readback=on; else readback=off; fi
      applied="$value"
      ;;
    *)
      emit "{\"ok\":false,\"why\":\"unknown lever\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
      return
      ;;
  esac

  emit "{\"ok\":true,\"lever\":\"$lever\",\"requested\":\"$value\",\"applied\":\"$applied\",\"readback\":\"$readback\",\"clamped\":$clamped,\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
}

# Restart one workload, on an operator's explicit instruction.
#
# Furcate does not restart things by itself and this does not change that: the
# MAPE loop is refused this action structurally, before it reaches here. What
# arrives here has already been ruled on by the policy engine on behalf of a
# human who asked for it. systemd and Docker still own supervision; this is the
# operator's hand on the same controls they would use by hand, from the screen
# they were already looking at.
#
# Deliberately restart and nothing else. There is no stop, no disable, no
# remove: a workload that is down stays a thing an operator decided, and a
# lever that can only put something back is one that cannot be used to take a
# site apart.
bound_memory() {
  slice=$1; swap=$2; nonce=$3

  # WHY THIS ACTION EXISTS AT ALL
  #
  # On 25 Aug 2026 spark became unreachable by SSH while a build held 100% of
  # the swap device. ping answered and TCP 22 accepted connections -- both are
  # in-kernel -- but sshd could not be scheduled, and `sudo` hung every time
  # because it must fork, read PAM config and write logs. A cheap `cat
  # /proc/loadavg` over the same SSH succeeded seconds earlier.
  #
  # furcated, holding MemoryMin and OOMScoreAdjust=-900, answered throughout.
  #
  # So the one process still guaranteed a scheduling slot could see the
  # problem and could not act on it, while the fix needed exactly the login
  # path that memory pressure had taken away. That is the gap this closes: the
  # daemon that survives the outage can now apply the bound that ends it.

  # The slice is named across a privilege boundary and becomes an argument.
  # Checked here as well as by the agent, for the same reason the workload id
  # is: a defence on the unprivileged side of the boundary is not a defence.
  case "$slice" in
    ''|*[!A-Za-z0-9.@-]*)
      emit "{\"ok\":false,\"why\":\"slice has characters that are not allowed\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
      return ;;
    -*)
      emit "{\"ok\":false,\"why\":\"slice may not start with a dash\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
      return ;;
    *.slice) ;;
    *)
      emit "{\"ok\":false,\"why\":\"only a .slice can be bounded\",\"slice\":\"$slice\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
      return ;;
  esac

  # system.slice is refused outright. Bounding the slice that holds sshd and
  # furcated is how you turn a busy machine into an unreachable one -- the
  # exact outcome this whole path exists to prevent. The floor is enforced
  # here rather than trusted from the intent, like every other floor in this
  # file.
  case "$slice" in
    system.slice|init.scope|-.slice)
      emit "{\"ok\":false,\"why\":\"refusing to bound the slice that carries the control path\",\"slice\":\"$slice\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
      return ;;
  esac

  case "$swap" in
    ''|*[!0-9]*)
      emit "{\"ok\":false,\"why\":\"swap must be a whole number of megabytes\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
      return ;;
  esac

  # A floor, not a ceiling: zero swap for user work turns every transient
  # spike into an instant kill. The point is to bound thrashing, not to
  # forbid swapping.
  if [ "$swap" -lt "$MIN_SWAP_MB" ]; then swap=$MIN_SWAP_MB; fi
  if [ "$swap" -gt "$MAX_SWAP_MB" ]; then swap=$MAX_SWAP_MB; fi

  # set-property, not a drop-in plus daemon-reload: a drop-in does NOT apply to
  # an already-running slice, and the whole value of this path is that it works
  # on a machine that is in trouble right now. --runtime so a bound applied
  # during an incident does not silently become permanent policy; the durable
  # version belongs in the versioned drop-in.
  if systemctl set-property --runtime -- "$slice" "MemorySwapMax=${swap}M" >/dev/null 2>&1; then
    live=$(cat "/sys/fs/cgroup/${slice}/memory.swap.max" 2>/dev/null || echo unknown)
    emit "{\"ok\":true,\"action\":\"bound_memory\",\"slice\":\"$slice\",\"swap_mb\":$swap,\"live\":\"$live\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
  else
    emit "{\"ok\":false,\"why\":\"systemctl refused it\",\"slice\":\"$slice\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
  fi
}

restart_workload() {
  kind=$1; id=$2; nonce=$3

  # The id crosses a privilege boundary as text and is about to be an argument,
  # so it is checked here as well as by the agent. A defence that exists only
  # on the unprivileged side of the boundary is not a defence.
  case "$id" in
    ''|*[!A-Za-z0-9._/-]*)
      emit "{\"ok\":false,\"why\":\"id has characters that are not allowed\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
      return ;;
    -*)
      emit "{\"ok\":false,\"why\":\"id may not start with a dash\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
      return ;;
  esac

  case "$kind" in
    unit)
      # `--` so an id that survived the check above still cannot become a flag.
      if systemctl restart -- "$id" >/dev/null 2>&1; then
        state=$(systemctl is-active -- "$id" 2>/dev/null || echo unknown)
        emit "{\"ok\":true,\"action\":\"restart\",\"kind\":\"unit\",\"id\":\"$id\",\"state\":\"$state\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
      else
        emit "{\"ok\":false,\"why\":\"systemctl refused it\",\"id\":\"$id\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
      fi ;;
    container)
      if docker restart "$id" >/dev/null 2>&1; then
        state=$(docker inspect -f '{{.State.Status}}' "$id" 2>/dev/null || echo unknown)
        emit "{\"ok\":true,\"action\":\"restart\",\"kind\":\"container\",\"id\":\"$id\",\"state\":\"$state\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
      else
        emit "{\"ok\":false,\"why\":\"docker refused it\",\"id\":\"$id\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
      fi ;;
    *)
      # A pod is deliberately absent. Kubernetes restarts pods itself, and a
      # node agent deleting one behind the control plane's back is a fight
      # between two supervisors that the cluster wins slowly.
      emit "{\"ok\":false,\"why\":\"only a unit or a container can be restarted here\",\"kind\":\"$kind\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}" ;;
  esac
}

# Whether an id appears on the operator's preemptible list.
#
# Exact match or prefix, the same shape the agent uses, re-derived here for the
# reason every other limit in this file is re-derived here.
is_preemptible() {
  want=$1
  [ -r "$PREEMPTIBLE" ] || return 1
  while IFS= read -r line || [ -n "$line" ]; do
    # Comments and blanks, so the file can explain itself to whoever edits it.
    case "$line" in ''|'#'*) continue ;; esac
    line=$(printf '%s' "$line" | tr -d ' 	
')
    [ -n "$line" ] || continue
    case "$want" in
      "$line"|"$line"*) return 0 ;;
    esac
  done < "$PREEMPTIBLE"
  return 1
}

# Stop one workload the operator has already designated as disposable.
#
# The single exception to "restart and nothing else" above, and narrower than
# it looks: it cannot stop anything the operator has not written on a root-owned
# list in advance. So the lever still cannot be used to take a site apart, which
# is the property that rule was protecting rather than the absence of a stop for
# its own sake.
#
# It exists because the power ladder's `Shed` rung has always named two actions
# and could only perform one. Capping the CPU buys some time on battery;
# releasing the machines held by work the operator already called expendable
# buys considerably more, and until now that instruction had no way to happen.
#
# Nothing here restarts what it stopped. Coming back up the ladder restores the
# CPU, because a cap outliving the brownout is a bug — but work that was shed is
# gone, and quietly relaunching jobs the site decided to lose is not something
# to do while nobody is watching.
shed_workload() {
  kind=$1; id=$2; nonce=$3

  case "$id" in
    ''|*[!A-Za-z0-9._/-]*)
      emit "{\"ok\":false,\"why\":\"id has characters that are not allowed\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
      return ;;
    -*)
      emit "{\"ok\":false,\"why\":\"id may not start with a dash\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
      return ;;
  esac

  if ! is_preemptible "$id"; then
    emit "{\"ok\":false,\"why\":\"not on this machine's preemptible list\",\"id\":\"$id\",\"list\":\"$PREEMPTIBLE\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
    return
  fi

  case "$kind" in
    unit)
      if systemctl stop -- "$id" >/dev/null 2>&1; then
        state=$(systemctl is-active -- "$id" 2>/dev/null || echo inactive)
        emit "{\"ok\":true,\"action\":\"shed\",\"kind\":\"unit\",\"id\":\"$id\",\"state\":\"$state\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
      else
        emit "{\"ok\":false,\"why\":\"systemctl refused it\",\"id\":\"$id\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
      fi ;;
    container)
      if docker stop "$id" >/dev/null 2>&1; then
        state=$(docker inspect -f '{{.State.Status}}' "$id" 2>/dev/null || echo unknown)
        emit "{\"ok\":true,\"action\":\"shed\",\"kind\":\"container\",\"id\":\"$id\",\"state\":\"$state\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
      else
        emit "{\"ok\":false,\"why\":\"docker refused it\",\"id\":\"$id\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
      fi ;;
    *)
      # A pod is absent for the same reason it is absent from restart: the
      # cluster owns pod lifecycle and a node agent fighting it loses slowly.
      emit "{\"ok\":false,\"why\":\"only a unit or a container can be shed here\",\"kind\":\"$kind\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}" ;;
  esac
}

# Reset one accelerator, on an operator's explicit instruction.
#
# The remedy for a card that has recorded a row remap or whose firmware stopped
# answering: the repair is queued and only a reset applies it. Until now that
# was advice with nothing behind it — furcate-health could say "reset the
# device" and no path existed to do it.
#
# THE GUARD, AND WHY IT IS HERE RATHER THAN IN THE AGENT
#
# A reset tears down every context on the card. Run it on a card that is
# working and you have killed whatever was running with no warning and no
# record beyond this line. So it refuses unless the card has no compute
# processes on it — which is the closest thing to "has been drained" that can
# be established from here, and it is established HERE, on the privileged side,
# for the same reason every other limit in this file is. An agent that believed
# a card was idle would be believing its own stale reading.
#
# It is not a drain. It cannot drain anything, and it does not pretend to: it
# refuses a busy card and tells the caller to drain it, which is a scheduling
# decision belonging to whoever owns the work.
reset_accelerator() {
  index=$1; nonce=$2

  case "$index" in
    ''|*[!0-9]*)
      emit "{\"ok\":false,\"why\":\"an accelerator index is a number\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
      return ;;
  esac
  if [ "$index" -gt 15 ]; then
    emit "{\"ok\":false,\"why\":\"accelerator index out of range\",\"index\":$index,\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
    return
  fi

  command -v nvidia-smi >/dev/null 2>&1 || {
    emit "{\"ok\":false,\"why\":\"no nvidia-smi on this host\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
    return
  }

  # A card that does not answer is not a card to reset. Distinguished from a
  # busy one, because they call for opposite responses.
  if ! nvidia-smi -i "$index" --query-gpu=uuid --format=csv,noheader >/dev/null 2>&1; then
    emit "{\"ok\":false,\"why\":\"no such accelerator, or the driver did not answer\",\"index\":$index,\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
    return
  fi

  busy=$(nvidia-smi -i "$index" --query-compute-apps=pid --format=csv,noheader 2>/dev/null | tr -d ' ' | grep -c '[0-9]' || true)
  if [ "${busy:-0}" -gt 0 ]; then
    emit "{\"ok\":false,\"why\":\"card is in use; drain it before resetting\",\"index\":$index,\"processes\":$busy,\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
    return
  fi

  if nvidia-smi -r -i "$index" >/dev/null 2>&1; then
    emit "{\"ok\":true,\"action\":\"reset_accelerator\",\"index\":$index,\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
  else
    # Commonly because something still holds the device that the compute-apps
    # query does not list — a graphics client, or a process in another
    # container namespace. Reported as the driver refusing rather than as an
    # unknown failure, because the next step is to find that holder.
    emit "{\"ok\":false,\"why\":\"the driver refused the reset; something still holds the device\",\"index\":$index,\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
  fi
}

# Power THIS machine off, at the bottom of the UPS ladder, when the operator
# has armed it. No target and no argument cross the boundary: the request can
# only stop the machine the helper runs on, and only after the operator wrote
# `mode=enforce` into a root-owned file. Not the kill switch, which is the
# operator's signed order and travels another path.
poweroff_node() {
  reason=$1; nonce=$2
  if [ "$reason" != "ups-halt" ]; then
    emit "{\"ok\":false,\"why\":\"a power-off is only taken for the ups ladder\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
    return
  fi
  if ! ups_armed; then
    emit "{\"ok\":false,\"why\":\"this node is not armed for a ups shutdown (dry run, or the kill switch is present)\",\"file\":\"$UPS_SHUTDOWN\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
    return
  fi
  # The daemon wrote its ledger before asking; this flushes it and the journal
  # to disk, then syncs, as the last things done before the power goes.
  journalctl --flush >/dev/null 2>&1 || true
  journalctl --sync >/dev/null 2>&1 || true
  sync
  emit "{\"ok\":true,\"action\":\"poweroff\",\"reason\":\"$reason\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
  $POWEROFF_CMD >/dev/null 2>&1 || emit "{\"ok\":false,\"why\":\"the power-off command failed\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
}

# Stop one unit on the way down, gracefully. systemd sends SIGTERM and waits;
# this sends nothing itself and kills nothing. The unit must be on the
# operator's root-owned stop list, which also fixes the window: the longer of
# `timeout` and `grace`. systemd's own stop timeout is raised for this run to
# outlast that window, so nothing is escalated to SIGKILL before it. An
# operator-set `stop=` command (a service's own safe-stop) runs first.
stop_unit() {
  id=$1; reason=$2; nonce=$3
  case "$id" in
    ''|-*|*[!A-Za-z0-9._@-]*)
      emit "{\"ok\":false,\"why\":\"not a unit name\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"; return ;;
  esac
  if [ "$reason" != "ups-halt" ]; then
    emit "{\"ok\":false,\"why\":\"a stop is only taken for the ups ladder\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"; return
  fi
  if ! ups_armed; then
    emit "{\"ok\":false,\"why\":\"this node is not armed for a ups shutdown (dry run, or the kill switch is present)\",\"id\":\"$id\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"; return
  fi
  line=$(awk -v id="unit=$id" '{for(i=1;i<=NF;i++) if($i==id){print; exit}}' "$UPS_STOP_LIST" 2>/dev/null | head -1)
  if [ -z "$line" ]; then
    emit "{\"ok\":false,\"why\":\"not on this machine's ups stop list\",\"id\":\"$id\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"; return
  fi
  t=$(printf '%s\n' "$line" | tr ' ' '\n' | sed -n 's/^timeout=//p' | head -1)
  g=$(printf '%s\n' "$line" | tr ' ' '\n' | sed -n 's/^grace=//p' | head -1)
  safe=$(printf '%s\n' "$line" | tr ' ' '\n' | sed -n 's/^stop=//p' | head -1)
  case "${t:-60}" in *[!0-9]*) t=60 ;; esac
  case "${g:-0}" in *[!0-9]*) g=0 ;; esac
  t=${t:-60}; g=${g:-0}
  win=$t; [ "$g" -gt "$win" ] && win=$g
  start=$(date +%s)
  if ! systemctl set-property --runtime -- "$id" "TimeoutStopSec=$((win + 15))" >/dev/null 2>&1; then
    emit "{\"ok\":false,\"why\":\"could not raise the unit's stop timeout above its window; refusing to risk an early kill\",\"id\":\"$id\",\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"; return
  fi
  if [ -n "$safe" ]; then
    # Only a root-owned file nobody else can write is ever run as root.
    if [ -x "$safe" ] && [ "$(stat -c %U "$safe")" = root ] && [ -z "$(find "$safe" -perm /022 2>/dev/null)" ]; then
      timeout "$win" "$safe" >/dev/null 2>&1 || true
    fi
  fi
  systemctl --no-block stop -- "$id" >/dev/null 2>&1
  timed_out=false
  while systemctl is-active --quiet -- "$id" || [ "$(systemctl is-active -- "$id" 2>/dev/null)" = deactivating ]; do
    if [ $(( $(date +%s) - start )) -ge "$win" ]; then timed_out=true; break; fi
    sleep 1
  done
  elapsed=$(( $(date +%s) - start ))
  killed=false
  [ "$(systemctl show -p Result --value -- "$id" 2>/dev/null)" = timeout ] && killed=true
  state=$(systemctl is-active -- "$id" 2>/dev/null || echo inactive)
  emit "{\"ok\":true,\"action\":\"stop_unit\",\"id\":\"$id\",\"state\":\"$state\",\"elapsed\":$elapsed,\"timed_out\":$timed_out,\"killed\":$killed,\"nonce\":\"$nonce\",\"at_ms\":$(now_ms)}"
}

# Whether an applied value leaves the machine in a state it is safe to be
# stranded in. Only `max_perf_pct` at or above the safe level qualifies —
# everything else is treated as held, because a governor or a package cap left
# behind by a dead controller has the same problem as a throttle.
is_safe_state() {
  [ "$1" = "max_perf_pct" ] && [ "$2" -ge "$SAFE_PERF_PCT" ] 2>/dev/null
}

last=""
while true; do
  if [ -r "$INTENT" ]; then
    body=$(cat "$INTENT" 2>/dev/null || echo "")
    if [ -n "$body" ] && [ "$body" != "$last" ]; then
      last="$body"
      lever=$(printf '%s\n' "$body" | sed -n 's/^lever=//p' | head -1)
      value=$(printf '%s\n' "$body" | sed -n 's/^value=//p' | head -1)
      nonce=$(printf '%s\n' "$body" | sed -n 's/^nonce=//p' | head -1)
      action=$(printf '%s\n' "$body" | sed -n 's/^action=//p' | head -1)
      kind=$(printf '%s\n' "$body" | sed -n 's/^kind=//p' | head -1)
      id=$(printf '%s\n' "$body" | sed -n 's/^id=//p' | head -1)
      slice=$(printf '%s\n' "$body" | sed -n 's/^slice=//p' | head -1)
      swap=$(printf '%s\n' "$body" | sed -n 's/^swap_mb=//p' | head -1)
      if [ -n "$lever" ]; then
        apply "$lever" "$value" "$nonce"
        if is_safe_state "$lever" "$value"; then held=""; else held="$lever"; fi
      elif [ "$action" = "bound_memory" ]; then
        # Not a held state: a bound stays until changed and is not something
        # the dead-man switch should revert -- reverting it would restore the
        # unbounded swap that caused the outage in the first place.
        bound_memory "$slice" "$swap" "$nonce"
      elif [ "$action" = "restart" ]; then
        # Not a held state: a restart happens once and leaves nothing behind
        # for the dead-man switch to revert.
        restart_workload "$kind" "$id" "$nonce"
      elif [ "$action" = "reset_accelerator" ]; then
        # Not a held state: a reset happens once. The dead-man switch has
        # nothing to revert, and must certainly not re-reset a card.
        reset_accelerator "$id" "$nonce"
      elif [ "$action" = "stop_unit" ]; then
        reason=$(printf '%s\n' "$body" | sed -n 's/^reason=//p' | head -1)
        stop_unit "$id" "$reason" "$nonce"
      elif [ "$action" = "poweroff" ]; then
        # Not a held state either: nothing to revert.
        reason=$(printf '%s\n' "$body" | sed -n 's/^reason=//p' | head -1)
        poweroff_node "$reason" "$nonce"
      elif [ "$action" = "shed" ]; then
        # Also not a held state, and deliberately so. The dead-man switch
        # restores the CPU when the controller dies; it must not restart work
        # the site shed, because relaunching jobs somebody decided to lose is
        # not a safe state to be stuck in.
        shed_workload "$kind" "$id" "$nonce"
      fi
    fi
  fi

  # Checked every pass, including passes where no new intent arrived — which is
  # the only kind of pass that happens once the controller is dead.
  if [ "$(heartbeat_age)" -gt "$HOLD_SECS" ]; then
    revert_to_safe
  fi

  sleep 2
done
