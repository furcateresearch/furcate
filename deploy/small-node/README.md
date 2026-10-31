# Small processing node: deploying it on a board

What it is and what it checks is in
`crates/open/furcate-sense/docs/small-processing-node.md`.
This page is how to put the program on a Raspberry Pi 5 running Furcate and
check it.

Files here:

- `build-aarch64.sh`: cross-builds `furcate-small` and `furcate-leaf-link` for 64-bit Arm from a pushed commit and prints the SHA-256 of each.
- `deploy.sh`: installs the binary under `/opt/tools` and the unit under `/etc/systemd/system`. Enables nothing.
- `verify.sh`: reads the node's identity and replays a recorded capture on the board, in memory.
- `furcate-small-node.service`: the unit. It is inert without `/etc/furcate/small-node.env`.
- `small-node.env.example`, `directory.example.json`: the configuration it reads.
- `furcate-leaf-link.service`, `deploy-link.sh`, `leaf-link.env.example`, `leaves.example.json`: the bridge from a micro processing node's session into the program's input (below). `deploy-link.sh` does for `furcate-leaf-link` what `deploy.sh` does for `furcate-small`.

## Before anything

1. The board is free: nobody is measuring it and no update is planned for it. `deploy.sh` refuses without `--released` so this is a decision, not a default.
2. The commit to deploy is pushed, and the binary is built from exactly that commit.
3. The board's node identity is not touched by any step here. `furcate-small identity` opens the signing broker and reads the public key; it signs nothing and enrols nothing.

## Steps

From a checkout of the pushed commit, on a Linux build host with the Arm cross linker and a target directory of its own:

```
CARGO_TARGET_DIR=$HOME/target-small deploy/small-node/build-aarch64.sh
```

Copy the binary to the host you deploy from, then:

```
deploy/small-node/deploy.sh --released ./furcate-small <sha256 printed above> \
    ssh JUMP-HOST ssh -o BatchMode=yes furcate@BOARD-ADDRESS
deploy/small-node/verify.sh crates/open/furcate-sense/tests/fixtures/nicla-standalone-usb.txt \
    ssh JUMP-HOST ssh -o BatchMode=yes furcate@BOARD-ADDRESS
```

`verify.sh` passes when `identity` prints the board's node id with class `device` and backend `rpi-fw-crypto`, and `replay` ends with two lines starting `next rung accepts an escalated item` and exit status 0.

## Signing through the board's broker

`furcate-small serve` and `furcate-leaf-link serve` sign with the board's OTP device key. They do
not open the firmware mailbox: on a Furcate OS board the key is used only through a broker, and
that is what the unit and the program are written for. This is everything reaching it takes.

| What | Value | Set by |
|---|---|---|
| Socket | `/run/furcate-os/fwcrypto.sock` | `furcate-fwcrypto-broker.socket` (`os/boards/rpi5/fwcrypto`) |
| Socket owner and mode | `root:furcate-fwcrypto`, `0660` | the same socket unit (`SocketGroup`, `SocketMode`) |
| Peer user | `root` or `furcate`, by `SO_PEERCRED` | the broker. Any other uid is answered `peer not allowed`, a member of the group or not |
| Peer group | `furcate-fwcrypto`, as a supplementary group, so the connect is allowed by the socket mode | the group is made by `furcate-fwcrypto.sysusers` (`g furcate-fwcrypto -`); it has no members |
| Key and calls | key 1; `pubkey` and `sign` (ECDSA P-256 over SHA-256); nothing else | the broker |
| Unit options | `User=furcate` and `SupplementaryGroups=furcate-fwcrypto` | `furcate-small-node.service`, `furcate-leaf-link.service` |
| Not needed | `DeviceAllow=/dev/vcio*`, `PrivateDevices=false`, `/etc/furcate/fwcrypto-direct` | the unit never opens the device. The direct path exists for a board with no broker, and is not tried while the broker's socket is there |

So the two units carry what is needed, and the user and the group are both required: the user
alone is refused at the socket, the group alone is refused by the broker.

A hand-run program is different. A login shell as `furcate` has the user and not the group, and
fails on connect with `connecting to the signing broker at /run/furcate-os/fwcrypto.sock:
Permission denied`. `deploy.sh`'s last step and `verify.sh` read the identity over ssh as `furcate`, so they are this
case and fail the same way unless the session has the group; both now say so when they fail. `peer not allowed` means the wrong user (not `furcate`
and not root); a missing socket means `furcate-fwcrypto-broker.socket` is not started, or the
base is not Furcate OS.

Two ways to give a hand-run program the group. Neither has been applied to the board: whether to
is the release owner's decision.

1. **No change to the board.** Run the command as a transient unit with the group, which is what
   the service does:

   ```
   sudo systemd-run --quiet --pipe --wait --collect --uid=furcate \
       --property=SupplementaryGroups=furcate-fwcrypto \
       /opt/tools/furcate-small identity --backend rpi-fw-crypto
   ```

   Nothing is persisted and no account changes. It has not been run on the board.
2. **Make `furcate` a member** by adding `m furcate furcate-fwcrypto` to
   `os/boards/rpi5/fwcrypto/furcate-fwcrypto.sysusers`. That is a base change: from the next
   base update every process the `furcate` account runs, including its login shells, can ask the
   broker to sign, where today only units that name the group can. The broker's own uid check is
   unchanged.

## Turning the service on

Only after the above, and only when a micro processing node is enrolled:

1. Write `/etc/furcate/small-node/directory.json` from `directory.example.json`: the micro processing node's attachment record (its id and public key from its own enrolment, and its key custody) and the id enrolment gave the sensing node behind it. The class of each node is derived from the custody record, so a record that overstates nothing needs no care and one that does is graded down.
2. Write `/etc/furcate/small-node.env` from `small-node.env.example`.
3. `sudo systemctl enable --now furcate-small-node.service`, then `journalctl -u furcate-small-node`. Refusals are in `/var/lib/furcate-small-node/refusals.jsonl`, outcomes in `results.jsonl`, escalations in the file named by `--forward`.

To remove it: `sudo systemctl disable --now furcate-small-node.service`, delete `/etc/systemd/system/furcate-small-node.service` and `/opt/tools/furcate-small`, `sudo systemctl daemon-reload`.

## The link from a micro processing node

`furcate-leaf-link` is the missing piece between the two ends. It is the host side of the micro
processing node's session (crate `furcate-leaf-link`; the micro node's firmware is the separate
leaf firmware repository): it answers the leaf's HELLO with the board's signature and the
operator's grant, asks for readings, checks each reading's signature against the key the leaf was
enrolled with, and writes one `reading` frame per line for the program above. The class it claims
for a frame is the lower of the board's key and what the leaf's enrolment earns.

```
leaf (ESP32-class)  --Wi-Fi, FL1 lines-->  furcate-leaf-link  --unix socket, JSON frames-->  furcate-small
```

1. Enrol the leaf. This is the operator's decision, once. With the leaf powered and dialling this
   board, `furcate-leaf-link enrol --link listen://0.0.0.0:7781` waits for one HELLO and prints the
   entry to review. It sends nothing to the leaf. Set `custody` from what you know of how the
   leaf's key is held, not from the label the leaf prints about itself.
2. Write `/etc/furcate/leaf-link/leaves.json` from `leaves.example.json` and the operator's grant
   for this board's key as `/etc/furcate/leaf-link/grant.json`. Give the bridge an id that is not
   the small node's own: both use this board's key, and a chain may not name a rung twice.
3. `furcate-leaf-link directory --config /etc/furcate/leaf-link/leaves.json --backend rpi-fw-crypto`
   prints the part of the small node's `directory.json` that names this bridge as the processing
   node of record for each sensing node. Merge it in. The same key signs the bridge's frames and the
   small node's own, so enrol the bridge with the same custody the board's key earns.
4. `/etc/furcate/leaf-link.env` from `leaf-link.env.example`, then
   `sudo systemctl enable --now furcate-leaf-link.service`. The unit is inert without the file.

Port 7781 is also the leaf head's. A leaf is served by one of the two; the head only reports the
leaf's status, the link carries its readings.

What is checked is in the crate's `README.md`. It is tested end to end against a simulated leaf
that signs with a test key. It has not been run against a real leaf: that needs the leaf to receive
the node's AUTH, which is a protocol write to the board and waits for the owner's go-ahead.

## When a leaf's key changes (identity rollover)

A leaf whose key moves to a new one (an ESP32-S3 after its eFuse HMAC key is burned gets a new leaf id) is not a new unit: it signs a rollover record with its old key, its new key and the operator, and the roster moves the enrolment across. The command runs on the node that holds the roster file (`/etc/furcate/leaf-link/leaves.json`):

```
furcate-leaf-link rollover --config /etc/furcate/leaf-link/leaves.json \
    --record s3-rollover.fli1 --operator-pub <hex of the operator key the leaf pins> \
    --proven-assurance efuse-hmac/development
```

- `--proven-assurance` is what the successor reported in a live, verified session (INFO tag 60). It comes from that session and never from the record; the record's claimed level may not exceed it.
- The command has no dry run. Run it on a copy of the file first (`cp leaves.json /tmp/leaves-copy.json`, point `--config` at the copy, check the result loads), then on the live file. It keeps the live file as `leaves.json.before-rollover-<time>` and replaces it only if the record verifies.
- The leaf's `key` becomes the new key with a `fuse-key` custody, and the old id is listed under `retired`, so presenting it again is refused and so is the same record twice.
- `serve` reads the file at start: restart `furcate-leaf-link` after the rollover, and do not run it while the old identity has a live session.
- A refusal (wrong operator, claimed level above the proven one, outside the record's window, a leaf the file does not hold, a replayed sequence) leaves the file as it was.

## What is not here

- A resumable per-leaf log. After a bridge restart the bridge's log for each leaf starts again at entry 1, and the small node's witness refuses that as a repeat of entries it has already witnessed. `furcate_sense::cascade::witness::LeafLog` has no way to resume from a saved head and the witness has no reset, so neither is built; until one is, restart the small node's witness state for that leaf together with the bridge.
- Carrying escalations to a medium or large node. They are appended to a file or a socket; the transport that sends them on is separate.
- The binary is not in the release manifest, so a base update does not carry it. Adding it there is a change to the release, made with whoever owns the release.
