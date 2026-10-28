# Small processing node: deploying it on a board

What it is and what it checks is in
`crates/open/furcate-sense/docs/small-processing-node.md`.
This page is how to put the program on a Raspberry Pi 5 running Furcate and
check it.

Files here:

- `build-aarch64.sh`: cross-builds `furcate-small` for 64-bit Arm from a pushed commit and prints its SHA-256.
- `deploy.sh`: installs the binary under `/opt/tools` and the unit under `/etc/systemd/system`. Enables nothing.
- `verify.sh`: reads the node's identity and replays a recorded capture on the board, in memory.
- `furcate-small-node.service`: the unit. It is inert without `/etc/furcate/small-node.env`.
- `small-node.env.example`, `directory.example.json`: the configuration it reads.

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

## Turning the service on

Only after the above, and only when a micro processing node is enrolled:

1. Write `/etc/furcate/small-node/directory.json` from `directory.example.json`: the micro processing node's attachment record (its id and public key from its own enrolment, and its key custody) and the id enrolment gave the sensing node behind it. The class of each node is derived from the custody record, so a record that overstates nothing needs no care and one that does is graded down.
2. Write `/etc/furcate/small-node.env` from `small-node.env.example`.
3. `sudo systemctl enable --now furcate-small-node.service`, then `journalctl -u furcate-small-node`. Refusals are in `/var/lib/furcate-small-node/refusals.jsonl`, outcomes in `results.jsonl`, escalations in the file named by `--forward`.

To remove it: `sudo systemctl disable --now furcate-small-node.service`, delete `/etc/systemd/system/furcate-small-node.service` and `/opt/tools/furcate-small`, `sudo systemctl daemon-reload`.

## What is not here

- The link from a micro processing node to the program's socket. The program reads one JSON frame per line on `--listen unix:PATH`; whatever carries a micro node's frames on this board writes them there.
- Carrying escalations to a medium or large node. They are appended to a file or a socket; the transport that sends them on is separate.
- The binary is not in the release manifest, so a base update does not carry it. Adding it there is a change to the release, made with whoever owns the release.
