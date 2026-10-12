# deploy

Files that turn the Rust crates into an installed Furcate node: the release
manifest and the installer that reads it, the systemd units, sysusers and
tmpfiles declarations, the overlay helper, the runtime assembler, the hardware
registry and the parts registry. Only the files listed below are part of this
tree.

## Release

- `release/manifest`: what a release ships, declared once. Each row names the
  Debian package that owns a file, where it ships (`pkg`, `ext`, `all`,
  `model`), which editions carry it, its mode, its source path and its
  destination. A unit, helper or tmpfiles line that is not listed here does not
  ship anywhere.
- `release/install`: installs what the manifest lists for one consumer.

  ```
  deploy/release/install deb   <edition> <bin-dir> <root-pattern>
  deploy/release/install ext   <edition> <bin-dir> <root>
  deploy/release/install stage <edition> <bin-dir> <root>
  deploy/release/install model <edition> <bin-dir> <root>
  deploy/release/install --list <deb|ext|stage|model> <edition>
  ```

  `ext` builds the board extension, `model` the model-server extension, `stage`
  a host rollout stage. Every artifact is built through this script; none names
  a file of its own. It refuses a binary whose edition mark does not match the
  edition being installed.
- `runtimes.sh`: assembles the runtimes that ship inside the system extension
  (a JavaScript runtime, a Python package manager and `llama-server` for local
  inference) into a tree that becomes `/usr`.

  ```
  deploy/runtimes.sh [--arch x86_64|aarch64] [--only node,python,llama] <out-dir>
  ```

## systemd

- `systemd/furcated.service`: the node agent, run as the unprivileged `furcate`
  user.
- `systemd/furcate-wg.service`: the overlay interface manager. It runs
  `furcate-wg.sh`, which applies a WireGuard peer set on behalf of the agent so
  the agent itself never holds network-admin capability.
- `systemd/furcate-names.service` and `systemd/furcate-names-link.service`:
  answer `<member>.<site>.internal` on the overlay address (`furcate-overlay
  names`) and route the site zone to the overlay interface.
- `systemd/furcate-overlay-reflect.service`: tells a sender the address its
  packet came from (`furcate-overlay reflect`), for nodes with a public
  address.
- `sysusers/furcate.conf`: the account Furcate's services run as.
- `tmpfiles/furcate.conf`, `tmpfiles/furcate-runtime.conf`,
  `tmpfiles/furcate-state-keys.conf`: what unit directory settings cannot
  express, ownership of `/run/furcate`, and ownership of the sealed key
  directories, repaired on every boot.

## Overlay

- `furcate-wg.sh`: the privileged helper described above.
- `overlay/overlay.env.example`: template for `/etc/furcate/overlay.env`, the
  node's overlay names and paths (site zone label, overlay address). Copy it
  into place and fill it in; nothing reads the example.

## Registries

- `hardware/machines/*.json` and `hardware/components/**`: the machine and
  component registry `furcate-host` uses to recognise hardware (board, BMC, CPU,
  memory, disk, fans, PSU) and decide which controls may be attempted on it.
- `os/arms.toml`: the parts of Furcate (network, storage, power, security,
  software update and others), each with a name, where to look at it and how to
  change it. `furcate-console` reads it at build time.
- `os/furcate-release.crt`: the certificate signed release images and system
  extensions are verified against. The OS image carries the same file under
  `/usr/lib/verity.d/`, and `os/build.sh` refuses to build if the two differ.

## Use

These files are consumed by the OS image build under `os/` and by
`release/install`; they are not run by hand on a node except
`release/install --list`, which prints what would be installed without
installing anything.
