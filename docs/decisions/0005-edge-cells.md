# 0005 — Edge cells: nested clusters with local control

Date: 2026-10-11. Status: decided by the owner.

## Decision

- **A site is a core cluster plus edge cells.** A cell is a gateway head, optionally an edge AI node, and its leaves, parented by a controller. A cell is a full Furcate cluster in its own right, with its own membership, placement, workloads, updates, registry cache, policy and console.
- **Cells nest.** A city cell can contain district or business cells, each with its own head and local control; nested cells are clusters of clusters. Cells are typed by scale (home, business, city, and so on) for views, policy and limits.
- **The tree is the signed control chain**, at any depth: operator, then controller, then cell head, then leaves. It is derived from the delegations, not from manual tags, so the view cannot drift from the trust structure. The operator's own workstation is never in the control path.
- **Control is local at every level.** A cell runs autonomously when cut off (local control, registry cache, escalation through the mesh), is air-gap native and quorumless, and syncs on reconnect.
- **Ownership rolls up; control never routes up.** The operator's ownership view shows every cell as an owned asset: inventory, health, power, cost. It reads; it never grants control.
- **Furcate's console is its own interface.** It is node-served and air-gap capable, and every cell has one. Metal is a separate product surface that only consumes Furcate's data.
- **Scope is enforced by signed delegations checked by the nodes**, not by hiding things in a UI:
  - a cell knows only its controller's public key and endpoint, never the rest of the operator's fleet;
  - it sends only roll-ups upward;
  - a cell's delegated managers (for example a business or city admin holding a passkey delegation scoped to that cell) see only that cell and its sub-cells.
  The same rule applies when an upper tier is someone else's infrastructure: the cell's owner manages their own cluster and sees only their own allotment and endpoints.
- **Per-tier views.** Machines show cores, power and workloads; leaves show sensors, models, streams, battery and signal; a cell rolls up to one health line.

## Leaf identity (2026-10-12)

- **A leaf's class is derived from how its key is held, never stated.** The attachment record describes the key's custody (stored, readable identifiers, SRAM fingerprint, or a fuse or key-peripheral key, with the part's secure boot, flash encryption, download and JTAG fuses). The head derives the class from that in one place, `furcate_identity::LeafKeyCustody::class`. The record format is `docs/interfaces/leaf-attachment.md`.
- **The line is whether anything is secret from the person holding the board.** A fuse-held key, or an SRAM fingerprint key on a part where only signed firmware runs and nothing can be read out, is `Device`, as decision 0003 already grades a PUF or eFuse key. An SRAM fingerprint on an open development part is `Soft`: anyone with a USB cable can flash a reader and rebuild the key. Readable identifiers are `Soft` always. No class is added between the two.
- **Each cell has a leaf floor**, the lowest class a leaf may hold to attach there: `device` unless the operator sets it otherwise for that cell (`furcatectl cell leaf-floor`, or `--leaf-min-class` on enrol and renew). It is carried in the head's link, signed by the controller on an operator-signed request, so it changes only with the operator's signature. A leaf below the floor is refused and the refusal names the cell and the command. The floor is separate from key custody: admitting `soft` leaves to a cell never opens the site's keys to TPM-less machines, and decision 0003's `custody.allow_soft` and `custody.tpm_less` remain about node custody only.
- **Roll-ups are forward-compatible.** A parent reads the roll-up fields it knows and drops the rest, so a child on a newer release is still heard; nothing dropped is kept or sent further up.
- **Leaves sign with Ed25519 or P-256**, read and verified by the same key helpers as heads. A P-256 leaf is named by its key.
- **The class is recorded as derived** in the leaf's link, the cell tree, roll-ups (counted by class), the cell views and `furcatectl cell show`, and is never raised afterwards.
- Leaf identity is open (Apache-2.0): it is a trust claim, and the licensing rule puts every trust claim in the open crates.

## Ownership of the work

- Cell model, delegation scope, console tree and roll-ups, in the furcate repo: the Furcate core session.
- Device side (Pi gateway enrolment, OTP device key, leaf link, OS image, leaf firmware): the edge-devices session.

## Evaluate before adopting (owner, 2026-10-11)

"We test, verify the benefits, then decide." Proposals that would replace something already built are prototyped and measured against what ships first:

- **Biscuit capability tokens** (offline public-key verification, attenuation that can only narrow, Datalog policies carrying cell scope, time and budgets) against the cell delegations shipped in phase 1. Checks: P-256 roots (TPM, the gateway's firmware key and passkeys are P-256), offline attenuation, policy expressiveness, token size and verification cost on a gateway.
- **iroh** for the data plane against the WireGuard overlay (streams and datagrams, hole-punch success, CPU and memory on the gateway), with BLAKE3-verified resumable blob distribution measured separately as the likely keeper.

Direction already consistent with the design: consensus only for exclusive resources inside one cell (leases, a single actuator owner); delta-state CRDTs for shared state; one-way roll-ups upward, parents holding only their children's roll-ups. Research: `~/Documents/FURCATE-CELLS-RESEARCH-2026-10-11.md`, `~/Documents/FURCATE-TRANSPORT-IROH-2026-10-11.md`.
