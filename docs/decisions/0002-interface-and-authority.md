# 0002 — Headless everywhere; the passkey assertion is the order

Date: 2026-10-11. Status: approved by the owner.

## Decisions

1. **No Desktop edition.** Furcate OS is headless on every machine. "Desktop" is the web interface every node serves, plus a tablet and phone app that wraps the same interface. A screen on a machine, if ever wanted, is an optional kiosk system extension pointing at the node's own interface, never a second UI.
2. **The passkey assertion is the signed order.** Each target node verifies the WebAuthn assertion itself. The challenge is the hash of the canonical order with a node-issued nonce and an expiry, so an approval binds exact bytes. No key is derived from a passkey and no private key exists in a browser; the earlier in-page Ed25519 key wrapped by the passkey PRF is retired.
3. **Agents propose, people approve.** One API: proposals from people or agents, orders carrying one or more passkey assertions, thresholds set by governance, independent credentials counted once per sync account.
4. **`isolate` is a node isolating itself.** It drops the node's own reach. It never removes a peer from the overlay, consistent with the overlay invariant that refuses that.
5. **A minimal multi-node site view is open**, so a home lab with several machines runs on the open edition.

Design: [research/interface-and-control.md](../research/interface-and-control.md).

## Passkey rules shared with the wallet methodology (2026-10-11)

Furcate keeps the same passkey principles as the wallet design it sits beside, so one person's passkeys behave the same way everywhere:

- **Per-credential RP ID.** Each enrolled credential keeps its own RP ID and is verified against it and its origin. There is no central related-origins list; the site's RP ID is only the default for the first enrolment.
- **Independence is proved, not declared.** Independent roots are distinct providers by AAGUID, or device-bound credentials, read from the registration authenticator data at enrolment. Two passkeys in one sync account count once.
- **Synced passkeys are allowed.** User verification is required; backup-eligible or backed-up credentials are not refused.
- **Adding a passkey while a site has fewer than two independent roots** is delayed with a cancel window (default 48 hours, governance-configurable) that any existing passkey can use. At two or more roots it follows the normal threshold.
- **Enrolment proves itself.** A new credential's AAGUID and backup flags come from its registration data, over a node-issued challenge.
- **No key is ever derived from a passkey.**
