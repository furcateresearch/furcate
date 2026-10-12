# 0003 — Who holds a cluster's keys

Date: 2026-10-11. Status: decided by the owner.

## Decision

- **Machines with a TPM hold the cluster's keys.** Custody of sealed data, the site CA roots and the operator-sealed material is placed only on TPM-class machines when the cluster has any.
- **A cluster with no TPM relies on silicon fingerprinting, when the operator allows it.** This is an explicit operator setting in site policy, off by default: without it, a cluster with no TPM refuses custody and says why. With it, custody falls to the strongest silicon-held secret the cluster has, in this order: a key the silicon derives from its own physical fingerprint or holds in read-protected fuses and never reveals (a PUF or eFuse key, `Device` class), and only then readable silicon characteristics (`Soft` fingerprint), which prove continuity rather than unforgeability.
- **The operator decides who holds custody.** By default custody is elected automatically, TPM-class machines first, spread over more than one machine where the cluster has them so no single machine is a point of failure. The operator can instead designate the holders, for example a Jetson-class Hub with a TPM, through a signed site-policy change recorded in the ledger. A designation can never place custody below the minimum class the policy allows, and a machine below TPM class is only eligible when TPM-less custody has been enabled.
- **Three custody modes, chosen by the operator in site policy:**
  1. **Elected** (default): custody elected automatically, TPM-class first, over more than one machine.
  2. **Designated**: the operator names the holders, for example a Hub with a TPM.
  3. **Self-custody**: every machine holds only its own keys and sealed data, rooted in its own silicon (its TPM where it has one, otherwise its silicon fingerprint when TPM-less custody is enabled). No machine holds anything for another; anything site-wide is held per machine, as the site CA already is (one root per machine, in that machine's own hardware).
  Changing mode is a signed policy change recorded in the ledger, and every sealed object records the mode and class it was sealed under.
- **"TPM-class" means a machine that can quote its boot state** (TPM or DICE). Trusted execution environments, secure elements (including a vendor secure enclave, which keeps the vendor out of the default trust root) and fuse or PUF keys are eligible only when the operator has enabled TPM-less custody; readable fingerprints only when the operator has also allowed them.
- **The custody class is always stated.** A cluster reports which class holds its keys, and policy, placement and evidence exports can require a minimum. Nothing is generated at random in software as a fallback.

## Consequence for the code

Today the identity layer refuses custody of sealed data to any machine below a hardware-bound class. Implementing this decision means: electing custody holders by class across the cluster (TPM first), allowing `Device`-class (and, if the operator also allows it, `Soft`) silicon keys to hold custody when the cluster has no TPM and the operator has enabled TPM-less custody in site policy — the setting itself is a signed policy change recorded in the ledger, and recording the custody class with every sealed object.

## Keys and identities are persistent

The same approach the Furcate servers already run on. A machine's identity and the keys it holds survive reboots, image updates, reinstalls and `furcate convert` / `furcate revert`, so a machine is always the same machine.

- **TPM machines:** identity and custody keys are TPM objects kept at fixed persistent handles, never evicted, and re-derivable from the TPM's own primary seed with the same template. They change only when the TPM itself is cleared, which happens only on a signed `crypto_erase`.
- **Silicon-fingerprint machines:** keys are re-derived deterministically from the silicon on every boot (PUF or read-protected fuse key; readable characteristics for the weakest class), so persistence comes from the silicon rather than from storage.
- **Leaves:** the one hardware-held key is fixed by the silicon for the life of the leaf.
- **Never carried by an update:** sealed objects, enrolment records and chain data live outside anything an image update writes. An update replaces `/usr`; it never touches identity.
- **Verified, not assumed:** conversion, update and revert check that every sealed key comes back byte-identical, as the first conversions already did on the production servers.
