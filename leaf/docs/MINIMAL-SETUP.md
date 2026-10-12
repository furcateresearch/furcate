# Minimal Furcate hardware setup: Pi 5 + leaf

The smallest real Furcate site has two devices:

- a **Pi 5** running Furcate OS (booting from a USB drive), as the authorised node;
- this **ESP32** running the leaf firmware, as its leaf.

It is tested after the bench test (TEST-RESULTS.md), in which a Mac with its Secure Enclave plays the authorised node. A control server with a TPM can stand in for the Mac when the Mac is asleep.

## Reference topology and where this fits

```
operator (Mac / Windows / Linux / control server / a hosted Furcate console)
   |  signs the grant for the Pi's key (passkey, Secure Enclave or TPM)
Pi 5 (Furcate OS, gateway tier)       <- this test
   |  leaf connects OUT to the Pi over Wi-Fi
ESP32 leaf
```

Adding a Jetson above the Pi later changes nothing for the leaf. With delegation (DESIGN.md section 8.3), the Pi's grant is signed by the Jetson within the operator's limits.

## Prerequisites

1. **Pi 5 with Furcate OS.** It has the Furcate extension, which includes the leaf connector (Furcate monorepo, see PENDING.md).
   - The Pi's identity comes from its silicon fingerprint path, per the owner's decision, or from a TPM HAT if fitted.
   - Its assurance class is shown on the console at first boot.
2. **Leaf firmware with the Wi-Fi transport** (PENDING.md, phase 2). It is installed by signed OTA from the bench setup, not by a reflash.
3. **The operator key** on the operator machine: passkey, Secure Enclave or TPM.
4. **The development registry** holding the release-signed person-detection model.

## Steps

1. **Enroll the Pi.**
   - Boot the Pi and read its node ID and public key from the console.
   - Approve it in the Furcate console with the operator passkey. The roster records it.
2. **Issue the Pi a short-lived grant for the leaf.**
   - On the operator machine: `host/fl.py grant <pi-node-key> read,command,model 2 --leaf <leaf-id>`.
   - The grant is scoped to this leaf and its generation is 2. When the test ends, revoke it by raising the leaf's minimum generation to 3.
   - Copy the grant (public data plus signature) to the Pi: over the LAN, or on USB if the site is air-gapped.
3. **Give the leaf its parent list.** Send a signed configuration item: the Pi's address and port, plus the expected node key. Send it over the bench session (the Mac node, `config` role).
   - The Wi-Fi credentials go in the same signed item. They are site credentials, not key material.
4. **Leaf connects out.**
   - The leaf reboots and dials the Pi.
   - The Pi presents its grant and signs the transcript with its hardware key.
   - The leaf verifies, and FINISH completes. Check the Pi's connector log for "session up" with the leaf ID.
5. **Model load through the Pi.**
   - The Pi's connector fetches the model and manifest from the registry (or its cache) and offers them to the leaf.
   - Expected: OFFER accepted (release threshold met), CHUNKs written, COMMIT passes the self-test, active slot switched.
6. **Inference results flow to the Pi.**
   - The Pi sends INFER with test images, or the leaf runs its own sensor loop.
   - Results (label, score, latency) arrive at the Pi and are published as leaf readings into the cluster.
   - Check that no raw input leaves the leaf under the default results-only policy.
7. **Negative checks.**
   - A Pi grant signed by a non-operator key is refused.
   - A revoked generation is refused.
   - A grant without the `model` role cannot load a model.
   - With the leaf not dialling, no connection to it is possible at all, because it has no listener.
8. **Air-gapped variant.** Disconnect the site's uplink and repeat steps 5 and 6 with the model imported on USB into the Pi's cache. The leaf behaves identically.

## Pass criteria

- The leaf completes a session only with the granted Pi key.
- A model is loaded and activated at runtime with no reflash, and results reach the Pi.
- Every refusal names its reason in the leaf log and on the Pi.
- Re-parenting back to the bench node needs only a new grant and parent list. No reflash.
