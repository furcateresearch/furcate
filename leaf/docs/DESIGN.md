# Design

## 1. What a Furcate leaf node is

A Furcate leaf node is a microcontroller member of a Furcate cluster. It does not gossip or take part in consensus. Instead it attaches to parent nodes (Pi- or Jetson-class Furcate nodes), sends them readings and inference results, and takes commands, models and firmware from them. It reports its assurance class honestly and never claims more than its silicon offers.

This matches the cluster side, which already models microcontrollers as the `Leaf` tier and keeps leaf attachment and signed readings in the Furcate monorepo.

## 2. Layers

| Furcate OS on Pi / Jetson | Furcate leaf node |
|---|---|
| Base system in A/B slots, rare updates | **Firmware in A/B app slots** (`ota_0`, `ota_1`), with rollback |
| Furcate as signed extensions, frequent updates | **Models as signed artifacts** in their own `models` partition (two slots), updated without reflash or reboot |
| Identity in the TPM, survives every update | **Identity derived from the silicon** on every boot (development board), or held by the chip's key engine (production boards). It survives every update. |
| Compatibility checked by Furcate, loudly; last good version kept | Capability checked by the leaf before staging; a refusal names its reason; last good model kept |
| Releases signed by a threshold of TPM-held keys | Same signers and threshold; the leaf verifies P-256 signatures |

## 3. Boot sequence

1. **Silicon fingerprint.** The leaf reads 2 KB of SRAM that neither the ROM nor the bootloader touches, before anything else runs.
   - If the region still holds the marker written on the previous boot, the SRAM never lost power. An EN reset does not always remove it. The leaf then deep-sleeps for 200 ms, which powers SRAM down, and reads again.
2. **Identity.**
   - A 256-bit secret is reconstructed from the fingerprint, using helper data from enrollment: 7 stable cells per bit, majority vote.
   - It is combined with the factory MAC and expanded with HKDF into a P-256 private key.
   - The key is never stored. The leaf ID is SHA-256 of the public key.
   - With no fingerprint there is no identity, and the leaf does not communicate.
3. **Trust anchors.** The leaf holds pinned public keys only:
   - the operator set, which may authorise nodes;
   - the release set and its threshold, which may sign firmware and models.
4. **Model server.**
   - Load the active model, verify its digest and run its self-test.
   - If that fails, fall back to the previous model.
5. **Firmware health.** A freshly installed image that fails these checks is rolled back by the bootloader.
6. **Channel** (section 4).

## 4. Channel: one-way, operator-authorised

**The leaf has no listening surface.** In this build the radio is off and the only transport is the serial console. Over a network the same frames run over a connection the leaf opens to its parents. Every session starts with the leaf; anything that does not answer the leaf's own HELLO is ignored.

| Step | Direction | Content |
|---|---|---|
| HELLO | leaf to node | leaf public key, ephemeral P-256 key, nonce, evidence (MAC, chip revision, eFuse security state, firmware hash, fingerprint statistics, assurance class) |
| AUTH | node to leaf | node public key (its TPM / Secure Enclave key), ephemeral key, **grant**, operator signature on the grant, node signature over the transcript |
| FINISH | leaf to node | leaf signature over the transcript and the node's signature |
| REFUSE | leaf to node | sent instead of FINISH when any check fails; nothing else follows |

**The grant.**
- Format: `"FLG1" | node public key | roles | generation | leaf scope`, signed by a pinned operator key.
- Roles: `read`, `command`, `model`, `config`, `ota`.
- A grant authorises one node key. It is useless without that node's hardware-held private key.

**After FINISH.**
- Both sides derive per-direction AES-256-GCM keys with HKDF over the ECDH secret and the transcript hash.
- Records carry a counter nonce, and a replayed counter is dropped.
- Every command is checked against the grant's roles.

**Revocation.**
- An operator-signed `"FLR1" | minimum generation` raises the minimum grant generation the leaf accepts. It is stored in NVS.
- The leaf has no trusted clock, so freshness comes from generations, nonces and counters, not timestamps.

**Why a grant and not a shared key.** The operator never shares a secret with the leaf. The leaf holds only public keys, and every private key involved sits in hardware:

- the leaf's own key in its silicon;
- the node's key in a TPM or Secure Enclave;
- the operator's key in a passkey or TPM.

Copying the leaf's flash therefore gives an attacker no key that could open any other device.

## 5. Model server

### 5.1 Partition layout (4 MB development board)

| Partition | Offset | Size | Use |
|---|---|---|---|
| nvs | 0x9000 | 24 KB | Helper data, revocation generation, downgrade counter |
| otadata | 0xF000 | 8 KB | Active firmware slot |
| phy_init | 0x11000 | 4 KB | Radio calibration |
| ota_0 / ota_1 | 0x20000 / 0x1A0000 | 1.5 MB each | Firmware A/B |
| models | 0x320000 | 896 KB | Two slot tables (alternating, CRC-checked) at 0x0 and 0x1000; slot A at 0x10000; slot B at 0x78000; 416 KB each |

### 5.2 Manifest

A model ships as the model file in its runtime's format (TFLite Micro flatbuffer here, `.espdl` on ESP-DL targets) plus a manifest. The manifest is TLV, wrapped in an envelope that carries the release signatures.

| Field | Purpose |
|---|---|
| kind, id, version | catalogue identity |
| size, sha256 | integrity |
| runtime, runtime_min | capability: the leaf refuses runtimes it lacks, and models that need newer firmware |
| target (repeated) | capability: the chip family |
| arena_kb, needs_psram | capability: working memory |
| input (h, w, c, dtype) | fixed input contract |
| ops | operator codes. The leaf also checks the model's own operator table. |
| labels, pre, post | named, built-in pre- and post-processing. No code ever arrives with a model. |
| selftest seed + expected outputs + tolerance | checked before a swap is accepted |
| data policy | results only (default), results + features, or raw allowed |
| licence | required |

### 5.3 Load flow

All of this happens without a reflash or a reboot.

1. **OFFER.**
   - The release signatures are verified against the pinned set, with a threshold of 2 here.
   - The capability check runs: runtime, target, PSRAM, arena, slot size, operators.
   - If both pass, the inactive slot is erased.
2. **CHUNK.** The model file streams in, written at the next offset and hashed as it goes.
3. **COMMIT.**
   - The digest must match the manifest, or the slot is erased.
   - The slot is memory-mapped and the interpreter is built from it. Its operators are checked and its tensors allocated.
   - The self-test runs.
   - **Pass:** the slot table records active = new and previous = old.
   - **Fail:** the slot is marked failed and the previous model is reloaded.
   - Without PSRAM there is room for only one working-memory arena, so inference pauses for the swap. The swap time is measured and reported.
4. **ROLLBACK.** Returns to the previous model on command.
5. **At boot**, an active model that fails its check falls back to the previous one.

### 5.4 Results and data sharing

- `INFER` returns:
  - the output scores (int8) and the quantisation parameters;
  - the top label from the manifest;
  - the measured latency.
- The input is not echoed back or kept. Results flow to the parent over the authenticated channel, and the parent publishes them into the cluster as leaf readings.
- Features or raw samples leave the device only under a model's or operator's data policy that allows it.

### 5.5 Relation to the cluster's model catalogue

- Models come only through the catalogue, never sideloaded.
- In this phase the catalogue is a **development registry**: a directory of release-signed manifests and artifacts on the node, produced by `host/fl.py`.
- When the Furcate catalogue supports microcontroller entries (docs/PENDING.md), parents serve leaf models from it with the same manifest format.

## 6. Firmware update

1. `OTA_OFFER` carries a release-signed firmware manifest: sequence, size, sha256 and target.
2. The leaf refuses any sequence that is not newer than the one it has confirmed (downgrade protection).
3. Chunks are written to the inactive app slot. At `OTA_COMMIT` the leaf checks the digest, selects the slot and reboots on trial.
4. On first boot the new image must derive its identity and start its model server. If not, it calls the rollback path and the bootloader returns to the previous slot.
5. In this development build downgrade protection is a counter in NVS, and the bootloader does not check signatures. On a locked-down unit the bootloader enforces secure boot v2 and the eFuse secure version (docs/SECURITY.md).

## 7. Portability

| Interface | Classic ESP32 (development) | ESP32-C5 / ESP32-P4 (production) |
|---|---|---|
| `fl_identity.h` | `fl_identity_fingerprint.c`: SRAM fingerprint + MAC, key derived each boot | `fl_identity_hwkey.c`: Key Manager / ECDSA peripheral, key generated in the chip, signing in the peripheral (pending) |
| `fl_crypto.h` | mbedTLS (hardware SHA/AES) + micro-ecc P-256 | same interface; ECDSA/ECC hardware where present |
| Model runtime | TFLite Micro + ESP-NN | TFLite Micro + ESP-NN, ESP-DL on P4 |
| Capability check | target from the build (`CONFIG_IDF_TARGET`), PSRAM detected at run time | same |

## 8. Tiers and topology

### 8.1 Reference setup: a chain

```
operator tier   Mac / Windows / Linux machine, a control server (TPM), or a hosted Furcate console
     |            holds the operator key (passkey, Secure Enclave, TPM); signs authorisations
Jetson          edge AI tier: caches models from the Furcate registry, runs heavier models
     |
Pi              gateway tier: the leaf's usual parent; relays models, aggregates results
     |
leaf (ESP32)    sensing / tiny models; connects out to its parent only
```

What moves along the chain:

- **Authorisations** flow down, from the operator to the leaf.
- **Models** flow down: the registry, then the Jetson cache, then the Pi relay, then the leaf, which loads them.
- **Data and results** flow up: the leaf, then the Pi (aggregation), then the Jetson (heavier models), then the operator or the cluster.

### 8.2 Topology is flexible

The chain is one valid arrangement, not the only one. A leaf's parent is whatever Furcate node holds a grant for it. Supported arrangements:

| Arrangement | Leaf's parent | Use |
|---|---|---|
| Chain (reference) | Pi | sites with all tiers |
| Pi only | Pi | small sites, no edge AI box |
| Jetson direct | Jetson | vision leaves next to the AI box |
| Operator machine direct | Mac / Windows / Linux / control server | bench, development, tiny deployments |
| Cloud parent | a cloud-side Furcate node (a hosted deployment) | leaves on sites with internet and no local node |
| Several parents | two or more of the above, each with its own grant | redundancy: no single parent is a point of failure |

**Re-parenting needs no reflash.**

- The operator issues a grant for the new parent's key.
- The leaf's parent list (the endpoints it dials) is a signed configuration item. The grant authorises; the list only says where to dial.
- Old parents are cut off by raising the minimum grant generation (revocation).

### 8.3 Delegation down the chain (designed; phase 2)

Today the operator signs every grant directly (one level). That already supports every arrangement above. For the chain, the design adds bounded delegation:

- The operator signs a grant for the Jetson with a `delegate` limit: the most roles, depth and leaf scope the Jetson may pass on.
- The Jetson signs a grant for the Pi inside those limits. The Pi presents the chain `operator → Jetson → Pi` to the leaf.
- The leaf verifies each link with the next key and checks that each link only narrows roles, scope and depth. The maximum depth is set by the operator; 2 is proposed.
- Revoking at any level cuts everything below it. The leaf checks generations per link.
- The node keys signing these links are hardware-held: Jetson fTPM, Pi TPM or fingerprint path.

### 8.4 A hosted console as the operator tier

A hosted Furcate deployment with a web console can be the operator tier.

- **The operator key never sits on a server.**
  - Authorisations made in the console are signed in the browser by the operator's passkey (WebAuthn), or by their device key.
  - The hosted console relays and records the signed authorisations. It cannot create them.
- **Verifying a passkey-signed grant on the leaf.**
  - The leaf checks the WebAuthn assertion: P-256 over `authenticatorData ‖ SHA-256(clientDataJSON)`, where the challenge equals the grant's hash.
  - This needs a small verifier in firmware (pending). Grants signed by an operator TPM or Secure Enclave work as they do today.
- **Cloud-side Furcate nodes can be parents** like any other node. They hold a grant, and their key is held in their own hardware.

### 8.5 Deployment modes

Both modes use the same keys, the same signatures and the same artifacts. Nothing the leaf needs in order to run, or to be updated, depends on the cloud.

| | Air-gapped | Cloud-connected |
|---|---|---|
| Operator tier | an operator machine on the local network (Mac / Windows / Linux / control server); passkey or local Secure Enclave / TPM | a hosted console (passkey in the browser), plus any local operator machine |
| Authorisations | signed on the operator machine; carried down the local chain, or by a signed offline bundle (USB to the Jetson or Pi) | signed in the browser; relayed by the hosted console to the site's top node, then down the chain |
| Models and firmware | release-signed artifacts from the registry, imported on USB or over the LAN into the Jetson / Pi cache | pulled by the top local node from the registry through the hosted deployment |
| Data and results | flow up to the highest tier present on site | also escalate to the hosted deployment when allowed by data policy |
| Leaf behaviour | identical | identical |

**Moving between modes.**

- Going online means giving the site's top node a grant for the cloud relay, and adding the cloud parent or relay endpoint to the signed configuration.
- Going offline means revoking that grant's generation.
- Leaves need no change in either direction: they only see grants and signed artifacts, whichever way those arrived.
