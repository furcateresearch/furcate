# fl-gateway: the controller end of a leaf link

`fl-gateway` is the program a gateway node (the Pi 5, later any authorised Furcate node) runs to own a leaf. It speaks the controller side of FL1:
- it answers the leaf's HELLO with an operator-signed grant and a node signature;
- it then sends sealed commands.

The leaf always initiates. On Wi-Fi it dials out to the gateway; the gateway never connects to the leaf.

It has no Mac dependency. It is one file built from `fl_gateway.py` and `../fl_proto.py`, and needs:
- Python 3.9 or later;
- the `cryptography` package;
- `pyserial`, only for a USB serial link.

It holds no private key.

## Two links, two roles

The leaf stays plugged into its gateway over USB, but USB is not the working link.

| Link | Role |
|---|---|
| **USB** (gateway's `/dev/ttyUSB0`, CP210x) | Power, deployment and recovery: USB-flashing a base image, recovering a leaf that cannot reach its controller, and the boot console. It is the fallback path for control too, because the leaf answers a session on serial whenever it is not connected to a controller. |
| **Wi-Fi** (home LAN) | The working link: control, data and OTA in normal operation. The leaf dials out to the controller address in its operator-signed config; the gateway listens on that address and never connects to the leaf. |

Both links carry the same FL1 protocol, so the leaf checks grants, signatures and release manifests the same way on either. The gateway relays bytes; signatures come from the node key (`--signer`) and the release threshold.

On the bench Pi (round 3) the user-space tools live in `/var/lib/furcate-leaf`:
- esptool and pyserial come from wheels unpacked into `pylib/`;
- serial access is granted per command with `sudo setpriv --groups=dialout`, so nothing persistent changes in `/etc`.

The controller drives the test runs and the gateway relays; the gateway holds no credential for the controller.

## Build

```
host/gateway/build.sh            # -> host/gateway/fl-gateway.pyz (not committed)
```

## Signer: where the node key lives

| `--signer` | Key | When |
|---|---|---|
| `tpm:NAME` | a TPM key on this host, through `host/tpm/fl-tpm` (non-exportable, no persistent handle) | a gateway with a TPM |
| `cmd:CMD` | any command that reads the message on stdin and prints a DER ECDSA P-256 signature (hex) over SHA-256 of it. The same command with `pub` in place of `sign` prints the public key | the Pi's OTP device key, once provisioned; or remote signing |

**Until the Pi's OTP key exists**, the Pi signs through the controller's TPM key `fl-node`:

```
--signer 'cmd:ssh <controller> ~/.furcate-leaf/bin/fl-tpm sign fl-node'
```

Only the transcript hash input crosses the link. The key stays in the controller's TPM.

**Once the OTP key exists**, the Pi signs with its own key. Use whatever command the OS provides for the OTP key, wrapped to the stdin/hex contract above. Then:
- the operator issues a grant for the Pi's public key;
- the leaf is moved to the Pi (chain step 5).

The grant's node key must match the signer's public key, or the leaf refuses.

## Use

```
FL_LINK=/dev/ttyUSB0                     # or listen://0.0.0.0:7781 for the leaf's Wi-Fi link
FL_SIGNER='cmd:ssh <controller> ~/.furcate-leaf/bin/fl-tpm sign fl-node'
FL_GRANT=fl-node.grant.json              # {"grant": hex, "sig": hex}, operator-signed
FL_LEAF=1d3d319e958177e5a4f2d8fb58c11cfe # optional: refuse any other leaf

python3 fl-gateway.pyz info
python3 fl-gateway.pyz serve --every 30          # keep the link; one INFO JSON line per 30 s
python3 fl-gateway.pyz ota  firmware.manifest firmware.bin
python3 fl-gateway.pyz model model.manifest model.tflite
python3 fl-gateway.pyz infer input.bin
ssh <controller> 'make-signed-config' | python3 fl-gateway.pyz config -
```

`config -` delivers an operator-signed CONFIG envelope read from stdin. The gateway cannot create or alter one:
- the operator signs it;
- it is scoped to one leaf;
- its sequence must be newer than the leaf's stored one.

Because the envelope can carry the Wi-Fi passphrase, it is never written to disk here.

Release manifests are signed by the release threshold. The gateway only relays them, and the leaf checks them.

`--leaf` takes the leaf id as INFO and the boot log show it: 32 hex digits, the first 16 bytes of SHA-256 of the leaf's public key. The full 64-hex digest is also accepted. Any other leaf is refused before the gateway signs anything.

## Not done here

- Not installed on the Pi.
- The OTP signer wrapper waits for `furcate-os otp-provision` (chain step 3).
- On a Wi-Fi link the gateway's listening port must be reachable from the leaf's network. On the bench Pi (2026-10-12) there is no packet filter: no nft or iptables, and no netfilter modules loaded. So the only need is a process listening on the LAN at the controller port (7781). That listener waits on approval from the session that owns the Pi's system.
