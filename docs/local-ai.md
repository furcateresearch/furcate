# Local AI on a Raspberry Pi 5 gateway

From a blank drive to a leaf asking a model on its gateway, with Furcate's own
commands. The Pi runs the model; the leaf (an ESP32-class board) attaches to
the Pi's cell and sends it requests.

What you need: a Raspberry Pi 5 (8 GB or 16 GB), a USB 3 drive, Ethernet, an
operator machine with `furcatectl` and an operator key (a Mac with its Secure
Enclave, or a machine with a TPM), and a leaf whose firmware writes the leaf
attachment record ([leaf attachment](interfaces/leaf-attachment.md)).

## 1. Write the image and boot

A release is `<name>.img.zst` with `<name>.img.zst.sha256`, its signature
`<name>.img.zst.sha256.p7s` and `furcate-release.crt`. Check both, then write
the drive (here `/dev/rdisk6` on a Mac; check the device twice, it is erased):

```
shasum -a 256 -c <name>.img.zst.sha256
openssl smime -verify -inform DER -in <name>.img.zst.sha256.p7s \
    -content <name>.img.zst.sha256 -CAfile furcate-release.crt \
    -purpose any -binary -out /dev/null
zstd -dc <name>.img.zst | sudo dd of=/dev/rdisk6 bs=4m && sync
```

Before the first boot, open `furcate-node.txt` on the `BOOT-A` volume, set
`operator` to your operator public key and leave `role = gateway`. Boot from a
blue USB 3 port with Ethernet connected; the first boot takes a minute longer.
Then, from the operator machine:

```
ssh furcate@furcate-pi5.local
furcate-os status
furcatectl identity show        # the Pi's key: you need it in step 2
```

## 2. Make the Pi a cell head

The Pi becomes the head of a cell; leaves attach to the cell, not to the
operator. On the operator machine, with the Pi's key from step 1:

```
furcatectl cell enrol --head <pi key> --cell lab --scale home --ttl 365d \
    --controller <controller addr:port> --out cell-anchor.json
```

Install the anchor on the Pi as `/etc/furcate/cell-anchor.json`. `furcatectl
cell show` lists the cell.

## 3. Install the model server

The inference runtime ships as its own system extension, `modelserver`,
signed like the `furcate` extension. Copy the release directory (it holds
`modelserver.raw` and `modelserver.release`) to the Pi and install it:

```
sudo furcate-os extension install /path/to/modelserver-<version>
furcatectl model list
```

`model list` names the runtime, the devices it can use, any NPU, and the
catalog.

## 4. Pull a model

Weights arrive only through `model pull`, which refuses a source that does not
advertise a SHA-256 and checks the download against it before the file is
used:

```
furcatectl model pull qwen3-0.6b
```

Models up to 2B parameters are comfortable on the Pi's CPU; `model list` marks
larger ones as wanting an accelerator.

## 5. Serve it

```
furcatectl model serve qwen3-0.6b --cpu --reasoning off
```

`--cpu` is required on a Pi. `model serve` never falls back to the CPU on its
own: without an accelerator the runtime can use it stops and says why, and
the CPU is your choice to make (`--cpu`, or `device = cpu` in
`/etc/furcate/model.conf` to make it the default).

The Pi's NPU (an AI HAT, Hailo-8 or Hailo-8L) is detected and reported, but it
cannot serve these models: it runs networks compiled to Hailo's HEF format
through HailoRT, and the catalog's models are GGUF language models run by
llama.cpp, which has no Hailo backend. `--device npu` gives that answer by
name instead of quietly running elsewhere. Keep the NPU for the vision and
audio networks it is built for.

`model serve` returns once the model has answered a real completion. Then
`furcatectl model status` shows it answering, and `furcatectl model endpoint
qwen3-0.6b` prints its local address.

## 6. Open the gateway to the cell

A served model listens on loopback only. The gateway is one endpoint for every
model on the Pi, and it is opened to the cell's network by naming an address:

```
furcatectl model gateway --cpu --reasoning off --bind <pi address on the leaf network>
```

The models run behind it on the Pi's loopback. What listens on the address is
the gateway's door, and it admits only a request signed by a leaf attached to
this cell or by the operator. There is no token to hand out: a leaf proves
itself with the key its hardware derives, and the door checks that key
against the cell's chain on every request. `model gateway` returns once the
models answer and the door refuses an unsigned request.

## 7. Attach the leaf

The leaf firmware writes its attachment record (the leaf's id, its parent, its
public key and how that key is held). On the operator machine:

```
furcatectl cell leaf --cell lab --leaf <leaf id> --attachment leaf.json \
    --head <pi addr:port>
```

The head checks the record with the same code before naming the leaf in a
signed link, and refuses a leaf below the cell's leaf floor with the command
that changes it. `furcatectl cell show` lists the leaf and its class.

That link is the leaf's access to the gateway. Revoking it, letting it end, or
raising the cell's floor above the leaf's class shuts the leaf out at its next
request.

## 8. Ask from the leaf

The leaf signs each request with its key and sends the signature in
`X-Furcate-Credential` ([leaf-signed gateway request](interfaces/leaf-gateway-request.md)):

```
POST http://<pi address>:8750/v1/chat/completions
Content-Type: application/json
Content-Length: <n>
X-Furcate-Credential: leaf:<leaf key>:<nonce>.<expires_at>.<signature>

{"model":"qwen3-0.6b","messages":[{"role":"user","content":"Soil at 12%, 31 C. Water now?"}],"max_tokens":64}
```

The signature is ECDSA P-256 over the method, the path, the SHA-256 of the
body, the nonce and the expiry. The door refuses a request that is unsigned,
signed by another key, replayed, expired or more than five minutes ahead,
altered in transit, or from a leaf that is not attached to this cell, has been
revoked, or is below the cell's floor. The leaf needs the time (SNTP) before
its first request.

[`docs/clients/furcate_leaf_request.py`](clients/furcate_leaf_request.py) is
a reference client, for a machine whose leaf key is held in a TPM:

```
python3 furcate_leaf_request.py key --tpm-handle <handle>     # the key to attach
python3 furcate_leaf_request.py ask --tpm-handle <handle> \
    --url http://<pi address>:8750/v1/chat/completions \
    --data '{"model":"qwen3-0.6b","messages":[{"role":"user","content":"ok"}],"max_tokens":16}'
```

The operator reaches the same door with the operator signature every Furcate
service takes. Applications on the Pi itself use the models on loopback,
`http://127.0.0.1:8751/v1`, with `furcatectl model credential gateway`; that
credential stays on the Pi and is never given to a leaf.

## Limits today

- The request is authenticated, not encrypted: on the leaf network the
  prompt and the answer travel in the clear. Keep the leaf network private.
- CPU only on the Pi. The Hailo-8/8L NPU cannot run language models; a
  Hailo-10H, HailoRT 5 with its GenAI library, and models compiled to HEF by
  Hailo would be needed, and Furcate ships none of them.
- The model server needs a base whose `/usr` carries the libraries the runtime
  links (C++ runtime and OpenMP); `os/build.sh rpi5 model-extension` checks
  this against the base and refuses when one is missing.
