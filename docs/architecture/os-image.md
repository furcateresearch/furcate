# The Furcate OS image

## Shape

- **Built by mkosi** from the Ubuntu 26.04 archive, against a dated snapshot mirror the operator controls, so a build can be repeated and its inputs recorded.
- **A signed GPT image**: a signed unified kernel image (kernel, initrd and command line in one file), two dm-verity protected `/usr` partitions (A and B), and encrypted state created on first boot by `systemd-repart` and bound to the TPM with a signed PCR policy.
- **System extensions** for optional layers: accelerator userspace, runtimes, and any further packages a distribution adds. An edition is a set of packages and extensions, never a fork of the image.
- **Updates** by `systemd-sysupdate` from operator-hosted sources, gated by `furcated` on attestation and policy. An update replaces an image; it never edits a machine. Identity, sealed keys and state live outside anything an update carries.
- **Installer**: a thin image that partitions the target and writes the signed image. `furcate convert` remains the package-based path onto machines already in service.

## Headless, with a web and tablet interface

No graphical session ships on any machine. Every node serves the same web interface from inside its signed image, discovered on the local network, and operates one node or the whole site; a tablet and phone app wraps the same interface for passkeys and onboarding. The interface design (kept in the private research notes, `interface-and-control`) covers passkey assertions as signed orders, a per-Hub site CA held in TPMs, BLE and QR onboarding, a Capacitor app wrapping the same web app.

## What the image carries from furcate

The packages built from the pinned Furcate release: `furcate-node` and `furcate-cli`.
