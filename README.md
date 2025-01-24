# ts-mullvad-signer

Automatically sign Tailscale Mullvad exit nodes when tailnet lock is enabled.

## CLI Arguments

```
Usage: ts-mullvad-signer [OPTIONS]

Options:
  -y, --yes       Signs without confirmation
      --no-print  Prevents printing a list of nodes to be signed to the console
  -r, --resign    Signs already signed nodes
  -h, --help      Print help
```

## Installation (from source)

This section will guide you through installation of `ts-mullvad-signer`.

### Requirements

A relatively recent version of the Rust toolchain and all of its dependencies to build. If you don't already have a toolchain installed, check [here](https://rustup.rs).

### Instructions

Clone the repository and enter the directory, then run:

```sh
cargo install --path .
```

If your path is already set up for Cargo, you should be able to invoke `ts-mullvad-signer`.
