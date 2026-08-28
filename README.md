# 🔑 Miniscript Descriptor Analyzer

A client-side Bitcoin miniscript descriptor analyzer powered by WebAssembly. All computation runs locally in your browser — no server required.

## Features

- **Parse & validate** Bitcoin output descriptors (wpkh, wsh, sh, multi, sortedmulti, etc.)
- **Multipath expansion** — automatically splits `<0;1>` descriptors into receive/change paths
- **Key derivation** — derive public keys at any index from xpub-based descriptors
- **Timelock analysis** — human-readable display of `after()` and `older()` timelocks
- **Spending policy** — readable breakdown of AND/OR/threshold spending conditions
- **Script inspection** — view the raw script hex and ASM
- **Address generation** — derive addresses for any network (mainnet, testnet, signet, regtest)
- **CSV export** — export index, path, address, and script type for a range of indices (multipath-aware)
- **Checksum validation** — verify descriptor checksums

## Tech Stack

- **Rust** + [rust-miniscript](https://github.com/rust-bitcoin/rust-miniscript) compiled to **WebAssembly** via `wasm-pack`
- Vanilla **HTML/CSS/JS** frontend — no build tools or frameworks required
- **GitHub Pages** deployment via GitHub Actions

## Development

### Prerequisites

- [Rust](https://rustup.rs/) with `wasm32-unknown-unknown` target
- [wasm-pack](https://rustwasm.github.io/wasm-pack/installer/)

### Build

```bash
wasm-pack build --target web --out-dir www/pkg --release
```

### Serve locally

```bash
# Any static file server works, e.g.:
cd www && python3 -m http.server 8080
```

Then open http://localhost:8080

## Deployment

Pushing to `master` automatically builds and deploys to GitHub Pages via the included GitHub Actions workflow.

## License

MIT
