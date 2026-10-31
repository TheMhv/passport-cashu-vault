# Cashu Vault (`cashu-vault`) for Passport Prime

An air-gapped **Cashu Ecash Hardware Vault** built with the **Foundation SDK** for **Passport Prime** (KeyOS).

`cashu-vault` derives deterministic secrets and blinding factors on-device from Passport Prime's hardware seed (`os/security` `GetAppSeed`) using **NUT-13** (`m/129372'/0'/{keyset_id_int}'/{counter}'/{0,1}`), blinds and unblinds messages on-device (**NUT-00 BDHKE**), verifies **NUT-12 DLEQ** proofs against pinned **NUT-02** mint keysets, stores unblinded `Proof`s in encrypted `AppData` (`os/fs`), and displays spendable `cashuB` (V4 CBOR) / `cashuA` (V3 JSON) tokens as QR codes on Passport Prime's trusted screen.

---

## Supported Operations

| Operation | Spec | How `cashu-vault` executes it |
|---|---|---|
| **Mint** | NUT-04 | Derives deterministic `(secret, r)` pairs via NUT-13, computes blinded outputs $B\_ = Y + rG$ on-device, verifies the mint's `BlindSignature` DLEQ proofs (NUT-12), unblinds $C = C\_ - rA$, and stores the resulting `Proof`s in KeyOS `AppData`. |
| **Receive** | NUT-03 | Decodes incoming `cashuA` (JSON) or `cashuB` (CBOR) tokens (scanned via Passport's camera or received over QR/bridge), shows the net amount and swap fee on the trusted display, and swaps the external proofs into fresh deterministic NUT-13 vault proofs. |
| **Swap** | NUT-03 | Consolidates proofs or splits denominations for an exact target amount using fresh NUT-13 blinded outputs, verified and approved on screen. |
| **Send** | NUT-00 | Selects exact vault proofs (or auto-splits in Demo Mint mode), enforces the device PIN policy (`verify_pin`), exports a compact `cashuB` (V4 CBOR) + `cashuA` (V3 JSON) token, and renders the bearer token QR code directly on Passport Prime's screen. |
| **Melt** | NUT-05 | Reviews the Lightning invoice, quote ID, LN fee reserve, and mint input fee on the trusted display, enforces PIN verification above threshold, locks input proofs with blank NUT-13 change outputs, and unblinds returned fee-overestimation change. |

---

## Repository Layout

| Path | Description |
|---|---|
| `crates/vault-protocol/` | `cashu-vault-protocol`: CBOR wire envelopes, NUT data structures, and `cashuA` (V3) / `cashuB` (V4) token codecs. |
| `crates/vault-core/` | `cashu-vault-core`: NUT-00 BDHKE (`hash_to_curve`, `blind_message`, `unblind_signature`), NUT-02 keyset verification & fee math, NUT-12 DLEQ verification, NUT-13 BIP-32 derivation, and an embedded cryptographic `MockMint`. |
| `crates/vault-service/` | `cashu-vault-service`: Stateful vault engine managing pinned mints, NUT-13 counters, write-ahead pending operations, proof storage, review screens, and PIN policy. |
| `crates/vault-transport/` | `cashu-vault-transport`: Multi-part animated UR QR codes (`cashu-vault-req` / `cashu-vault-res`) and the simulator file bridge (`~/.cashu-vault-sim`). |
| `crates/simdrive/` | `cashu-vault-simdrive`: Drives the KeyOS simulator screen and reads QR codes from screenshots via `foundation-passport-drive mcp --sim`. |
| `passport-app/` | The Foundation SDK KeyOS Slint application (`cashu-vault`) for Passport Prime. |
| `tools/vault-cli/` | `vault-cli`: Host companion CLI and mint relay for interacting with `cashu-vault` over the simulator bridge. |
| `tools/sim-e2e/` | `sim-e2e`: Automated end-to-end test driver executing AddMint, Mint, Receive, Swap, Send (with QR scan verification), and Melt against the live KeyOS simulator. |

---

## Building and Testing

### 1. Host Unit & Integration Tests
```sh
cargo test --workspace
```

### 2. Device Build (`armv7a-unknown-xous-elf`)
Compile the vault crates and the full KeyOS ELF for Passport Prime using the Foundation SDK toolchain:
```sh
./scripts/device-build.sh -p cashu-vault-protocol -p cashu-vault-core -p cashu-vault-service -p cashu-vault-transport --release
./scripts/app-device-build.sh
```

### 3. Run in the KeyOS Simulator with a Real Testnet Mint (`https://testnut.cashu.space`)

**Terminal 1 — Start the Passport Prime Simulator:**
```sh
cd /home/themhv/github_projects/bitmela-workshop/cashu-vault
./scripts/sdk-shell.sh bash -c 'cd passport-app && foundation sim'
```

**Terminal 2 — Use `vault-cli` with `https://testnut.cashu.space` (default) or any `--mint <url>`:**
```sh
cd /home/themhv/github_projects/bitmela-workshop/cashu-vault

# 1. Fetch & pin the active 'sat' keyset from https://testnut.cashu.space (tap Approve on simulator)
cargo run -p cashu-vault-cli -- add-mint

# 2. Mint 64 sats from testnut.cashu.space (tap Approve on simulator)
cargo run -p cashu-vault-cli -- mint 64

# 3. Export a 16 sat cashuB/cashuA token (tap Approve on simulator, or scan QR from screen)
cargo run -p cashu-vault-cli -- send 16 "testnet coffee"

# 4. Receive a cashuA... or cashuB... token into the vault (swaps into fresh NUT-13 proofs)
cargo run -p cashu-vault-cli -- receive <cashuB_or_cashuA_token>

# 5. Swap / consolidate proofs or split for a target amount (e.g. 20 sat)
cargo run -p cashu-vault-cli -- swap 20

# 6. Melt proofs to pay a BOLT11 invoice (or pass a sat amount on FakeWallet testnet mints)
cargo run -p cashu-vault-cli -- melt 16

# 7. Check vault balance and mints
cargo run -p cashu-vault-cli -- info
```

To use a different testnet or local mint (such as `https://nofees.testnut.cashu.space` or a local `cdk-mintd` at `http://127.0.0.1:3338`), pass `--mint <url>` or set `CASHU_MINT_URL=<url>`:
```sh
cargo run -p cashu-vault-cli -- --mint https://nofees.testnut.cashu.space add-mint
cargo run -p cashu-vault-cli -- --mint https://nofees.testnut.cashu.space mint 100
```

### 4. Automated Simulator End-to-End Test
```sh
./scripts/sim-e2e.sh
```
