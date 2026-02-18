# Encrypted Link

Privacy-preserving wallet linking system built on [Arcium](https://arcium.com/). Stores the association between users and their Solana wallet public keys **without ever storing the public key in cleartext** on-chain.

## How it works

The system uses Arcium's Multi-Party Computation (MPC) network as a confidential co-processor. A secret **salt** is generated and stored encrypted on-chain — only the MPC nodes can decrypt it. When a user links their wallet, the MPC hashes `wallet_pubkey || salt` using SHA3-256 and returns an encrypted **commitment**. To verify ownership later, the MPC re-hashes the claimed wallet with the same salt and compares.

```
                  ┌──────────────────────────────┐
  Signup          │       Arcium MPC Cluster      │
  ──────────►     │  SHA3_256(wallet || salt)      │  ──────► commitment (encrypted)
  wallet pubkey   │  salt read from on-chain       │          stored off-chain by app
  (encrypted)     └──────────────────────────────┘

                  ┌──────────────────────────────┐
  Signin          │       Arcium MPC Cluster      │
  ──────────►     │  SHA3_256(wallet || salt)      │  ──────► match: 1 or 0 (encrypted)
  wallet pubkey   │  compare with commitment       │
  + commitment    └──────────────────────────────┘
```

**Key properties:**
- The wallet public key is **never** stored or visible on-chain
- The salt is MXE-encrypted — only the MPC cluster can read it
- Commitments are returned encrypted to the caller via a shared key
- Verification is a constant-time byte comparison inside the MPC

## Project structure

```
├── encrypted-ixs/src/lib.rs    # Arcis circuits (MPC logic)
├── programs/encrypted_link/     # Solana Anchor program
│   └── src/lib.rs
├── tests/encrypted_link.ts      # Integration tests
├── run_test.sh                  # Test runner (Apple Silicon compatible)
├── Anchor.toml
└── Arcium.toml
```

### Circuits (`encrypted-ixs/`)

Written in [Arcis](https://docs.arcium.com/developers/arcis), Arcium's Rust-based circuit language:

| Circuit | Input | Output | Description |
|---------|-------|--------|-------------|
| `init_salt` | `Enc<Shared, SaltInput>` | `Enc<Mxe, Salt>` | Generates and stores the MXE-encrypted salt on-chain |
| `store_wallet` | `Enc<Shared, WalletInput>` + `Enc<Mxe, &Salt>` | `Enc<Shared, Commitment>` | Hashes wallet+salt, returns commitment to caller |
| `verify_wallet` | `Enc<Shared, VerifyInput>` + `Enc<Mxe, &Salt>` | `Enc<Shared, u8>` | Re-hashes and compares, returns 1 (match) or 0 |

### Solana program (`programs/`)

Standard Anchor program that orchestrates computation queuing and callback handling:

- **`init_salt`** — Queues MPC computation, callback stores encrypted salt in a PDA
- **`store_wallet`** — Passes encrypted wallet + on-chain salt reference to MPC, emits commitment via event
- **`verify_wallet`** — Passes encrypted wallet + commitment + salt reference, emits match result via event

### On-chain accounts

| Account | Seeds | Description |
|---------|-------|-------------|
| `SaltAccount` | `["salt"]` | Stores MXE-encrypted salt (nonce + 2 ciphertexts) |

## Prerequisites

Before running the installation script, make sure you have these dependencies installed:

- **Rust** — [Install](https://www.rust-lang.org/tools/install)
- **Solana CLI 2.3.0** — [Install](https://docs.solanalabs.com/cli/install), then run `solana-keygen new`
- **Yarn** — [Install](https://yarnpkg.com/getting-started/install)
- **Anchor 0.32.1** — [Install](https://www.anchor-lang.com/docs/installation)
- **Docker & Docker Compose** — [Docker](https://docs.docker.com/get-docker/) and [Docker Compose](https://docs.docker.com/compose/install/)

Then install the Arcium CLI:

```bash
curl --proto '=https' --tlsv1.2 -sSfL https://install.arcium.com/ | bash
```

## Build

```bash
arcium build
```

## Test

**On Apple Silicon (M1/M2/M3):**

```bash
./run_test.sh
```

This script automatically pulls the correct `linux/amd64` Docker images before running tests, since Arcium's Docker images don't have native ARM64 builds.

**On x86_64:**

```bash
arcium test
```

### Expected output

```
  EncryptedLink
    ✔ Initializes salt (16s)
    ✔ Stores a wallet commitment (signup) (4s)
    ✔ Verifies correct wallet (signin — match) (4s)
    ✔ Rejects wrong wallet (signin — no match) (4s)

  4 passing (28s)
```

## Technical details

### Encryption types

| Type | Description |
|------|-------------|
| `Enc<Shared, T>` | Client-encrypted data (x25519 shared secret). Both client and MPC can decrypt. |
| `Enc<Mxe, T>` | MXE-encrypted output. Only the MPC cluster can decrypt. Stored on-chain. |
| `Enc<Mxe, &T>` | Reference to existing MXE-encrypted on-chain data. MPC reads it directly from the Solana account. |

### Hash construction

The commitment is computed inside the MPC as:

```
commitment = SHA3-256(wallet_lo ‖ wallet_hi ‖ salt_lo ‖ salt_hi)
```

Where `wallet_lo`/`wallet_hi` and `salt_lo`/`salt_hi` are the lower/upper 16 bytes (as `u128`) of the 32-byte wallet public key and salt respectively. The 32-byte hash output is split into two `u128` values (`lo`/`hi`) for efficient on-chain storage as 2 ciphertexts instead of 32.

### Callback flow

```
Client                    Solana Program              Arcium MPC
  │                            │                          │
  ├── store_wallet(enc_data) ──►│                          │
  │                            ├── queue_computation() ───►│
  │                            │                          ├── decrypt inputs
  │                            │                          ├── read salt from chain
  │                            │                          ├── SHA3_256(wallet||salt)
  │                            │                          ├── encrypt result
  │                            │◄── callback(output) ──────┤
  │                            ├── emit WalletStored event │
  │◄── event (commitment) ─────┤                          │
```
