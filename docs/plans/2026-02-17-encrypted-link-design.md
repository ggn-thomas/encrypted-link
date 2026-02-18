# Encrypted Link — Design Document

**Date**: 2026-02-17
**Status**: Approved
**Scope**: Solana program + Arcium circuits + integration tests (no backend)

## Problem

Store the link between a user and their Solana wallet with maximum privacy. The wallet public key must never be stored in cleartext — not in the database, not on the server, not observable on-chain. Only the Arcium MPC cluster can access wallet data during computation.

## Threat Model

| Threat | Protection |
|--------|-----------|
| DB compromise | Attacker sees only `user_ref` (hash of UUID) + `commitment` (keyed hash). Cannot reverse without MPC salt. |
| Server compromise | Server never sees wallet in cleartext. All encryption/decryption happens client-side or in MPC. |
| On-chain observers | Transactions contain only encrypted data (Enc<Shared> ciphertexts). |
| Brute-force with known wallets | BLAKE3 keyed hash with MPC-held salt makes brute-force impossible without the salt. |
| MPC node collusion | Inherent to MPC trust model. Acceptable with Arcium's threshold security. |

## Approach: HMAC with MXE-Encrypted Salt

A global salt is stored on-chain in a PDA, encrypted with `Enc<Mxe>` (only the MPC cluster can decrypt it). Every wallet hash uses this salt, making brute-force impossible without access to the MPC's collective decryption capability.

## Architecture

### Constraints

- **1 user = 1 wallet** (MVP)
- **Client-driven flow**: frontend calls Solana program directly, backend only stores/retrieves commitments
- **Off-chain storage**: commitments stored in external DB, not on-chain
- **user_id**: UUID from auth system, derived to `user_ref = BLAKE3(user_id)` client-side

### Data Flow

```
INIT (once, at deployment)
══════════════════════════
Admin → init_salt_comp_def()         → register circuit
Admin → init_store_wallet_comp_def() → register circuit
Admin → init_verify_wallet_comp_def()→ register circuit
Admin → init_salt(random_salt)       → MPC re-encrypts as Enc<Mxe>
        init_salt_callback()         → stores ciphertext in SaltAccount PDA

SIGNUP
══════════════════════════
Client → encrypt(wallet_lo, wallet_hi) → store_wallet() → MPC reads Salt PDA
         store_wallet_callback()       ← MPC returns Enc<Shared, Commitment>
         Event: WalletStored { commitment, nonce }
         Client decrypts → recombines lo+hi → 32 bytes
         Client sends (user_ref, commitment) to backend
         Backend stores in DB

SIGNIN
══════════════════════════
Client → requests commitment from backend via user_ref
Client → encrypt(wallet_lo, wallet_hi, expected_lo, expected_hi)
         → verify_wallet() → MPC reads Salt PDA
         verify_wallet_callback() ← MPC returns Enc<Shared, u8>
         Event: WalletVerified { result, nonce }
         Client decrypts → 1 (match) or 0 (no match)
```

## Circuits (encrypted-ixs)

### Why lo/hi split?

Arcis encrypts each struct field separately. The largest primitive is `u128` (16 bytes). A Solana wallet pubkey is 32 bytes, so it must be split into two `u128` values.

### Circuit 1: `init_salt`

```rust
pub struct SaltInput {
    lo: u128,
    hi: u128,
}

#[instruction]
pub fn init_salt(salt_ctxt: Enc<Shared, SaltInput>) -> Enc<Mxe, SaltInput> {
    let salt = salt_ctxt.to_arcis();
    salt_ctxt.mxe.from_arcis(salt)
}
```

- Input: `Enc<Shared, SaltInput>` — client-encrypted random salt
- Output: `Enc<Mxe, SaltInput>` — re-encrypted for MPC only
- Called once at initialization

### Circuit 2: `store_wallet`

```rust
pub struct WalletInput {
    wallet_lo: u128,
    wallet_hi: u128,
}

pub struct Commitment {
    lo: u128,
    hi: u128,
}

#[instruction]
pub fn store_wallet(
    wallet_ctxt: Enc<Shared, WalletInput>,
    salt_ctxt: Enc<Mxe, &SaltInput>,
) -> Enc<Shared, Commitment> {
    let wallet = wallet_ctxt.to_arcis();
    let salt = salt_ctxt.to_arcis();

    // Reconstruct 32-byte wallet
    let mut wallet_bytes = [0u8; 32];
    wallet_bytes[..16].copy_from_slice(&wallet.wallet_lo.to_le_bytes());
    wallet_bytes[16..].copy_from_slice(&wallet.wallet_hi.to_le_bytes());

    // Reconstruct 32-byte salt key
    let mut salt_key = [0u8; 32];
    salt_key[..16].copy_from_slice(&salt.lo.to_le_bytes());
    salt_key[16..].copy_from_slice(&salt.hi.to_le_bytes());

    // BLAKE3 keyed hash
    let hash = blake3::keyed_hash(&salt_key, &wallet_bytes);
    let hash_bytes = hash.as_bytes();

    let lo = u128::from_le_bytes(hash_bytes[..16].try_into().unwrap());
    let hi = u128::from_le_bytes(hash_bytes[16..].try_into().unwrap());

    wallet_ctxt.owner.from_arcis(Commitment { lo, hi })
}
```

- Input: wallet (Enc<Shared>) + salt reference (Enc<Mxe, &>)
- Output: keyed hash commitment (Enc<Shared>) — client can decrypt
- The wallet never leaves the MPC in cleartext

### Circuit 3: `verify_wallet`

```rust
pub struct VerifyInput {
    wallet_lo: u128,
    wallet_hi: u128,
    expected_lo: u128,
    expected_hi: u128,
}

#[instruction]
pub fn verify_wallet(
    input_ctxt: Enc<Shared, VerifyInput>,
    salt_ctxt: Enc<Mxe, &SaltInput>,
) -> Enc<Shared, u8> {
    let input = input_ctxt.to_arcis();
    let salt = salt_ctxt.to_arcis();

    // Same hash computation as store_wallet
    let mut wallet_bytes = [0u8; 32];
    wallet_bytes[..16].copy_from_slice(&input.wallet_lo.to_le_bytes());
    wallet_bytes[16..].copy_from_slice(&input.wallet_hi.to_le_bytes());

    let mut salt_key = [0u8; 32];
    salt_key[..16].copy_from_slice(&salt.lo.to_le_bytes());
    salt_key[16..].copy_from_slice(&salt.hi.to_le_bytes());

    let hash = blake3::keyed_hash(&salt_key, &wallet_bytes);
    let hash_bytes = hash.as_bytes();

    let computed_lo = u128::from_le_bytes(hash_bytes[..16].try_into().unwrap());
    let computed_hi = u128::from_le_bytes(hash_bytes[16..].try_into().unwrap());

    let matches = (computed_lo == input.expected_lo)
               && (computed_hi == input.expected_hi);

    input_ctxt.owner.from_arcis(matches as u8)
}
```

- Input: wallet + expected commitment (Enc<Shared>) + salt reference (Enc<Mxe, &>)
- Output: `u8` — 1 = match, 0 = no match (Enc<Shared>)

## Solana Program

### Accounts

```rust
// PDA seeds: ["salt"]
// Created once at init, stores MXE-encrypted salt
pub struct SaltAccount {
    pub bump: u8,
    pub is_initialized: bool,
    pub salt_ciphertext: Vec<u8>,  // Enc<Mxe> bytes (opaque)
}
```

### Instructions

| Instruction | When | Purpose |
|------------|------|---------|
| `init_salt_comp_def` | Deploy | Register init_salt circuit with Arcium |
| `init_store_wallet_comp_def` | Deploy | Register store_wallet circuit |
| `init_verify_wallet_comp_def` | Deploy | Register verify_wallet circuit |
| `init_salt` | Deploy | Queue salt generation computation |
| `store_wallet` | Signup | Queue wallet hashing computation |
| `verify_wallet` | Signin | Queue wallet verification computation |

### Callbacks

| Callback | Receives | Action |
|----------|----------|--------|
| `init_salt_callback` | `Enc<Mxe, SaltInput>` | Store ciphertext in SaltAccount PDA |
| `store_wallet_callback` | `Enc<Shared, Commitment>` | Emit `WalletStored` event |
| `verify_wallet_callback` | `Enc<Shared, u8>` | Emit `WalletVerified` event |

### Events

```rust
#[event]
pub struct SaltInitialized {
    pub initialized: bool,
}

#[event]
pub struct WalletStored {
    pub commitment: [u8; 32],
    pub nonce: [u8; 16],
}

#[event]
pub struct WalletVerified {
    pub result: [u8; 32],
    pub nonce: [u8; 16],
}
```

## Tests

### Test 1: Initialize salt

1. Register all 3 computation definitions
2. Generate random 32-byte salt client-side
3. Encrypt and send to MPC via `init_salt`
4. Verify SaltAccount PDA is initialized

### Test 2: Store wallet (signup)

1. Generate a random wallet keypair
2. Split pubkey into lo/hi, encrypt with MXE shared secret
3. Call `store_wallet`, await callback
4. Decrypt commitment from `WalletStored` event
5. Verify commitment is 32 bytes of deterministic output

### Test 3: Verify wallet — match (signin)

1. Use same wallet and commitment from Test 2
2. Encrypt wallet + commitment, call `verify_wallet`
3. Decrypt result from `WalletVerified` event
4. Assert result == 1 (match)

### Test 4: Verify wallet — no match

1. Generate a different wallet
2. Use commitment from Test 2 (wrong wallet)
3. Call `verify_wallet`
4. Assert result == 0 (no match)

## File Structure

```
encrypted_link/
├── programs/encrypted_link/src/
│   └── lib.rs                      # Instructions, callbacks, accounts, events
├── encrypted-ixs/src/
│   └── lib.rs                      # 3 circuits: init_salt, store_wallet, verify_wallet
├── tests/
│   └── encrypted_link.ts           # 4 tests: init, signup, signin-match, signin-nomatch
└── docs/plans/
    └── 2026-02-17-encrypted-link-design.md  # This document
```

## Open Questions / Risks

1. **BLAKE3 in Arcis**: The `blake3` crate is a dependency but needs verification that it compiles to Arcis circuit format. Fallback: manual hash implementation.
2. **`Enc<Mxe>` output in callback**: Need to verify the exact format of MXE-encrypted output in the callback struct to correctly store it in the SaltAccount PDA.
3. **`Enc<Mxe, &T>` reference passing**: Need to verify how the salt PDA account is passed to `store_wallet` and `verify_wallet` circuits via the Anchor accounts struct.
4. **Salt rotation**: Not in MVP scope. If the salt needs to be rotated, all existing commitments would need to be re-computed (requires migration circuit).
