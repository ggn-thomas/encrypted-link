# Stealf — Private Transaction Protocol on Solana

**Date:** 2026-02-19
**Status:** Validated
**Stack:** Solana, Arcium MPC, ZK Proofs (Groth16), SPL Token (USDC)

---

## 1. Problem Statement

On Solana (and most public blockchains), every transaction is fully transparent: sender address, receiver address, and amount are visible to anyone. This makes it impossible to transfer value privately.

**Goal:** Break the link between sender and receiver while hiding the transfer amount. Nobody — not even on-chain observers — should be able to determine who paid whom.

## 2. Design Constraints

| Constraint | Decision |
|-----------|----------|
| Token | USDC (SPL Token) |
| Denomination | Fixed 10 USDC per deposit (MVP) |
| Privacy target | Sender ↔ receiver link broken, amount hidden |
| Trust model | ZKP (trustless proofs) + MPC threshold trust (relayer) |
| Relayer | Arcium MPC cluster (decentralized, no single operator) |
| Receiver UX | Completely passive — receives funds without any action |

## 3. Architecture Overview

The protocol combines two proven privacy primitives:

1. **ZK Proofs + Merkle tree** — Tornado Cash-style commitment scheme for trustless deposit verification
2. **Arcium MPC as relayer** — Decentralized relayer that executes withdrawal transactions, breaking the on-chain sender→receiver link

```
                         DEPOSIT (on-chain, public)
   Bob ──────────────────────────────────────────────► Vault
   │  10 USDC + commitment                              │
   │  commitment = hash(secret, nullifier)               │
   │                                                     │
   │         WITHDRAW REQUEST (encrypted, to MPC)        │
   │  ┌──────────────────────────────────────────┐       │
   ├─►│           Arcium MPC Cluster              │       │
   │  │  1. Verify ZK proof (Merkle inclusion)    │       │
   │  │  2. Check nullifier not spent             │       │
   │  │  3. Random delay (0-24h)                  │       │
   │  │  4. Execute withdrawal to Alice           │       │
   │  └──────────────────┬───────────────────────┘       │
   │                     │                               │
   │                     ▼                               │
   │              Alice's wallet ◄───────────────────────┘
   │              (10 USDC received)
   │
   │  On-chain observer sees:
   │  - Bob deposited 10 USDC (identical to all other deposits)
   │  - MPC withdrew 10 USDC to Alice (no link to Bob)
   │  - Anonymity set = all deposits of 10 USDC
```

## 4. Core Concepts

### 4.1 Commitment Scheme

Each deposit produces a **commitment** stored in an on-chain Merkle tree:

```
commitment = hash(secret || nullifier)
```

- **secret**: Random 256-bit value known only to the depositor (Bob)
- **nullifier**: Random 256-bit value, revealed at withdrawal to prevent double-spend
- **commitment**: The hash, stored publicly in the Merkle tree (reveals nothing about secret or nullifier)

### 4.2 Merkle Tree

All commitments are leaves in a binary Merkle tree stored on-chain. This provides:

- **O(log n)** proof of membership (a deposit exists without revealing which one)
- **Scalable** storage — only the root + leaves, not all historical proofs
- Fixed depth (e.g., 20 levels = ~1M deposits capacity)

### 4.3 ZK Proof (Groth16)

At withdrawal time, Bob generates a client-side ZK proof that proves:

> "I know a secret and nullifier such that hash(secret || nullifier) is a leaf in the Merkle tree with root R"

Without revealing:
- Which leaf (which deposit is his)
- The secret
- The nullifier's association with the commitment

The proof also binds:
- The **nullifier** (public input, to prevent double-spend)
- The **recipient address** (public input, to prevent front-running)

### 4.4 Nullifier Set

A **nullifier set** stored on-chain tracks all revealed nullifiers. If a nullifier has already been used, the withdrawal is rejected. This prevents double-spending without revealing which deposit is being spent.

### 4.5 MPC as Decentralized Relayer

This is the key differentiator from Tornado Cash. Instead of centralized relayers (or the user self-relaying and leaking their identity via gas payments), the **Arcium MPC cluster** acts as the relayer:

| Property | Tornado Cash Relayer | Arcium MPC Relayer |
|----------|---------------------|-------------------|
| Operator | Single third-party | Threshold MPC cluster |
| Trust | Trust the relayer not to censor | Threshold trust (t-of-n nodes) |
| Censorship resistance | Relayer can refuse | MPC nodes are independent |
| Fee model | Relayer takes a cut | MPC computation fees |
| Decentralization | Depends on relayer market | Built into the protocol |
| Sender→receiver link | Relayer knows it | MPC knows it (threshold) |

**Why MPC signing matters:**
- The vault is controlled by the MPC, not by the depositor
- Withdrawal transactions are **signed by the MPC** — Alice never interacts with the protocol
- On-chain, the withdrawal comes from the vault (MPC-signed), not from Bob
- There is no on-chain link between Bob's deposit and Alice's withdrawal
- Alice is completely passive: she just receives USDC in her wallet

## 5. Detailed Flow

### 5.1 Deposit (Bob → Vault)

```
Bob (client-side)                    Solana Program              Merkle Tree
  │                                       │                          │
  ├── Generate random secret (256-bit)    │                          │
  ├── Generate random nullifier (256-bit) │                          │
  ├── commitment = hash(secret||nullifier)│                          │
  │                                       │                          │
  ├── deposit(10 USDC, commitment) ──────►│                          │
  │                                       ├── Transfer 10 USDC ─► Vault
  │                                       ├── Insert commitment ────►│
  │                                       │                    (new leaf)
  │◄── tx confirmed ─────────────────────┤                          │
  │                                       │                          │
  │  Bob stores locally:                  │                          │
  │  { secret, nullifier, commitment,     │                          │
  │    leafIndex, recipientAddress }      │                          │
```

**What's visible on-chain:**
- Bob deposited 10 USDC (identical to every other deposit)
- A new commitment was added to the Merkle tree
- Nothing about who will receive the funds

### 5.2 Withdrawal (Bob → MPC → Alice)

```
Bob (client-side)                    Arcium MPC Cluster           Solana Program
  │                                       │                          │
  ├── Fetch current Merkle root           │                          │
  ├── Compute Merkle proof for leaf       │                          │
  ├── Generate ZK proof:                  │                          │
  │   public: {nullifier, recipient,      │                          │
  │            root, fee}                 │                          │
  │   private: {secret, pathElements,     │                          │
  │             pathIndices}              │                          │
  │                                       │                          │
  ├── withdraw_request(                   │                          │
  │     zk_proof,                         │                          │
  │     nullifier,           ────────────►│                          │
  │     recipient=Alice,                  │                          │
  │     root                              │                          │
  │   )                                   │                          │
  │                                       ├── Verify ZK proof        │
  │                                       ├── Check nullifier unused │
  │                                       ├── Check root is valid    │
  │                                       │                          │
  │                                       │  (Random delay: 0-24h)   │
  │                                       │                          │
  │                                       ├── withdraw(              │
  │                                       │     nullifier,           │
  │                                       │     recipient=Alice ────►│
  │                                       │   )                      │
  │                                       │                          ├── Check nullifier unused
  │                                       │                          ├── Mark nullifier as spent
  │                                       │                          ├── Transfer 10 USDC
  │                                       │                          │   Vault → Alice
  │                                       │◄── tx confirmed ────────┤
  │                                       │                          │
  Alice receives 10 USDC                  │                          │
  (she did nothing)                       │                          │
```

**What's visible on-chain:**
- The MPC withdrew 10 USDC from the vault to Alice
- A nullifier was marked as spent
- No connection to Bob's deposit

### 5.3 Random Delay Mechanism

The MPC introduces a random delay between receiving the withdrawal request and executing it:

- **Range:** 0 to 24 hours (configurable)
- **Purpose:** Prevents timing correlation (deposit at T, withdraw at T+5min = suspicious)
- **Implementation:** MPC's randomness function determines the execution time
- **Optional enhancement:** Split withdrawal into multiple sub-transactions at random intervals

Example: Bob requests withdrawal → MPC waits 7h 23min → executes transfer to Alice.

## 6. On-Chain Accounts

| Account | Seeds | Description |
|---------|-------|-------------|
| `Vault` | `["vault"]` | Holds deposited USDC tokens |
| `MerkleTree` | `["merkle_tree"]` | Stores commitment tree (root + leaves) |
| `NullifierSet` | `["nullifier", nullifier_hash]` | One PDA per spent nullifier |
| `ProtocolConfig` | `["config"]` | Tree depth, fee, denomination, authority |

## 7. Circuit Design (Arcium MPC)

| Circuit | Input | Output | Description |
|---------|-------|--------|-------------|
| `verify_and_queue_withdrawal` | ZK proof + nullifier + recipient + root (all `Enc<Shared, _>`) | `Enc<Shared, bool>` (valid/invalid) | Verifies ZK proof, checks nullifier, queues withdrawal |
| `execute_withdrawal` | Recipient + amount (`Enc<Mxe, _>` from queue) | MPC-signed transaction | Signs and submits the withdrawal tx from vault to recipient |

## 8. ZK Circuit (Groth16, client-side)

```
Circuit: WithdrawProof

Public inputs:
  - root          : Field    // Current Merkle tree root
  - nullifier_hash: Field    // hash(nullifier) — prevents double-spend
  - recipient     : Field    // Alice's address — prevents front-running
  - fee           : Field    // Protocol fee (optional)

Private inputs:
  - secret        : Field    // Bob's random secret
  - nullifier     : Field    // Bob's random nullifier
  - pathElements  : Field[20]  // Merkle proof siblings
  - pathIndices   : u1[20]     // Left/right path (0 or 1)

Constraints:
  1. commitment = hash(secret, nullifier)
  2. nullifier_hash = hash(nullifier)
  3. MerkleProof(commitment, pathElements, pathIndices) == root
```

## 9. Trust Model Analysis

### What is trustless (ZK guarantees)

- **Deposit integrity:** Commitments are verified on-chain
- **No double-spend:** Nullifier set is on-chain, publicly verifiable
- **Proof validity:** ZK proof verification is deterministic, no trust needed
- **Merkle inclusion:** Proof that a valid deposit exists, without revealing which one

### What requires threshold trust (MPC)

- **Sender → receiver link:** The MPC knows Bob wants to send to Alice. This is a threshold secret — requires t-of-n MPC nodes to collude to reveal it.
- **Withdrawal execution:** The MPC must actually execute the withdrawal (liveness)
- **Random delay honesty:** The MPC controls the timing randomization

### Comparison with alternatives

| Model | Sender→Receiver link | Relayer trust | Decentralization |
|-------|---------------------|---------------|-----------------|
| **Tornado Cash** | Nobody knows (trustless) | Centralized relayers | Low (relayer market) |
| **Stealf (this design)** | MPC knows (threshold) | Arcium MPC cluster | High (t-of-n threshold) |
| **Zcash** | Nobody knows (trustless) | N/A (native chain) | High (own blockchain) |
| **Monero** | Probabilistic hiding (ring sigs) | N/A (native chain) | High (own blockchain) |

**Trade-off accepted:** We sacrifice perfect sender→receiver privacy (MPC knows the link) in exchange for a fully decentralized relayer with no single point of censorship. The threshold trust model means an attacker must compromise t-of-n independent MPC nodes to learn who paid whom.

## 10. Anonymity Set

The **anonymity set** is the pool of deposits that are indistinguishable from each other. With fixed 10 USDC deposits:

- Every deposit looks identical on-chain (same amount, same type)
- An observer cannot tell which deposit corresponds to which withdrawal
- Anonymity set = total number of unspent deposits
- Larger anonymity set = stronger privacy

**Example:** If 1000 people have deposited 10 USDC each, and Alice receives 10 USDC, there are 1000 possible senders. The observer has a 0.1% chance of guessing correctly.

### Fixed denomination rationale

| Approach | Anonymity set | Amount privacy |
|----------|--------------|---------------|
| Variable amounts (hidden) | Small (amounts correlate) | Yes |
| Fixed denomination (10 USDC) | Maximum (all identical) | Yes (always 10) |

Fixed denominations maximize the anonymity set because all deposits are indistinguishable. Variable amounts — even encrypted — leak information through timing and amount correlation.

## 11. Attack Surface

### 11.1 Timing correlation
**Attack:** Observer notes Bob deposits at T=0, Alice receives at T=30min.
**Mitigation:** MPC random delay (0-24h). Multiple deposits/withdrawals in the pool make correlation probabilistic.

### 11.2 Amount correlation
**Attack:** Bob deposits unusual amount X, Alice receives X minus fee.
**Mitigation:** Fixed 10 USDC denomination. All deposits and withdrawals are identical amounts.

### 11.3 MPC collusion
**Attack:** t-of-n MPC nodes collude to reveal sender→receiver mapping.
**Mitigation:** Arcium's threshold model requires compromising multiple independent nodes. Economic incentives (slashing) discourage collusion.

### 11.4 Front-running
**Attack:** Attacker sees Bob's withdrawal request and substitutes their own address.
**Mitigation:** Recipient address is bound in the ZK proof as a public input. Changing the recipient invalidates the proof.

### 11.5 Double-spend
**Attack:** Bob tries to withdraw the same deposit twice.
**Mitigation:** On-chain nullifier set. Once a nullifier is revealed, it's permanently recorded.

### 11.6 Merkle root manipulation
**Attack:** Attacker uses a stale Merkle root to prove inclusion of a removed commitment.
**Mitigation:** Store historical roots (last N roots valid) to allow for latency, but reject very old roots.

### 11.7 Deposit/withdraw pattern analysis
**Attack:** Bob always deposits then immediately requests withdrawal.
**Mitigation:** Random delay + growing anonymity set makes patterns unreliable. Users should wait for the pool to grow before withdrawing.

## 12. MVP Scope

### In scope (v1)
- Fixed 10 USDC denomination
- Single deposit / single withdrawal per commitment
- Merkle tree depth = 20 (~1M deposits)
- Groth16 ZK proofs (client-side generation)
- Arcium MPC as relayer with random delay
- On-chain nullifier tracking
- Basic protocol fee mechanism

### Out of scope (future)
- Multiple denominations (10, 100, 1000 USDC)
- Multi-token support (SOL, other SPL tokens)
- Withdrawal splitting (one deposit → multiple smaller withdrawals at random intervals)
- Compliance features (optional view keys for auditors)
- Cross-chain privacy bridges
- Mobile client SDK

## 13. Technology Stack

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Smart contract | Solana Anchor | Vault, Merkle tree, nullifier set |
| MPC circuits | Arcium (Arcis) | ZK verification, withdrawal signing, delay logic |
| ZK proofs | Groth16 (circom/snarkjs) | Client-side proof generation |
| Token | SPL Token (USDC) | Transfer medium |
| Client | TypeScript | Deposit, proof generation, withdrawal request |
| Merkle tree | On-chain (incremental) | Commitment storage and verification |

## 14. Reference

### Tornado Cash
- Fixed denominations (0.1, 1, 10, 100 ETH)
- Commitment/nullifier scheme with Merkle tree
- Groth16 ZK proofs for withdrawal
- Centralized relayer market

### Zcash (Sapling)
- Shielded pool with UTXO-style notes
- Merkle tree of note commitments
- Groth16 zk-SNARKs
- Native chain (not a smart contract)

### Monero
- Ring signatures (hide sender among decoys)
- Stealth addresses (one-time receiver addresses)
- RingCT (Pedersen commitments for amounts)
- Native chain privacy by default
