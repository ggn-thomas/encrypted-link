import * as anchor from "@coral-xyz/anchor";
import { Program } from "@coral-xyz/anchor";
import { PublicKey, Keypair } from "@solana/web3.js";
import { EncryptedLink } from "../target/types/encrypted_link";
import { randomBytes } from "crypto";
import {
  awaitComputationFinalization,
  getArciumEnv,
  getCompDefAccOffset,
  getArciumAccountBaseSeed,
  getArciumProgramId,
  getArciumProgram,
  uploadCircuit,
  RescueCipher,
  deserializeLE,
  getMXEPublicKey,
  getMXEAccAddress,
  getMempoolAccAddress,
  getCompDefAccAddress,
  getExecutingPoolAccAddress,
  getComputationAccAddress,
  getClusterAccAddress,
  getLookupTableAddress,
  x25519,
} from "@arcium-hq/client";
import * as fs from "fs";
import * as os from "os";
import { expect } from "chai";

// ── Helpers ────────────────────────────────────────────────────────

function splitPubkeyToU128s(pubkey: Uint8Array): { lo: bigint; hi: bigint } {
  const lo = deserializeLE(pubkey.slice(0, 16));
  const hi = deserializeLE(pubkey.slice(16, 32));
  return { lo, hi };
}

function readKpJson(path: string): Keypair {
  const file = fs.readFileSync(path);
  return Keypair.fromSecretKey(new Uint8Array(JSON.parse(file.toString())));
}

async function getMXEPublicKeyWithRetry(
  provider: anchor.AnchorProvider,
  programId: PublicKey,
  maxRetries: number = 20,
  retryDelayMs: number = 500
): Promise<Uint8Array> {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    try {
      const mxePublicKey = await getMXEPublicKey(provider, programId);
      if (mxePublicKey) return mxePublicKey;
    } catch (error) {
      console.log(
        `Attempt ${attempt} failed to fetch MXE public key:`,
        error
      );
    }
    if (attempt < maxRetries) {
      console.log(
        `Retrying in ${retryDelayMs}ms... (attempt ${attempt}/${maxRetries})`
      );
      await new Promise((resolve) => setTimeout(resolve, retryDelayMs));
    }
  }
  throw new Error(
    `Failed to fetch MXE public key after ${maxRetries} attempts`
  );
}

async function initCompDef(
  program: Program<EncryptedLink>,
  arciumProgram: any,
  owner: Keypair,
  provider: anchor.AnchorProvider,
  circuitName: string,
  methodName: string
): Promise<string> {
  const baseSeedCompDefAcc = getArciumAccountBaseSeed(
    "ComputationDefinitionAccount"
  );
  const offset = getCompDefAccOffset(circuitName);

  const compDefPDA = PublicKey.findProgramAddressSync(
    [baseSeedCompDefAcc, program.programId.toBuffer(), offset],
    getArciumProgramId()
  )[0];

  const mxeAccount = getMXEAccAddress(program.programId);
  const mxeAcc = await arciumProgram.account.mxeAccount.fetch(mxeAccount);
  const lutAddress = getLookupTableAddress(
    program.programId,
    mxeAcc.lutOffsetSlot
  );

  const sig = await program.methods[methodName]()
    .accounts({
      compDefAccount: compDefPDA,
      payer: owner.publicKey,
      mxeAccount,
      addressLookupTable: lutAddress,
    })
    .signers([owner])
    .rpc({ commitment: "confirmed" });

  console.log(`Init ${circuitName} comp def tx:`, sig);

  const rawCircuit = fs.readFileSync(`build/${circuitName}.arcis`);
  await uploadCircuit(
    provider,
    circuitName,
    program.programId,
    rawCircuit,
    true
  );

  return sig;
}

// ── Tests ──────────────────────────────────────────────────────────

describe("EncryptedLink", () => {
  anchor.setProvider(anchor.AnchorProvider.env());

  const program = anchor.workspace
    .EncryptedLink as Program<EncryptedLink>;
  const provider = anchor.getProvider() as anchor.AnchorProvider;
  const arciumProgram = getArciumProgram(provider);
  const arciumEnv = getArciumEnv();

  const clusterAccount = getClusterAccAddress(arciumEnv.arciumClusterOffset);
  const mxeAccount = getMXEAccAddress(program.programId);

  // Salt PDA
  const [saltPDA] = PublicKey.findProgramAddressSync(
    [Buffer.from("salt")],
    program.programId
  );

  // Event listener helper
  type Event = anchor.IdlEvents<(typeof program)["idl"]>;
  const awaitEvent = async <E extends keyof Event>(
    eventName: E
  ): Promise<Event[E]> => {
    let listenerId: number;
    const event = await new Promise<Event[E]>((res) => {
      listenerId = program.addEventListener(eventName, (event) => {
        res(event);
      });
    });
    await program.removeEventListener(listenerId);
    return event;
  };

  // Shared state
  let mxePublicKey: Uint8Array;
  let savedCommitmentLo: bigint;
  let savedCommitmentHi: bigint;
  let savedWallet: PublicKey;

  // ── Test 1: Init salt ────────────────────────────────────────────

  it("Initializes salt", async () => {
    const owner = readKpJson(`${os.homedir()}/.config/solana/id.json`);

    // 1. Register all computation definitions
    console.log("Registering computation definitions...");
    await initCompDef(
      program, arciumProgram, owner, provider,
      "init_salt", "initInitSaltCompDef"
    );
    await initCompDef(
      program, arciumProgram, owner, provider,
      "store_wallet", "initStoreWalletCompDef"
    );
    await initCompDef(
      program, arciumProgram, owner, provider,
      "verify_wallet", "initVerifyWalletCompDef"
    );
    console.log("All computation definitions registered.");

    // 2. Get MXE public key
    mxePublicKey = await getMXEPublicKeyWithRetry(provider, program.programId);
    console.log("MXE x25519 pubkey fetched.");

    // 3. Setup encryption
    const privateKey = x25519.utils.randomSecretKey();
    const publicKey = x25519.getPublicKey(privateKey);
    const sharedSecret = x25519.getSharedSecret(privateKey, mxePublicKey);
    const cipher = new RescueCipher(sharedSecret);

    // 4. Generate random salt (32 bytes = 2x u128)
    const salt = randomBytes(32);
    const saltLo = deserializeLE(salt.slice(0, 16));
    const saltHi = deserializeLE(salt.slice(16, 32));

    // 5. Encrypt
    const nonce = randomBytes(16);
    const ciphertext = cipher.encrypt([saltLo, saltHi], nonce);

    // 6. Listen for event
    const eventPromise = awaitEvent("saltInitialized");

    // 7. Call init_salt
    const computationOffset = new anchor.BN(randomBytes(8), "hex");
    console.log("Computation offset: ", computationOffset);

    await program.methods
      .initSalt(
        computationOffset,
        Array.from(ciphertext[0]),
        Array.from(ciphertext[1]),
        Array.from(publicKey),
        new anchor.BN(deserializeLE(nonce).toString())
      )
      .accountsPartial({
        saltAccount: saltPDA,
        computationAccount: getComputationAccAddress(
          arciumEnv.arciumClusterOffset,
          computationOffset
        ),
        clusterAccount,
        mxeAccount,
        mempoolAccount: getMempoolAccAddress(arciumEnv.arciumClusterOffset),
        executingPool: getExecutingPoolAccAddress(
          arciumEnv.arciumClusterOffset
        ),
        compDefAccount: getCompDefAccAddress(
          program.programId,
          Buffer.from(getCompDefAccOffset("init_salt")).readUInt32LE()
        ),
      })
      .rpc({ skipPreflight: true, commitment: "confirmed" });

    // 8. Wait for MPC finalization
    console.log("Waiting for MPC finalization...");
    await awaitComputationFinalization(
      provider,
      computationOffset,
      program.programId,
      "confirmed"
    );
    await eventPromise;

    // 9. Verify salt account is initialized
    const saltAccount = await program.account.saltAccount.fetch(saltPDA);
    expect(saltAccount.isInitialized).to.be.true;
    console.log("Salt initialized successfully!");
  });

  // ── Test 2: Store wallet (signup) ────────────────────────────────

  it("Stores a wallet commitment (signup)", async () => {
    savedWallet = Keypair.generate().publicKey;
    const { lo: walletLo, hi: walletHi } = splitPubkeyToU128s(savedWallet.toBytes());
    console.log("User wallet:", savedWallet.toBase58());

    const privateKey = x25519.utils.randomSecretKey();
    const publicKey = x25519.getPublicKey(privateKey);
    const sharedSecret = x25519.getSharedSecret(privateKey, mxePublicKey);
    const cipher = new RescueCipher(sharedSecret);

    const nonce = randomBytes(16);
    const ciphertext = cipher.encrypt([walletLo, walletHi], nonce);

    const eventPromise = awaitEvent("walletStored");

    const computationOffset = new anchor.BN(randomBytes(8), "hex");
    console.log("Queuing store_wallet computation...");

    await program.methods
      .storeWallet(
        computationOffset,
        Array.from(ciphertext[0]),
        Array.from(ciphertext[1]),
        Array.from(publicKey),
        new anchor.BN(deserializeLE(nonce).toString())
      )
      .accountsPartial({
        saltAccount: saltPDA,
        computationAccount: getComputationAccAddress(
          arciumEnv.arciumClusterOffset,
          computationOffset
        ),
        clusterAccount,
        mxeAccount,
        mempoolAccount: getMempoolAccAddress(arciumEnv.arciumClusterOffset),
        executingPool: getExecutingPoolAccAddress(
          arciumEnv.arciumClusterOffset
        ),
        compDefAccount: getCompDefAccAddress(
          program.programId,
          Buffer.from(getCompDefAccOffset("store_wallet")).readUInt32LE()
        ),
      })
      .rpc({ skipPreflight: true, commitment: "confirmed" });

    console.log("Waiting for MPC finalization...");
    await awaitComputationFinalization(
      provider,
      computationOffset,
      program.programId,
      "confirmed"
    );

    const event = await eventPromise;
    const decrypted = cipher.decrypt(
      [event.commitmentLo, event.commitmentHi],
      event.nonce
    );

    savedCommitmentLo = decrypted[0];
    savedCommitmentHi = decrypted[1];

    console.log(
      "Commitment stored:",
      savedCommitmentLo.toString(16),
      savedCommitmentHi.toString(16)
    );
  });

  // ── Test 3: Verify wallet — match ────────────────────────────────

  it("Verifies correct wallet (signin — match)", async () => {
    const { lo, hi } = splitPubkeyToU128s(savedWallet.toBytes());

    const privateKey = x25519.utils.randomSecretKey();
    const publicKey = x25519.getPublicKey(privateKey);
    const sharedSecret = x25519.getSharedSecret(privateKey, mxePublicKey);
    const cipher = new RescueCipher(sharedSecret);

    const nonce = randomBytes(16);
    const ciphertext = cipher.encrypt(
      [lo, hi, savedCommitmentLo, savedCommitmentHi],
      nonce
    );

    const eventPromise = awaitEvent("walletVerified");

    const computationOffset = new anchor.BN(randomBytes(8), "hex");
    console.log("Computation offset: ", computationOffset);

    const queueSig = await program.methods
      .verifyWallet(
        computationOffset,
        Array.from(ciphertext[0]),
        Array.from(ciphertext[1]),
        Array.from(ciphertext[2]),
        Array.from(ciphertext[3]),
        Array.from(publicKey),
        new anchor.BN(deserializeLE(nonce).toString())
      )
      .accountsPartial({
        saltAccount: saltPDA,
        computationAccount: getComputationAccAddress(
          arciumEnv.arciumClusterOffset,
          computationOffset
        ),
        clusterAccount,
        mxeAccount,
        mempoolAccount: getMempoolAccAddress(arciumEnv.arciumClusterOffset),
        executingPool: getExecutingPoolAccAddress(
          arciumEnv.arciumClusterOffset
        ),
        compDefAccount: getCompDefAccAddress(
          program.programId,
          Buffer.from(getCompDefAccOffset("verify_wallet")).readUInt32LE()
        ),
      })
      .rpc({ skipPreflight: true, commitment: "confirmed" });

    console.log("Queue sig is ", queueSig);
    const finalizedSig = await awaitComputationFinalization(
      provider as anchor.AnchorProvider,
      computationOffset,
      program.programId,
      "confirmed"
    );
    console.log("Finalized sig is: ", finalizedSig);

    const event = await eventPromise;
    const result = cipher.decrypt([event.result], event.nonce)[0];

    console.log("Verify result (should be 1):", Number(result));
    expect(Number(result)).to.equal(1);
  });

  // ── Test 4: Verify wallet — no match ─────────────────────────────

  it("Rejects wrong wallet (signin — no match)", async () => {
    const wrongWallet = Keypair.generate().publicKey;
    const { lo, hi } = splitPubkeyToU128s(wrongWallet.toBytes());
    console.log("Wrong wallet:", wrongWallet.toBase58());

    const privateKey = x25519.utils.randomSecretKey();
    const publicKey = x25519.getPublicKey(privateKey);
    const sharedSecret = x25519.getSharedSecret(privateKey, mxePublicKey);
    const cipher = new RescueCipher(sharedSecret);

    const nonce = randomBytes(16);
    const ciphertext = cipher.encrypt(
      [lo, hi, savedCommitmentLo, savedCommitmentHi],
      nonce
    );

    const eventPromise = awaitEvent("walletVerified");

    const computationOffset = new anchor.BN(randomBytes(8), "hex");
    console.log("Queuing verify_wallet computation (wrong wallet)...");

    await program.methods
      .verifyWallet(
        computationOffset,
        Array.from(ciphertext[0]),
        Array.from(ciphertext[1]),
        Array.from(ciphertext[2]),
        Array.from(ciphertext[3]),
        Array.from(publicKey),
        new anchor.BN(deserializeLE(nonce).toString())
      )
      .accountsPartial({
        saltAccount: saltPDA,
        computationAccount: getComputationAccAddress(
          arciumEnv.arciumClusterOffset,
          computationOffset
        ),
        clusterAccount,
        mxeAccount,
        mempoolAccount: getMempoolAccAddress(arciumEnv.arciumClusterOffset),
        executingPool: getExecutingPoolAccAddress(
          arciumEnv.arciumClusterOffset
        ),
        compDefAccount: getCompDefAccAddress(
          program.programId,
          Buffer.from(getCompDefAccOffset("verify_wallet")).readUInt32LE()
        ),
      })
      .rpc({ skipPreflight: true, commitment: "confirmed" });

    console.log("Waiting for MPC finalization...");
    await awaitComputationFinalization(
      provider,
      computationOffset,
      program.programId,
      "confirmed"
    );

    const event = await eventPromise;
    const result = cipher.decrypt([event.result], event.nonce)[0];

    console.log("Verify result (should be 0):", Number(result));
    expect(Number(result)).to.equal(0);
  });
});
