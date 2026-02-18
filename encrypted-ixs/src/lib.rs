use arcis::*;

#[encrypted]
mod circuits {
    use arcis::*;

    // ── Structs ────────────────────────────────────────────────────

    pub struct SaltInput {
        lo: u128,
        hi: u128,
    }

    pub struct Salt {
        lo: u128,
        hi: u128,
    }

    pub struct WalletInput {
        wallet_lo: u128,
        wallet_hi: u128,
    }

    pub struct Commitment {
        lo: u128,
        hi: u128,
    }

    pub struct VerifyInput {
        wallet_lo: u128,
        wallet_hi: u128,
        expected_lo: u128,
        expected_hi: u128,
    }


    #[instruction]
    pub fn init_salt(salt_ctxt: Enc<Shared, SaltInput>) -> Enc<Mxe, Salt> {
        let salt = salt_ctxt.to_arcis();
        let mxe = Mxe::get();
        mxe.from_arcis(Salt { lo: salt.lo, hi: salt.hi })
    }

    #[instruction]
    pub fn store_wallet(
        wallet_ctxt: Enc<Shared, WalletInput>,
        salt_ctxt: Enc<Mxe, &Salt>,
    ) -> Enc<Shared, Commitment> {
        let wallet = wallet_ctxt.to_arcis();
        let salt = salt_ctxt.to_arcis();

        let mut data = [0u8; 64];
        data[0..16].copy_from_slice(&wallet.wallet_lo.to_le_bytes());
        data[16..32].copy_from_slice(&wallet.wallet_hi.to_le_bytes());
        data[32..48].copy_from_slice(&salt.lo.to_le_bytes());
        data[48..64].copy_from_slice(&salt.hi.to_le_bytes());

        let hasher = SHA3_256::new();
        let hash_bytes = hasher.digest(&data);

        let lo: u128 = hash_bytes[0..16]
            .iter()
            .rev()
            .copied()
            .fold(0u128, |acc, b| acc * 256 + b as u128);
        let hi: u128 = hash_bytes[16..32]
            .iter()
            .rev()
            .copied()
            .fold(0u128, |acc, b| acc * 256 + b as u128);

        wallet_ctxt.owner.from_arcis(Commitment { lo, hi })
    }


    #[instruction]
    pub fn verify_wallet(
        input_ctxt: Enc<Shared, VerifyInput>,
        salt_ctxt: Enc<Mxe, &Salt>,
    ) -> Enc<Shared, u8> {
        let input = input_ctxt.to_arcis();
        let salt = salt_ctxt.to_arcis();

        let mut data = [0u8; 64];
        data[0..16].copy_from_slice(&input.wallet_lo.to_le_bytes());
        data[16..32].copy_from_slice(&input.wallet_hi.to_le_bytes());
        data[32..48].copy_from_slice(&salt.lo.to_le_bytes());
        data[48..64].copy_from_slice(&salt.hi.to_le_bytes());

        let hasher = SHA3_256::new();
        let hash_bytes = hasher.digest(&data);

        let mut expected = [0u8; 32];
        expected[0..16].copy_from_slice(&input.expected_lo.to_le_bytes());
        expected[16..32].copy_from_slice(&input.expected_hi.to_le_bytes());

        let matches = hash_bytes == expected;
        input_ctxt.owner.from_arcis(matches as u8)
    }
}
