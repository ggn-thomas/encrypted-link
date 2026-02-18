use anchor_lang::prelude::*;
use arcium_anchor::prelude::*;
use arcium_client::idl::arcium::types::CallbackAccount;

const COMP_DEF_OFFSET_INIT_SALT: u32 = comp_def_offset("init_salt");
const COMP_DEF_OFFSET_STORE_WALLET: u32 = comp_def_offset("store_wallet");
const COMP_DEF_OFFSET_VERIFY_WALLET: u32 = comp_def_offset("verify_wallet");

declare_id!("6YSDocmEoLjFbxCY7YMpr8WNiPsx9V6x3xogmuAC5QWX");

#[arcium_program]
pub mod encrypted_link {
    use super::*;

    // ── init comp defs ─────────────────────────────────────────────

    pub fn init_init_salt_comp_def(ctx: Context<InitInitSaltCompDef>) -> Result<()> {
        init_comp_def(ctx.accounts, None, None)?;
        Ok(())
    }

    pub fn init_store_wallet_comp_def(ctx: Context<InitStoreWalletCompDef>) -> Result<()> {
        init_comp_def(ctx.accounts, None, None)?;
        Ok(())
    }

    pub fn init_verify_wallet_comp_def(ctx: Context<InitVerifyWalletCompDef>) -> Result<()> {
        init_comp_def(ctx.accounts, None, None)?;
        Ok(())
    }

    // ── init_salt ──────────────────────────────────────────────────

    pub fn init_salt(
        ctx: Context<InitSalt>,
        computation_offset: u64,
        salt_lo: [u8; 32],
        salt_hi: [u8; 32],
        pubkey: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        require!(
            !ctx.accounts.salt_account.is_initialized,
            ErrorCode::SaltAlreadyInitialized
        );
        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

        let args = ArgBuilder::new()
            .x25519_pubkey(pubkey)
            .plaintext_u128(nonce)
            .encrypted_u128(salt_lo)
            .encrypted_u128(salt_hi)
            .build();

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            vec![InitSaltCallback::callback_ix(
                computation_offset,
                &ctx.accounts.mxe_account,
                &[CallbackAccount {
                    pubkey: ctx.accounts.salt_account.key(),
                    is_writable: true,
                }],
            )?],
            1,
            0,
        )?;
        Ok(())
    }

    #[arcium_callback(encrypted_ix = "init_salt")]
    pub fn init_salt_callback(
        ctx: Context<InitSaltCallback>,
        output: SignedComputationOutputs<InitSaltOutput>,
    ) -> Result<()> {
        let o = match output.verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        ) {
            Ok(InitSaltOutput { field_0 }) => field_0,
            Err(_) => return Err(ErrorCode::AbortedComputation.into()),
        };

        ctx.accounts.salt_account.is_initialized = true;
        ctx.accounts.salt_account.nonce = o.nonce;
        ctx.accounts.salt_account.salt_lo = o.ciphertexts[0];
        ctx.accounts.salt_account.salt_hi = o.ciphertexts[1];

        emit!(SaltInitialized {});
        Ok(())
    }

    // ── store_wallet (signup) ──────────────────────────────────────

    pub fn store_wallet(
        ctx: Context<StoreWallet>,
        computation_offset: u64,
        wallet_lo: [u8; 32],
        wallet_hi: [u8; 32],
        pubkey: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

        // Args for wallet_ctxt: Enc<Shared, WalletInput>
        // then salt_ctxt: Enc<Mxe, &Salt> via account reference
        let args = ArgBuilder::new()
            .x25519_pubkey(pubkey)
            .plaintext_u128(nonce)
            .encrypted_u128(wallet_lo)
            .encrypted_u128(wallet_hi)
            .plaintext_u128(ctx.accounts.salt_account.nonce)
            .account(
                ctx.accounts.salt_account.key(),
                8 + 1 + 16, // discriminator + is_initialized + nonce
                32 * 2,     // salt_lo + salt_hi
            )
            .build();

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            vec![StoreWalletCallback::callback_ix(
                computation_offset,
                &ctx.accounts.mxe_account,
                &[],
            )?],
            1,
            0,
        )?;
        Ok(())
    }

    #[arcium_callback(encrypted_ix = "store_wallet")]
    pub fn store_wallet_callback(
        ctx: Context<StoreWalletCallback>,
        output: SignedComputationOutputs<StoreWalletOutput>,
    ) -> Result<()> {
        let o = match output.verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        ) {
            Ok(StoreWalletOutput { field_0 }) => field_0,
            Err(_) => return Err(ErrorCode::AbortedComputation.into()),
        };

        emit!(WalletStored {
            commitment_lo: o.ciphertexts[0],
            commitment_hi: o.ciphertexts[1],
            nonce: o.nonce.to_le_bytes(),
        });
        Ok(())
    }

    // ── verify_wallet (signin) ─────────────────────────────────────

    pub fn verify_wallet(
        ctx: Context<VerifyWallet>,
        computation_offset: u64,
        wallet_lo: [u8; 32],
        wallet_hi: [u8; 32],
        expected_lo: [u8; 32],
        expected_hi: [u8; 32],
        pubkey: [u8; 32],
        nonce: u128,
    ) -> Result<()> {
        ctx.accounts.sign_pda_account.bump = ctx.bumps.sign_pda_account;

        // Args for input_ctxt: Enc<Shared, VerifyInput>
        // then salt_ctxt: Enc<Mxe, &Salt> via account reference
        let args = ArgBuilder::new()
            .x25519_pubkey(pubkey)
            .plaintext_u128(nonce)
            .encrypted_u128(wallet_lo)
            .encrypted_u128(wallet_hi)
            .encrypted_u128(expected_lo)
            .encrypted_u128(expected_hi)
            .plaintext_u128(ctx.accounts.salt_account.nonce)
            .account(
                ctx.accounts.salt_account.key(),
                8 + 1 + 16, // discriminator + is_initialized + nonce
                32 * 2,     // salt_lo + salt_hi
            )
            .build();

        queue_computation(
            ctx.accounts,
            computation_offset,
            args,
            vec![VerifyWalletCallback::callback_ix(
                computation_offset,
                &ctx.accounts.mxe_account,
                &[],
            )?],
            1,
            0,
        )?;
        Ok(())
    }

    #[arcium_callback(encrypted_ix = "verify_wallet")]
    pub fn verify_wallet_callback(
        ctx: Context<VerifyWalletCallback>,
        output: SignedComputationOutputs<VerifyWalletOutput>,
    ) -> Result<()> {
        let o = match output.verify_output(
            &ctx.accounts.cluster_account,
            &ctx.accounts.computation_account,
        ) {
            Ok(VerifyWalletOutput { field_0 }) => field_0,
            Err(_) => return Err(ErrorCode::AbortedComputation.into()),
        };

        emit!(WalletVerified {
            result: o.ciphertexts[0],
            nonce: o.nonce.to_le_bytes(),
        });
        Ok(())
    }
}

// ── Data accounts ──────────────────────────────────────────────────

#[account]
pub struct SaltAccount {
    pub is_initialized: bool,
    pub nonce: u128,
    pub salt_lo: [u8; 32],
    pub salt_hi: [u8; 32],
}

// ── Events ─────────────────────────────────────────────────────────

#[event]
pub struct SaltInitialized {}

#[event]
pub struct WalletStored {
    pub commitment_lo: [u8; 32],
    pub commitment_hi: [u8; 32],
    pub nonce: [u8; 16],
}

#[event]
pub struct WalletVerified {
    pub result: [u8; 32],
    pub nonce: [u8; 16],
}

// ── Errors ─────────────────────────────────────────────────────────

#[error_code]
pub enum ErrorCode {
    #[msg("The computation was aborted")]
    AbortedComputation,
    #[msg("Cluster not set")]
    ClusterNotSet,
    #[msg("Salt already initialized")]
    SaltAlreadyInitialized,
    #[msg("Salt not initialized")]
    SaltNotInitialized,
}

// ── init comp def accounts ─────────────────────────────────────────

#[init_computation_definition_accounts("init_salt", payer)]
#[derive(Accounts)]
pub struct InitInitSaltCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: comp_def_account, checked by arcium program.
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: address_lookup_table, checked by arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: lut_program is the Address Lookup Table program.
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[init_computation_definition_accounts("store_wallet", payer)]
#[derive(Accounts)]
pub struct InitStoreWalletCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: comp_def_account, checked by arcium program.
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: address_lookup_table, checked by arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: lut_program is the Address Lookup Table program.
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

#[init_computation_definition_accounts("verify_wallet", payer)]
#[derive(Accounts)]
pub struct InitVerifyWalletCompDef<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(mut, address = derive_mxe_pda!())]
    pub mxe_account: Box<Account<'info, MXEAccount>>,
    #[account(mut)]
    /// CHECK: comp_def_account, checked by arcium program.
    pub comp_def_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_mxe_lut_pda!(mxe_account.lut_offset_slot))]
    /// CHECK: address_lookup_table, checked by arcium program.
    pub address_lookup_table: UncheckedAccount<'info>,
    #[account(address = LUT_PROGRAM_ID)]
    /// CHECK: lut_program is the Address Lookup Table program.
    pub lut_program: UncheckedAccount<'info>,
    pub arcium_program: Program<'info, Arcium>,
    pub system_program: Program<'info, System>,
}

// ── init_salt accounts ────────────────────────────────────────────

#[queue_computation_accounts("init_salt", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct InitSalt<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        init_if_needed,
        space = 8 + 1 + 16 + 32 + 32,
        payer = payer,
        seeds = [b"salt"],
        bump,
    )]
    pub salt_account: Account<'info, SaltAccount>,
    #[account(
        init_if_needed,
        space = 9,
        payer = payer,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Account<'info, MXEAccount>,
    #[account(mut, address = derive_mempool_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    /// CHECK: mempool_account, checked by the arcium program.
    pub mempool_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_execpool_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    /// CHECK: executing_pool, checked by the arcium program.
    pub executing_pool: UncheckedAccount<'info>,
    #[account(mut, address = derive_comp_pda!(computation_offset, mxe_account, ErrorCode::ClusterNotSet))]
    /// CHECK: computation_account, checked by the arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_INIT_SALT))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(mut, address = derive_cluster_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    pub cluster_account: Account<'info, Cluster>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Account<'info, FeePool>,
    #[account(mut, address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Account<'info, ClockAccount>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("init_salt")]
#[derive(Accounts)]
pub struct InitSaltCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_INIT_SALT))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Account<'info, MXEAccount>,
    /// CHECK: computation_account, checked by arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_cluster_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    pub cluster_account: Account<'info, Cluster>,
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: instructions_sysvar
    pub instructions_sysvar: AccountInfo<'info>,
    #[account(mut, seeds = [b"salt"], bump)]
    pub salt_account: Account<'info, SaltAccount>,
}

// ── store_wallet accounts ──────────────────────────────────────────

#[queue_computation_accounts("store_wallet", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct StoreWallet<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        seeds = [b"salt"],
        bump,
        constraint = salt_account.is_initialized @ ErrorCode::SaltNotInitialized,
    )]
    pub salt_account: Account<'info, SaltAccount>,
    #[account(
        init_if_needed,
        space = 9,
        payer = payer,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Account<'info, MXEAccount>,
    #[account(mut, address = derive_mempool_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    /// CHECK: mempool_account, checked by the arcium program.
    pub mempool_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_execpool_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    /// CHECK: executing_pool, checked by the arcium program.
    pub executing_pool: UncheckedAccount<'info>,
    #[account(mut, address = derive_comp_pda!(computation_offset, mxe_account, ErrorCode::ClusterNotSet))]
    /// CHECK: computation_account, checked by the arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_STORE_WALLET))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(mut, address = derive_cluster_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    pub cluster_account: Account<'info, Cluster>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Account<'info, FeePool>,
    #[account(mut, address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Account<'info, ClockAccount>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("store_wallet")]
#[derive(Accounts)]
pub struct StoreWalletCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_STORE_WALLET))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Account<'info, MXEAccount>,
    /// CHECK: computation_account, checked by arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_cluster_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    pub cluster_account: Account<'info, Cluster>,
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: instructions_sysvar
    pub instructions_sysvar: AccountInfo<'info>,
}

// ── verify_wallet accounts ─────────────────────────────────────────

#[queue_computation_accounts("verify_wallet", payer)]
#[derive(Accounts)]
#[instruction(computation_offset: u64)]
pub struct VerifyWallet<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,
    #[account(
        seeds = [b"salt"],
        bump,
        constraint = salt_account.is_initialized @ ErrorCode::SaltNotInitialized,
    )]
    pub salt_account: Account<'info, SaltAccount>,
    #[account(
        init_if_needed,
        space = 9,
        payer = payer,
        seeds = [&SIGN_PDA_SEED],
        bump,
        address = derive_sign_pda!(),
    )]
    pub sign_pda_account: Account<'info, ArciumSignerAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Account<'info, MXEAccount>,
    #[account(mut, address = derive_mempool_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    /// CHECK: mempool_account, checked by the arcium program.
    pub mempool_account: UncheckedAccount<'info>,
    #[account(mut, address = derive_execpool_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    /// CHECK: executing_pool, checked by the arcium program.
    pub executing_pool: UncheckedAccount<'info>,
    #[account(mut, address = derive_comp_pda!(computation_offset, mxe_account, ErrorCode::ClusterNotSet))]
    /// CHECK: computation_account, checked by the arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_VERIFY_WALLET))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(mut, address = derive_cluster_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    pub cluster_account: Account<'info, Cluster>,
    #[account(mut, address = ARCIUM_FEE_POOL_ACCOUNT_ADDRESS)]
    pub pool_account: Account<'info, FeePool>,
    #[account(mut, address = ARCIUM_CLOCK_ACCOUNT_ADDRESS)]
    pub clock_account: Account<'info, ClockAccount>,
    pub system_program: Program<'info, System>,
    pub arcium_program: Program<'info, Arcium>,
}

#[callback_accounts("verify_wallet")]
#[derive(Accounts)]
pub struct VerifyWalletCallback<'info> {
    pub arcium_program: Program<'info, Arcium>,
    #[account(address = derive_comp_def_pda!(COMP_DEF_OFFSET_VERIFY_WALLET))]
    pub comp_def_account: Account<'info, ComputationDefinitionAccount>,
    #[account(address = derive_mxe_pda!())]
    pub mxe_account: Account<'info, MXEAccount>,
    /// CHECK: computation_account, checked by arcium program.
    pub computation_account: UncheckedAccount<'info>,
    #[account(address = derive_cluster_pda!(mxe_account, ErrorCode::ClusterNotSet))]
    pub cluster_account: Account<'info, Cluster>,
    #[account(address = ::anchor_lang::solana_program::sysvar::instructions::ID)]
    /// CHECK: instructions_sysvar
    pub instructions_sysvar: AccountInfo<'info>,
}
