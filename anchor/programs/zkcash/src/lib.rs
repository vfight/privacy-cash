use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar::rent::Rent;
use anchor_spl::associated_token::{self, AssociatedToken};
use anchor_spl::token_interface::{self, Mint, TokenAccount, TokenInterface, TransferChecked};
use ark_bn254::Fr;
use ark_ff::PrimeField;
use light_hasher::Poseidon;

#[cfg(any(feature = "devnet", feature = "localnet", feature = "localnet-mint-checked"))]
declare_id!("ATZj4jZ4FFzkvAcvk27DW9GRkgSbFnHo49fKKPQXU7VS");

#[cfg(not(any(feature = "devnet", feature = "localnet", feature = "localnet-mint-checked")))]
declare_id!("9fhQBbumKEFuXtMBDw8AaQyAjCorLGJQiS3skWZdQyQD");

pub mod errors;
pub mod groth16;
pub mod merkle_tree;
pub mod utils;

use merkle_tree::MerkleTree;

// Constants
const MERKLE_TREE_HEIGHT: u8 = 26;
const DEFAULT_SPL_MAX_DEPOSIT_AMOUNT: u64 = i64::MAX as u64;

#[cfg(any(feature = "localnet", feature = "localnet-mint-checked", test))]
pub const ADMIN_PUBKEY: Option<Pubkey> = None;

#[cfg(all(feature = "devnet", not(any(feature = "localnet", feature = "localnet-mint-checked", test))))]
pub const ADMIN_PUBKEY: Option<Pubkey> = Some(pubkey!("97rSMQUukMDjA7PYErccyx7ZxbHvSDaeXp2ig5BwSrTf"));

#[cfg(not(any(feature = "localnet", feature = "localnet-mint-checked", feature = "devnet", test)))]
pub const ADMIN_PUBKEY: Option<Pubkey> = Some(pubkey!("AWexibGxNFKTa1b5R5MN4PJr9HWnWRwf8EW9g8cLx3dM"));

fn validate_token_account(
    account_info: &AccountInfo<'_>,
    expected_token_program: &Pubkey,
    expected_mint: &Pubkey,
    expected_owner: &Pubkey,
) -> Result<()> {
    use anchor_spl::token_2022::spl_token_2022::{
        extension::StateWithExtensions,
        state::{Account as Spl2022Account, AccountState},
    };
    require_keys_eq!(
        *account_info.owner,
        *expected_token_program,
        ErrorCode::InvalidTokenAccount
    );
    let data = account_info.try_borrow_data()?;
    let state = StateWithExtensions::<Spl2022Account>::unpack(&data)
        .map_err(|_| error!(ErrorCode::InvalidTokenAccount))?;
    require!(
        state.base.state != AccountState::Uninitialized,
        ErrorCode::InvalidTokenAccount
    );
    require_keys_eq!(
        state.base.mint,
        *expected_mint,
        ErrorCode::InvalidTokenAccountMintAddress
    );
    require_keys_eq!(
        state.base.owner,
        *expected_owner,
        ErrorCode::InvalidTokenAccount
    );
    Ok(())
}

#[program]
pub mod zkcash {
    use crate::utils::{verify_proof, VERIFYING_KEY};

    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        if let Some(admin_key) = ADMIN_PUBKEY {
            require!(ctx.accounts.authority.key().eq(&admin_key), ErrorCode::Unauthorized);
        }

        let tree_account = &mut ctx.accounts.tree_account.load_init()?;
        tree_account.authority = ctx.accounts.authority.key();
        tree_account.next_index = 0;
        tree_account.root_index = 0;
        tree_account.bump = ctx.bumps.tree_account;
        tree_account.max_deposit_amount = 1_000_000_000_000; // 1000 SOL default limit
        tree_account.min_deposit_fee = 0;
        tree_account.min_withdrawal_fee = 0;
        tree_account.height = MERKLE_TREE_HEIGHT; // Hardcoded height
        tree_account.root_history_size = 100; // Hardcoded root history size

        MerkleTree::initialize::<Poseidon>(tree_account)?;

        let token_account = &mut ctx.accounts.tree_token_account;
        token_account.authority = ctx.accounts.authority.key();
        token_account.bump = ctx.bumps.tree_token_account;

        // Initialize global config
        let global_config = &mut ctx.accounts.global_config;
        global_config.authority = ctx.accounts.authority.key();
        global_config.fee_recipient = ctx.accounts.authority.key();
        global_config.deposit_fee_rate = 0; // 0% - Free deposits
        global_config.withdrawal_fee_rate = 25; // 0.25% (25 basis points)
        global_config.fee_error_margin = 500; // 5% (500 basis points)
        global_config.bump = ctx.bumps.global_config;

        msg!(
            "Sparse Merkle Tree initialized: height={}, root_history_size={}, deposit_limit={}, deposit_fee_rate={}, withdrawal_fee_rate={}, fee_error_margin={}, fee_recipient={}",
            MERKLE_TREE_HEIGHT,
            100,
            tree_account.max_deposit_amount,
            global_config.deposit_fee_rate,
            global_config.withdrawal_fee_rate,
            global_config.fee_error_margin,
            global_config.fee_recipient
        );
        Ok(())
    }

    /**
     * Update the maximum deposit amount limit for the SOL tree. Only the authority can call this.
     */
    pub fn update_deposit_limit(ctx: Context<UpdateDepositLimit>, new_limit: u64) -> Result<()> {
        let tree_account = &mut ctx.accounts.tree_account.load_mut()?;
        tree_account.max_deposit_amount = new_limit;
        msg!("Deposit limit updated to: {} lamports", new_limit);
        Ok(())
    }

    /**
     * Update per-tree configuration (deposit limit and minimum deposit/withdrawal fees) for the SOL tree.
     * Only the tree authority can call this.
     */
    pub fn update_tree_config(
        ctx: Context<UpdateDepositLimit>,
        new_max_deposit_amount: Option<u64>,
        new_min_deposit_fee: Option<u64>,
        new_min_withdrawal_fee: Option<u64>,
    ) -> Result<()> {
        let tree_account = &mut ctx.accounts.tree_account.load_mut()?;
        if let Some(limit) = new_max_deposit_amount {
            tree_account.max_deposit_amount = limit;
            msg!("SOL max_deposit_amount updated to: {}", limit);
        }
        if let Some(min_dep) = new_min_deposit_fee {
            tree_account.min_deposit_fee = min_dep;
            msg!("SOL min_deposit_fee updated to: {}", min_dep);
        }
        if let Some(min_wd) = new_min_withdrawal_fee {
            tree_account.min_withdrawal_fee = min_wd;
            msg!("SOL min_withdrawal_fee updated to: {}", min_wd);
        }
        Ok(())
    }

    /**
     * Update global configuration for SOL and SPL/Token-2022 tokens. Only the authority can call this.
     */
    pub fn update_global_config(
        ctx: Context<UpdateGlobalConfig>,
        deposit_fee_rate: Option<u16>,
        withdrawal_fee_rate: Option<u16>,
        fee_error_margin: Option<u16>,
        fee_recipient: Option<Pubkey>,
    ) -> Result<()> {
        let global_config = &mut ctx.accounts.global_config;

        if let Some(deposit_rate) = deposit_fee_rate {
            require!(deposit_rate <= 10000, ErrorCode::InvalidFeeRate);
            global_config.deposit_fee_rate = deposit_rate;
            msg!("Deposit fee rate updated to: {} basis points", deposit_rate);
        }

        if let Some(withdrawal_rate) = withdrawal_fee_rate {
            require!(withdrawal_rate <= 10000, ErrorCode::InvalidFeeRate);
            global_config.withdrawal_fee_rate = withdrawal_rate;
            msg!("Withdrawal fee rate updated to: {} basis points", withdrawal_rate);
        }

        if let Some(fee_error_margin_val) = fee_error_margin {
            require!(fee_error_margin_val <= 10000, ErrorCode::InvalidFeeRate);
            global_config.fee_error_margin = fee_error_margin_val;
            msg!("Fee error margin updated to: {} basis points", fee_error_margin_val);
        }

        if let Some(new_fee_recipient) = fee_recipient {
            require!(new_fee_recipient != Pubkey::default(), ErrorCode::InvalidFeeRecipient);
            global_config.fee_recipient = new_fee_recipient;
            msg!("Fee recipient updated to: {}", new_fee_recipient);
        }

        Ok(())
    }

    /**
     * Permissionlessly initialize a new Merkle tree (and vault ATA) for any safe SPL or Token-2022 mint.
     * Any user can call this by paying account rent; governance authority always belongs to global_config.authority.
     */
    pub fn initialize_tree_account_for_spl_token(
        ctx: Context<InitializeTreeAccountForSplToken>,
    ) -> Result<()> {
        utils::validate_mint_extensions(
            &ctx.accounts.mint.to_account_info(),
            &ctx.accounts.token_program.to_account_info(),
        )?;

        let tree_account = &mut ctx.accounts.tree_account.load_init()?;
        tree_account.authority = ctx.accounts.global_config.authority;
        tree_account.next_index = 0;
        tree_account.root_index = 0;
        tree_account.bump = ctx.bumps.tree_account;
        tree_account.max_deposit_amount = DEFAULT_SPL_MAX_DEPOSIT_AMOUNT;
        tree_account.min_deposit_fee = 0;
        tree_account.min_withdrawal_fee = 0;
        tree_account.height = MERKLE_TREE_HEIGHT;
        tree_account.root_history_size = 100;

        MerkleTree::initialize::<Poseidon>(tree_account)?;

        emit!(SplTreeInitialized {
            mint_address: ctx.accounts.mint.key(),
            token_program: ctx.accounts.token_program.key(),
            tree_account: ctx.accounts.tree_account.key(),
            tree_ata: ctx.accounts.tree_ata.key(),
            payer: ctx.accounts.payer.key(),
        });

        msg!(
            "Token merkle tree initialized for mint: {}, token_program: {}, height: {}, max_deposit_amount: {}",
            ctx.accounts.mint.key(),
            ctx.accounts.token_program.key(),
            MERKLE_TREE_HEIGHT,
            DEFAULT_SPL_MAX_DEPOSIT_AMOUNT
        );

        Ok(())
    }

    /**
     * Update the maximum deposit amount limit for a specific SPL/Token-2022 tree.
     * Only the protocol authority can call this.
     */
    pub fn update_deposit_limit_for_spl_token(
        ctx: Context<UpdateDepositLimitForSplToken>,
        new_limit: u64,
    ) -> Result<()> {
        let tree_account = &mut ctx.accounts.tree_account.load_mut()?;
        tree_account.max_deposit_amount = new_limit;
        msg!(
            "Deposit limit updated to: {} for mint: {}",
            new_limit,
            ctx.accounts.mint.key()
        );
        Ok(())
    }

    /**
     * Update per-mint configuration (deposit limit and minimum deposit/withdrawal fees) for an SPL/Token-2022 tree.
     * Only the protocol authority can call this.
     */
    pub fn update_tree_config_for_spl_token(
        ctx: Context<UpdateDepositLimitForSplToken>,
        new_max_deposit_amount: Option<u64>,
        new_min_deposit_fee: Option<u64>,
        new_min_withdrawal_fee: Option<u64>,
    ) -> Result<()> {
        let tree_account = &mut ctx.accounts.tree_account.load_mut()?;
        if let Some(limit) = new_max_deposit_amount {
            tree_account.max_deposit_amount = limit;
            msg!("max_deposit_amount updated to {} for mint {}", limit, ctx.accounts.mint.key());
        }
        if let Some(min_dep) = new_min_deposit_fee {
            tree_account.min_deposit_fee = min_dep;
            msg!("min_deposit_fee updated to {} for mint {}", min_dep, ctx.accounts.mint.key());
        }
        if let Some(min_wd) = new_min_withdrawal_fee {
            tree_account.min_withdrawal_fee = min_wd;
            msg!("min_withdrawal_fee updated to {} for mint {}", min_wd, ctx.accounts.mint.key());
        }
        Ok(())
    }

    /**
     * Users deposit or withdraw SOL from the program.
     *
     * Reentrant attacks are not possible, because nullifier creation is checked by anchor first.
     */
    pub fn transact(
        ctx: Context<Transact>,
        proof: Proof,
        ext_data_minified: ExtDataMinified,
        encrypted_output1: Vec<u8>,
        encrypted_output2: Vec<u8>,
    ) -> Result<()> {
        let tree_account = &mut ctx.accounts.tree_account.load_mut()?;
        let global_config = &ctx.accounts.global_config;

        // Enforce protocol fee recipient on-chain
        require_keys_eq!(
            ctx.accounts.fee_recipient_account.key(),
            global_config.fee_recipient,
            ErrorCode::InvalidFeeRecipient
        );

        // Reconstruct full ExtData from minified version and context accounts
        let ext_data = ExtData::from_minified(&ctx, ext_data_minified);

        // check if proof.root is in the tree_account's proof history
        require!(
            MerkleTree::is_known_root(&tree_account, proof.root),
            ErrorCode::UnknownRoot
        );

        // check if the ext_data hashes to the same ext_data in the proof
        let calculated_ext_data_hash = utils::calculate_complete_ext_data_hash(
            ext_data.recipient,
            ext_data.ext_amount,
            &encrypted_output1,
            &encrypted_output2,
            ext_data.fee,
            ext_data.fee_recipient,
            ext_data.mint_address,
        )?;

        require!(
            Fr::from_le_bytes_mod_order(&calculated_ext_data_hash)
                == Fr::from_be_bytes_mod_order(&proof.ext_data_hash),
            ErrorCode::ExtDataHashMismatch
        );

        require!(
            utils::check_public_amount(ext_data.ext_amount, ext_data.fee, proof.public_amount),
            ErrorCode::InvalidPublicAmountData
        );

        let ext_amount = ext_data.ext_amount;
        let fee = ext_data.fee;

        // Validate fee calculation with per-tree minimum fee floor: max(rate_fee, min_fee)
        utils::validate_fee_with_min(
            ext_amount,
            fee,
            global_config.deposit_fee_rate,
            global_config.withdrawal_fee_rate,
            global_config.fee_error_margin,
            tree_account.min_deposit_fee,
            tree_account.min_withdrawal_fee,
        )?;

        // verify the proof
        require!(verify_proof(proof.clone(), VERIFYING_KEY), ErrorCode::InvalidProof);

        let tree_token_account_info = ctx.accounts.tree_token_account.to_account_info();
        let rent = Rent::get()?;
        let rent_exempt_minimum = rent.minimum_balance(tree_token_account_info.data_len());

        if ext_amount > 0 {
            let deposit_amount = ext_amount as u64;
            require!(
                deposit_amount <= tree_account.max_deposit_amount,
                ErrorCode::DepositLimitExceeded
            );

            anchor_lang::system_program::transfer(
                CpiContext::new(
                    ctx.accounts.system_program.to_account_info(),
                    anchor_lang::system_program::Transfer {
                        from: ctx.accounts.signer.to_account_info(),
                        to: ctx.accounts.tree_token_account.to_account_info(),
                    },
                ),
                deposit_amount,
            )?;
        } else if ext_amount < 0 {
            let recipient_account_info = ctx.accounts.recipient.to_account_info();

            let ext_amount_abs: u64 = ext_amount
                .checked_neg()
                .ok_or(ErrorCode::ArithmeticOverflow)?
                .try_into()
                .map_err(|_| ErrorCode::InvalidExtAmount)?;

            let total_required = ext_amount_abs
                .checked_add(fee)
                .ok_or(ErrorCode::ArithmeticOverflow)?
                .checked_add(rent_exempt_minimum)
                .ok_or(ErrorCode::ArithmeticOverflow)?;

            require!(
                tree_token_account_info.lamports() >= total_required,
                ErrorCode::InsufficientFundsForWithdrawal
            );

            let tree_token_balance = tree_token_account_info.lamports();
            let recipient_balance = recipient_account_info.lamports();

            let new_tree_token_balance = tree_token_balance
                .checked_sub(ext_amount_abs)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
            let new_recipient_balance = recipient_balance
                .checked_add(ext_amount_abs)
                .ok_or(ErrorCode::ArithmeticOverflow)?;

            **tree_token_account_info.try_borrow_mut_lamports()? = new_tree_token_balance;
            **recipient_account_info.try_borrow_mut_lamports()? = new_recipient_balance;
        }

        if fee > 0 {
            let fee_recipient_account_info = ctx.accounts.fee_recipient_account.to_account_info();

            if ext_amount >= 0 {
                let total_required = fee
                    .checked_add(rent_exempt_minimum)
                    .ok_or(ErrorCode::ArithmeticOverflow)?;

                require!(
                    tree_token_account_info.lamports() >= total_required,
                    ErrorCode::InsufficientFundsForFee
                );
            }

            let tree_token_balance = tree_token_account_info.lamports();
            let fee_recipient_balance = fee_recipient_account_info.lamports();

            let new_tree_token_balance = tree_token_balance
                .checked_sub(fee)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
            let new_fee_recipient_balance = fee_recipient_balance
                .checked_add(fee)
                .ok_or(ErrorCode::ArithmeticOverflow)?;

            **tree_token_account_info.try_borrow_mut_lamports()? = new_tree_token_balance;
            **fee_recipient_account_info.try_borrow_mut_lamports()? = new_fee_recipient_balance;
        }

        let next_index_to_insert = tree_account.next_index;
        MerkleTree::append::<Poseidon>(proof.output_commitments[0], tree_account)?;
        MerkleTree::append::<Poseidon>(proof.output_commitments[1], tree_account)?;

        let second_index = next_index_to_insert
            .checked_add(1)
            .ok_or(ErrorCode::ArithmeticOverflow)?;

        emit!(CommitmentData {
            index: next_index_to_insert,
            commitment: proof.output_commitments[0],
            encrypted_output: encrypted_output1.to_vec(),
        });

        emit!(CommitmentData {
            index: second_index,
            commitment: proof.output_commitments[1],
            encrypted_output: encrypted_output2.to_vec(),
        });

        Ok(())
    }

    /**
     * Users deposit or withdraw any supported SPL or Token-2022 token from the program.
     *
     * Reentrant attacks are not possible, because nullifier creation is checked by anchor first.
     */
    pub fn transact_spl(
        ctx: Context<TransactSpl>,
        proof: Proof,
        ext_data_minified: ExtDataMinified,
        encrypted_output1: Vec<u8>,
        encrypted_output2: Vec<u8>,
    ) -> Result<()> {
        let tree_account = &mut ctx.accounts.tree_account.load_mut()?;
        let global_config = &ctx.accounts.global_config;
        let mint_key = ctx.accounts.mint.key();
        let token_program_key = ctx.accounts.token_program.key();

        // Enforce protocol fee recipient ATA on-chain (works even when fee == 0 and ATA is not yet created)
        let expected_fee_recipient_ata = associated_token::get_associated_token_address_with_program_id(
            &global_config.fee_recipient,
            &mint_key,
            &token_program_key,
        );
        require_keys_eq!(
            ctx.accounts.fee_recipient_ata.key(),
            expected_fee_recipient_ata,
            ErrorCode::InvalidFeeRecipient
        );

        // Reconstruct full ExtData from minified version and context accounts
        let ext_data = ExtData::from_minified_spl(&ctx, ext_data_minified);

        // Check if proof.root is in the tree_account's proof history
        require!(
            MerkleTree::is_known_root(&tree_account, proof.root),
            ErrorCode::UnknownRoot
        );

        let calculated_ext_data_hash = utils::calculate_complete_ext_data_hash(
            ext_data.recipient,
            ext_data.ext_amount,
            &encrypted_output1,
            &encrypted_output2,
            ext_data.fee,
            ext_data.fee_recipient,
            ext_data.mint_address,
        )?;

        require!(
            Fr::from_le_bytes_mod_order(&calculated_ext_data_hash)
                == Fr::from_be_bytes_mod_order(&proof.ext_data_hash),
            ErrorCode::ExtDataHashMismatch
        );

        require!(
            utils::check_public_amount(ext_data.ext_amount, ext_data.fee, proof.public_amount),
            ErrorCode::InvalidPublicAmountData
        );

        let ext_amount = ext_data.ext_amount;
        let fee = ext_data.fee;

        // Validate fee calculation with per-mint minimum fee floor: max(rate_fee, min_fee)
        utils::validate_fee_with_min(
            ext_amount,
            fee,
            global_config.deposit_fee_rate,
            global_config.withdrawal_fee_rate,
            global_config.fee_error_margin,
            tree_account.min_deposit_fee,
            tree_account.min_withdrawal_fee,
        )?;

        // Verify the ZK proof
        require!(verify_proof(proof.clone(), VERIFYING_KEY), ErrorCode::InvalidProof);

        let decimals = ctx.accounts.mint.decimals;

        if ext_amount > 0 {
            let deposit_amount = ext_amount as u64;
            require!(
                deposit_amount <= tree_account.max_deposit_amount,
                ErrorCode::DepositLimitExceeded
            );

            validate_token_account(
                &ctx.accounts.signer_token_account.to_account_info(),
                &token_program_key,
                &mint_key,
                &ctx.accounts.signer.key(),
            )?;

            let before_balance = ctx.accounts.tree_ata.amount;

            token_interface::transfer_checked(
                CpiContext::new(
                    ctx.accounts.token_program.to_account_info(),
                    TransferChecked {
                        from: ctx.accounts.signer_token_account.to_account_info(),
                        mint: ctx.accounts.mint.to_account_info(),
                        to: ctx.accounts.tree_ata.to_account_info(),
                        authority: ctx.accounts.signer.to_account_info(),
                    },
                ),
                deposit_amount,
                decimals,
            )?;

            // Defense-in-depth: ensure the pool actually received the exact deposited amount
            ctx.accounts.tree_ata.reload()?;
            let actual_received = ctx
                .accounts
                .tree_ata
                .amount
                .checked_sub(before_balance)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
            require_eq!(actual_received, deposit_amount, ErrorCode::DepositAmountMismatch);
        } else if ext_amount < 0 {
            let ext_amount_abs: u64 = ext_amount
                .checked_neg()
                .ok_or(ErrorCode::ArithmeticOverflow)?
                .try_into()
                .map_err(|_| ErrorCode::InvalidExtAmount)?;

            validate_token_account(
                &ctx.accounts.recipient_token_account.to_account_info(),
                &token_program_key,
                &mint_key,
                &ctx.accounts.recipient.key(),
            )?;

            let bump = &[ctx.accounts.global_config.bump];
            let seeds: &[&[u8]] = &[b"global_config", bump];
            let signer_seeds = &[seeds];

            token_interface::transfer_checked(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    TransferChecked {
                        from: ctx.accounts.tree_ata.to_account_info(),
                        mint: ctx.accounts.mint.to_account_info(),
                        to: ctx.accounts.recipient_token_account.to_account_info(),
                        authority: ctx.accounts.global_config.to_account_info(),
                    },
                    signer_seeds,
                ),
                ext_amount_abs,
                decimals,
            )?;
        }

        if fee > 0 {
            validate_token_account(
                &ctx.accounts.fee_recipient_ata.to_account_info(),
                &token_program_key,
                &mint_key,
                &global_config.fee_recipient,
            )?;

            let bump = &[ctx.accounts.global_config.bump];
            let seeds: &[&[u8]] = &[b"global_config", bump];
            let signer_seeds = &[seeds];

            token_interface::transfer_checked(
                CpiContext::new_with_signer(
                    ctx.accounts.token_program.to_account_info(),
                    TransferChecked {
                        from: ctx.accounts.tree_ata.to_account_info(),
                        mint: ctx.accounts.mint.to_account_info(),
                        to: ctx.accounts.fee_recipient_ata.to_account_info(),
                        authority: ctx.accounts.global_config.to_account_info(),
                    },
                    signer_seeds,
                ),
                fee,
                decimals,
            )?;
        }

        let next_index_to_insert = tree_account.next_index;
        MerkleTree::append::<Poseidon>(proof.output_commitments[0], tree_account)?;
        MerkleTree::append::<Poseidon>(proof.output_commitments[1], tree_account)?;

        let second_index = next_index_to_insert
            .checked_add(1)
            .ok_or(ErrorCode::ArithmeticOverflow)?;

        emit!(SplCommitmentData {
            index: next_index_to_insert,
            mint_address: ext_data.mint_address,
            commitment: proof.output_commitments[0],
            encrypted_output: encrypted_output1.to_vec(),
        });

        emit!(SplCommitmentData {
            index: second_index,
            mint_address: ext_data.mint_address,
            commitment: proof.output_commitments[1],
            encrypted_output: encrypted_output2.to_vec(),
        });

        Ok(())
    }
}

#[event]
pub struct CommitmentData {
    pub index: u64,
    pub commitment: [u8; 32],
    pub encrypted_output: Vec<u8>,
}

#[event]
pub struct SplCommitmentData {
    pub index: u64,
    pub mint_address: Pubkey,
    pub commitment: [u8; 32],
    pub encrypted_output: Vec<u8>,
}

#[event]
pub struct SplTreeInitialized {
    pub mint_address: Pubkey,
    pub token_program: Pubkey,
    pub tree_account: Pubkey,
    pub tree_ata: Pubkey,
    pub payer: Pubkey,
}

// all public inputs needs to be in big endian format
#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct Proof {
    pub proof_a: [u8; 64],
    pub proof_b: [u8; 128],
    pub proof_c: [u8; 64],
    pub root: [u8; 32],
    pub public_amount: [u8; 32],
    pub ext_data_hash: [u8; 32],
    pub input_nullifiers: [[u8; 32]; 2],
    pub output_commitments: [[u8; 32]; 2],
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ExtData {
    pub recipient: Pubkey,
    pub ext_amount: i64,
    pub fee: u64,
    pub fee_recipient: Pubkey,
    pub mint_address: Pubkey,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone)]
pub struct ExtDataMinified {
    pub ext_amount: i64,
    pub fee: u64,
}

impl ExtData {
    fn from_minified(ctx: &Context<Transact>, minified: ExtDataMinified) -> Self {
        Self {
            recipient: ctx.accounts.recipient.key(),
            ext_amount: minified.ext_amount,
            fee: minified.fee,
            fee_recipient: ctx.accounts.fee_recipient_account.key(),
            mint_address: utils::SOL_ADDRESS,
        }
    }

    fn from_minified_spl(ctx: &Context<TransactSpl>, minified: ExtDataMinified) -> Self {
        Self {
            recipient: ctx.accounts.recipient_token_account.key(),
            ext_amount: minified.ext_amount,
            fee: minified.fee,
            fee_recipient: ctx.accounts.fee_recipient_ata.key(),
            mint_address: ctx.accounts.mint.key(),
        }
    }
}

#[derive(Accounts)]
#[instruction(proof: Proof, ext_data_minified: ExtDataMinified, encrypted_output1: Vec<u8>, encrypted_output2: Vec<u8>)]
pub struct Transact<'info> {
    #[account(
        mut,
        seeds = [b"merkle_tree"],
        bump = tree_account.load()?.bump
    )]
    pub tree_account: AccountLoader<'info, MerkleTreeAccount>,

    /// Nullifier account to mark the first input as spent.
    #[account(
        init,
        payer = signer,
        space = 8 + std::mem::size_of::<NullifierAccount>(),
        seeds = [b"nullifier0", proof.input_nullifiers[0].as_ref()],
        bump
    )]
    pub nullifier0: Account<'info, NullifierAccount>,

    /// Nullifier account to mark the second input as spent.
    #[account(
        init,
        payer = signer,
        space = 8 + std::mem::size_of::<NullifierAccount>(),
        seeds = [b"nullifier1", proof.input_nullifiers[1].as_ref()],
        bump
    )]
    pub nullifier1: Account<'info, NullifierAccount>,

    #[account(
        seeds = [b"nullifier0", proof.input_nullifiers[1].as_ref()],
        bump
    )]
    pub nullifier2: SystemAccount<'info>,

    #[account(
        seeds = [b"nullifier1", proof.input_nullifiers[0].as_ref()],
        bump
    )]
    pub nullifier3: SystemAccount<'info>,

    #[account(
        mut,
        seeds = [b"tree_token"],
        bump = tree_token_account.bump
    )]
    pub tree_token_account: Account<'info, TreeTokenAccount>,

    #[account(
        seeds = [b"global_config"],
        bump = global_config.bump
    )]
    pub global_config: Account<'info, GlobalConfig>,

    #[account(mut)]
    /// CHECK: user should be able to send funds to any types of accounts
    pub recipient: UncheckedAccount<'info>,

    #[account(mut)]
    /// CHECK: validated against global_config.fee_recipient in transact
    pub fee_recipient_account: UncheckedAccount<'info>,

    /// The account that is signing the transaction
    #[account(mut)]
    pub signer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(proof: Proof, ext_data_minified: ExtDataMinified, encrypted_output1: Vec<u8>, encrypted_output2: Vec<u8>)]
pub struct TransactSpl<'info> {
    #[account(
        mut,
        seeds = [b"merkle_tree", mint.key().as_ref()],
        bump = tree_account.load()?.bump
    )]
    pub tree_account: AccountLoader<'info, MerkleTreeAccount>,

    /// Nullifier account to mark the first input as spent.
    #[account(
        init,
        payer = signer,
        space = 8 + std::mem::size_of::<NullifierAccount>(),
        seeds = [b"nullifier0", proof.input_nullifiers[0].as_ref()],
        bump
    )]
    pub nullifier0: Account<'info, NullifierAccount>,

    /// Nullifier account to mark the second input as spent.
    #[account(
        init,
        payer = signer,
        space = 8 + std::mem::size_of::<NullifierAccount>(),
        seeds = [b"nullifier1", proof.input_nullifiers[1].as_ref()],
        bump
    )]
    pub nullifier1: Account<'info, NullifierAccount>,

    #[account(
        seeds = [b"nullifier0", proof.input_nullifiers[1].as_ref()],
        bump
    )]
    pub nullifier2: SystemAccount<'info>,

    #[account(
        seeds = [b"nullifier1", proof.input_nullifiers[0].as_ref()],
        bump
    )]
    pub nullifier3: SystemAccount<'info>,

    #[account(
        seeds = [b"global_config"],
        bump = global_config.bump
    )]
    pub global_config: Account<'info, GlobalConfig>,

    /// The account that is signing the transaction
    #[account(mut)]
    pub signer: Signer<'info>,

    /// SPL or Token-2022 mint account
    #[account(mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,

    /// Signer's token account (required and validated on deposits where ext_amount > 0)
    /// CHECK: validated via validate_token_account when ext_amount > 0
    #[account(mut)]
    pub signer_token_account: UncheckedAccount<'info>,

    /// CHECK: user should be able to send funds to any types of accounts
    pub recipient: UncheckedAccount<'info>,

    /// Recipient's token account (required and validated on withdrawals where ext_amount < 0)
    /// CHECK: validated via validate_token_account when ext_amount < 0
    #[account(mut)]
    pub recipient_token_account: UncheckedAccount<'info>,

    /// Tree's associated token account (destination for deposits, source for withdrawals)
    #[account(
        init_if_needed,
        payer = signer,
        associated_token::mint = mint,
        associated_token::authority = global_config,
        associated_token::token_program = token_program
    )]
    pub tree_ata: InterfaceAccount<'info, TokenAccount>,

    /// Fee recipient's associated token account (must match ATA(global_config.fee_recipient, mint, token_program))
    /// CHECK: address validated against global_config.fee_recipient; token account validated when fee > 0
    #[account(mut)]
    pub fee_recipient_ata: UncheckedAccount<'info>,

    /// SPL Token or Token-2022 program
    pub token_program: Interface<'info, TokenInterface>,

    /// Associated Token program
    pub associated_token_program: Program<'info, AssociatedToken>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(
        init,
        payer = authority,
        space = 8 + std::mem::size_of::<MerkleTreeAccount>(),
        seeds = [b"merkle_tree"],
        bump
    )]
    pub tree_account: AccountLoader<'info, MerkleTreeAccount>,

    #[account(
        init,
        payer = authority,
        space = 8 + std::mem::size_of::<TreeTokenAccount>(),
        seeds = [b"tree_token"],
        bump
    )]
    pub tree_token_account: Account<'info, TreeTokenAccount>,

    #[account(
        init,
        payer = authority,
        space = 8 + std::mem::size_of::<GlobalConfig>(),
        seeds = [b"global_config"],
        bump
    )]
    pub global_config: Account<'info, GlobalConfig>,

    #[account(mut)]
    pub authority: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateDepositLimit<'info> {
    #[account(
        mut,
        seeds = [b"merkle_tree"],
        bump = tree_account.load()?.bump,
        has_one = authority @ ErrorCode::Unauthorized
    )]
    pub tree_account: AccountLoader<'info, MerkleTreeAccount>,

    /// The authority account that can update tree config
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct UpdateGlobalConfig<'info> {
    #[account(
        mut,
        seeds = [b"global_config"],
        bump = global_config.bump,
        has_one = authority @ ErrorCode::Unauthorized
    )]
    pub global_config: Account<'info, GlobalConfig>,

    /// The authority account that can update the global config
    pub authority: Signer<'info>,
}

#[derive(Accounts)]
pub struct InitializeTreeAccountForSplToken<'info> {
    #[account(
        init,
        payer = payer,
        space = 8 + std::mem::size_of::<MerkleTreeAccount>(),
        seeds = [b"merkle_tree", mint.key().as_ref()],
        bump
    )]
    pub tree_account: AccountLoader<'info, MerkleTreeAccount>,

    /// SPL or Token-2022 mint account
    #[account(mint::token_program = token_program)]
    pub mint: InterfaceAccount<'info, Mint>,

    /// Vault ATA for this mint owned by global_config
    #[account(
        init_if_needed,
        payer = payer,
        associated_token::mint = mint,
        associated_token::authority = global_config,
        associated_token::token_program = token_program
    )]
    pub tree_ata: InterfaceAccount<'info, TokenAccount>,

    #[account(
        seeds = [b"global_config"],
        bump = global_config.bump
    )]
    pub global_config: Account<'info, GlobalConfig>,

    /// Any user can pay rent to initialize a tree for a new token
    #[account(mut)]
    pub payer: Signer<'info>,

    /// SPL Token or Token-2022 program
    pub token_program: Interface<'info, TokenInterface>,

    pub associated_token_program: Program<'info, AssociatedToken>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UpdateDepositLimitForSplToken<'info> {
    #[account(
        mut,
        seeds = [b"merkle_tree", mint.key().as_ref()],
        bump = tree_account.load()?.bump,
        has_one = authority @ ErrorCode::Unauthorized
    )]
    pub tree_account: AccountLoader<'info, MerkleTreeAccount>,

    /// SPL or Token-2022 mint account
    pub mint: InterfaceAccount<'info, Mint>,

    /// The authority account that can update tree config
    pub authority: Signer<'info>,
}

#[account]
pub struct TreeTokenAccount {
    pub authority: Pubkey,
    pub bump: u8,
}

#[account]
pub struct GlobalConfig {
    pub authority: Pubkey,
    pub fee_recipient: Pubkey,
    pub deposit_fee_rate: u16,    // basis points (0-10000, where 10000 = 100%)
    pub withdrawal_fee_rate: u16, // basis points (0-10000, where 10000 = 100%)
    pub fee_error_margin: u16,    // basis points (0-10000, where 10000 = 100%)
    pub bump: u8,
}

#[account]
pub struct NullifierAccount {
    /// This account's existence indicates that the nullifier has been used.
    /// No fields needed other than bump for PDA verification.
    pub bump: u8,
}

#[account(zero_copy)]
pub struct MerkleTreeAccount {
    pub authority: Pubkey,
    pub next_index: u64,
    pub subtrees: [[u8; 32]; MERKLE_TREE_HEIGHT as usize],
    pub root: [u8; 32],
    pub root_history: [[u8; 32]; 100],
    pub root_index: u64,
    pub max_deposit_amount: u64,
    pub min_deposit_fee: u64,
    pub min_withdrawal_fee: u64,
    pub height: u8,
    pub root_history_size: u8,
    pub bump: u8,
    // Needed for 8-byte alignment under #[account(zero_copy)].
    pub _padding: [u8; 5],
}

#[error_code]
pub enum ErrorCode {
    #[msg("Not authorized to perform this action")]
    Unauthorized,
    #[msg("External data hash does not match the one in the proof")]
    ExtDataHashMismatch,
    #[msg("Root is not known in the tree")]
    UnknownRoot,
    #[msg("Public amount is invalid")]
    InvalidPublicAmountData,
    #[msg("Insufficient funds for withdrawal")]
    InsufficientFundsForWithdrawal,
    #[msg("Insufficient funds for fee")]
    InsufficientFundsForFee,
    #[msg("Proof is invalid")]
    InvalidProof,
    #[msg("Invalid fee: fee must be less than MAX_ALLOWED_VAL (2^248).")]
    InvalidFee,
    #[msg("Invalid ext amount: absolute ext_amount must be less than MAX_ALLOWED_VAL (2^248).")]
    InvalidExtAmount,
    #[msg("Public amount calculation resulted in an overflow/underflow.")]
    PublicAmountCalculationError,
    #[msg("Arithmetic overflow/underflow occurred")]
    ArithmeticOverflow,
    #[msg("Deposit limit exceeded")]
    DepositLimitExceeded,
    #[msg("Invalid fee rate: must be between 0 and 10000 basis points")]
    InvalidFeeRate,
    #[msg("Fee recipient does not match global configuration")]
    InvalidFeeRecipient,
    #[msg("Fee amount is below minimum required")]
    InvalidFeeAmount,
    #[msg("Recipient account does not match the ExtData recipient")]
    RecipientMismatch,
    #[msg("Merkle tree is full: cannot add more leaves")]
    MerkleTreeFull,
    #[msg("Invalid token account: account is not owned by the token program")]
    InvalidTokenAccount,
    #[msg("Invalid mint address: mint address is not allowed")]
    InvalidMintAddress,
    #[msg("Invalid token account mint address")]
    InvalidTokenAccountMintAddress,
    #[msg("Mint has an unsupported Token-2022 extension")]
    UnsupportedMintExtension,
    #[msg("Actual deposited token amount does not match ext_amount")]
    DepositAmountMismatch,
}
