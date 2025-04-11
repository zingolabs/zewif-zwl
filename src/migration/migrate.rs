use anyhow::{Result, bail};
use zewif::{Network, ZewifTop, ZewifWallet};

use crate::ZwlWallet;

use super::{convert_seed_material, convert_transactions};

/// Migrate a Zecwallet-lite wallet to the Zewif wallet format
pub fn migrate_to_zewif(wallet: &ZwlWallet) -> Result<ZewifTop> {
    // Create a new ZewifTop
    let mut zewif_top = ZewifTop::new();

    // Convert seed material (mnemonic phrase)
    let seed_material = convert_seed_material(wallet)?;

    let network = match wallet.chain_name() {
        "zs" => Network::Main,
        "mainnet" => Network::Main,
        "main" => Network::Main,
        "testnet" => Network::Test,
        "regtest" => Network::Regtest,
        _ => bail!("Unsupported chain name: {}", wallet.chain_name()),
    };

    // Create a complete Zewif wallet
    let mut zewif_wallet = ZewifWallet::new(network);

    if let Some(seed_material) = seed_material {
        zewif_wallet.set_seed_material(seed_material);
    }

    // Process transactions and collect relevant transaction IDs
    let transactions = convert_transactions(wallet)?;

    // // Convert orchard note commitment tree if available
    // if !wallet
    //     .orchard_note_commitment_tree()
    //     .unparsed_data()
    //     .is_empty()
    // {
    //     // Update transaction outputs with note positions from the note commitment tree
    //     update_transaction_positions(wallet, &mut transactions)?;
    // }

    // // If there are unified accounts, process them
    // if let Some(unified_accounts) = wallet.unified_accounts() {
    //     // Create accounts based on unified_accounts structure
    //     let mut accounts_map = convert_unified_accounts(wallet, unified_accounts, &transactions)?;

    //     // Initialize address registry to track address-to-account relationships
    //     let address_registry = initialize_address_registry(wallet, unified_accounts)?;

    //     // Create a default account for addresses not associated with any other account
    //     let mut default_account = Account::new();
    //     default_account.set_name("Default Account");

    //     // Create a mutable reference for accounts_map to use in the conversion functions
    //     let mut accounts_map_ref = Some(&mut accounts_map);

    //     // Convert transparent addresses using the registry to assign to correct accounts
    //     convert_transparent_addresses(
    //         wallet,
    //         &mut default_account,
    //         Some(&address_registry),
    //         &mut accounts_map_ref,
    //     )?;

    //     // Convert sapling addresses using the registry to assign to correct accounts
    //     convert_sapling_addresses(
    //         wallet,
    //         &mut default_account,
    //         Some(&address_registry),
    //         &mut accounts_map_ref,
    //     )?;

    //     // Convert unified addresses using the registry to assign to correct accounts
    //     convert_unified_addresses(
    //         wallet,
    //         &mut default_account,
    //         Some(&address_registry),
    //         &mut accounts_map_ref,
    //     )?;

    //     // Add the default account to accounts_map if it has any addresses
    //     if !default_account.addresses().is_empty() {
    //         accounts_map.insert(u256::default(), default_account);
    //     }

    //     // Add all accounts to the wallet
    //     for account in accounts_map.values() {
    //         zewif_wallet.add_account(account.clone());
    //     }
    // } else {
    //     // No unified accounts - create a single default account
    //     let mut default_account = Account::new();
    //     default_account.set_name("Default Account");

    //     // Create a None reference for accounts_map
    //     let mut accounts_map_ref = None;

    //     // Convert transparent addresses (single account mode)
    //     convert_transparent_addresses(wallet, &mut default_account, None, &mut accounts_map_ref)?;

    //     // Convert sapling addresses (single account mode)
    //     convert_sapling_addresses(wallet, &mut default_account, None, &mut accounts_map_ref)?;

    //     // Add all transaction IDs to the default account's relevant transactions
    //     for txid in transactions.keys() {
    //         default_account.add_relevant_transaction(*txid);
    //     }

    //     // Add the default account to the wallet
    //     zewif_wallet.add_account(default_account);
    // }

    // Add wallet and transactions to the ZewifTop
    zewif_top.add_wallet(zewif_wallet);
    zewif_top.set_transactions(transactions);

    Ok(zewif_top)
}
