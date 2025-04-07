use std::collections::HashMap;

use anyhow::{Context, Ok, Result};
use zewif::{Transaction, TxId};

use crate::{WalletTx, ZwlWallet};

pub fn convert_transactions(wallet: &ZwlWallet) -> Result<HashMap<TxId, Transaction>> {
    let mut transactions = HashMap::new();

    for (tx_id, tx) in wallet.transactions.current.clone().into_iter() {
        let id: [u8; 32] = tx_id.into();
        let zewif_txid = TxId::from_bytes(id);
        let zewif_tx = convert_transaction(zewif_txid, &tx)
            .with_context(|| format!("Failed to convert transaction {}", tx_id))?;
        transactions.insert(zewif_txid, zewif_tx);
    }

    Ok(transactions)
}

fn convert_transaction(tx_id: TxId, tx: &WalletTx) -> Result<zewif::Transaction> {
    let mut zewif_tx = Transaction::new(tx_id);

    // No raw transaction data available for ZWL
    // ...

    // Extract transaction status
    match tx.unconfirmed {
        true => zewif_tx.set_status(zewif::TransactionStatus::Pending),
        false => zewif_tx.set_status(zewif::TransactionStatus::Confirmed),
    }

    // Extract timestamp
    if tx.datetime > 0 {
        let timestamp = zewif::SecondsSinceEpoch::from(tx.datetime);
        zewif_tx.set_timestamp(timestamp);
    }

    // TODO: Convert transparent inputs

    // TODO: Convert transparent outputs

    // TODO: Access sapling note data hashmap for witness information if available

    // TODO: Convert Sapling spends and outputs

    // TODO: Convert Orchard actions

    // TODO: Convert Sprout JoinSplits if present

    Ok(zewif_tx)
}
