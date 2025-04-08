use std::collections::HashMap;

use anyhow::{Context, Ok, Result};
use zewif::{Amount, Data, Script, Transaction, TxId, TxIn, TxOut};

use crate::{Utxo, WalletTx, ZwlWallet};

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
    use std::result::Result::{Err, Ok};

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

    // Note: ZWL does not store any UTXO data, so conversion is not possible.
    // As a result, the transparent_inputs vec will be empty.
    for utxo in tx.utxos.iter() {
        match utxo.spent {
            None => {
                // Unspent UTXO, this means it is an input
                match utxo.try_into() {
                    Err(_) => continue,
                    Ok(tx_in) => zewif_tx.add_input(tx_in),
                }
            }
            Some(_spent_txid) => {
                // Spent UTXO, this means it is an output. Ignored.
            }
        }
    }

    // Convert transparent outputs
    tx.utxos
        .iter()
        .filter_map(|utxo| utxo.try_into().ok())
        .for_each(|zewif_output| {
            zewif_tx.add_output(zewif_output);
        });

    // TODO: Access sapling note data hashmap for witness information if available

    // TODO: Convert Sapling spends and outputs

    // TODO: Convert Orchard actions

    // TODO: Convert Sprout JoinSplits if present

    Ok(zewif_tx)
}

/// For a tx input, zewif needs a previous output, a script signature and the sequence field.
/// Zecwallet does not store any UTXO data. It stores transparent inputs summarized only as a total.
impl TryFrom<&Utxo> for TxIn {
    type Error = ();
    fn try_from(_utxo: &Utxo) -> Result<Self, Self::Error> {
        // let zewif_txin = TxIn::new(previous_output, script_sig, sequence);
        Err(())
    }
}

impl TryFrom<&Utxo> for TxOut {
    type Error = anyhow::Error;
    fn try_from(utxo: &Utxo) -> Result<zewif::TxOut, Self::Error> {
        let tx_out = TxOut::new(
            Amount::from_u64(utxo.value)?,
            Script::from(Data::from_vec(utxo.script.clone())),
        );
        Ok(tx_out)
    }
}
