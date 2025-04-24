use std::collections::HashMap;

use anyhow::{Context, Ok, Result};
use zewif::{
    Amount, BlockHeight, Data, JoinSplitDescription, OrchardActionDescription, Script, Transaction,
    TxId, TxIn, TxOut,
    sapling::{SaplingOutputDescription, SaplingSpendDescription},
    u256,
};

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

    // Convert Sapling spends and outputs
    let mut sapling_spends: Vec<SaplingSpendDescription> = Vec::new();

    let input_sapling_notes = tx.s_notes.clone();
    let sapling_spent_nullifiers = tx.s_spent_nullifiers.clone();

    for note in input_sapling_notes.iter() {
        if sapling_spent_nullifiers
            .iter()
            .any(|nf| *nf == note.nullifier)
        {
            // Spend found, we add it to sapling_spends

            // Value
            let mut zewif_sapling_desc = SaplingSpendDescription::new();
            zewif_sapling_desc
                .set_value(Some(Amount::from_u64(note.note.value().inner()).unwrap()));

            // Index: Zecwallet does not store the spend index
            // zewif_sapling_desc.set_spend_index(note);

            // Anchor height
            zewif_sapling_desc.set_anchor_height(Some(BlockHeight::from_u32(
                note.witnesses.top_height as u32,
            )));

            // Nullifier
            zewif_sapling_desc.set_nullifier(u256::from_hex(hex::encode(note.nullifier).as_str()));

            // TODO: ZKProof
            // It might be possible to regenerate this Groth16 proof when matching it with the corresponding
            // SpendingKey, but it is not trivial.

            sapling_spends.push(zewif_sapling_desc);
            // note.spent = Some(true);
        }
    }

    let mut sapling_outputs: Vec<SaplingOutputDescription> = Vec::new();

    let output_sapling_notes = tx.s_notes.clone();

    for note in output_sapling_notes.iter() {
        let mut zewif_sapling_desc = SaplingOutputDescription::new();

        // Output index: Not possible

        // Commitment
        zewif_sapling_desc.set_commitment(u256::from_hex(
            hex::encode(note.note.cmu().to_bytes()).as_str(),
        ));

        // Ephemeral key: Not possible
        // zewif_sapling_desc.set_ephemeral_key(note.note.cmu());

        // Encrypted ciphertext: Not possible
        // zewif_sapling_desc.set_enc_ciphertext(note);

        // Memo
        match &note.memo {
            Some(m) => zewif_sapling_desc.set_memo(Some(Data::from_slice(m.encode().as_slice()))),
            None => zewif_sapling_desc.set_memo(None),
        }

        // Note commitment tree position: Not possible

        // TODO: Witness
        // let zewif_witness: IncrementalWitness<Anchor, SaplingWitness> = IncrementalWitness::
        // zewif_sapling_desc.set_witness

        sapling_outputs.push(zewif_sapling_desc);
    }

    // TODO: Convert Orchard actions
    let orchard_actions: Option<Vec<OrchardActionDescription>>;

    // TODO: Convert Sprout JoinSplits if present
    let sprout_joinsplits: Option<Vec<JoinSplitDescription>>;

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
