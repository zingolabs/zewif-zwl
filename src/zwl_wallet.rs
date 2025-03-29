#![allow(dead_code)]

use incrementalmerkletree::bridgetree::BridgeTree;
use orchard_old::tree::MerkleHashOrchard;
use zcash_client_backend::proto::service::TreeState;

use crate::{CompactBlockData, Keys, WalletOptions, WalletTxns, WalletZecPriceInfo};

use crate::orchard_tree::MERKLE_DEPTH;

#[derive(Debug)]
pub struct ZwlWallet {
    pub version: u64,
    pub keys: Keys<zcash_protocol::consensus::MainNetwork>,
    pub blocks: Vec<CompactBlockData>,
    pub transactions: WalletTxns,
    pub chain_name: String,
    pub wallet_options: WalletOptions,
    pub birthday: u64,
    pub verified_tree: Option<TreeState>,
    pub orchard_witnesses: Option<BridgeTree<MerkleHashOrchard, MERKLE_DEPTH>>,
    pub price: WalletZecPriceInfo,
    pub remaining: usize,
}

impl ZwlWallet {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        version: u64,
        chain_name: String,
        blocks: Vec<CompactBlockData>,
        transactions: WalletTxns,
        birthday: u64,
        wallet_options: WalletOptions,
        verified_tree: Option<TreeState>,
        price: WalletZecPriceInfo,
        keys: Keys<zcash_protocol::consensus::MainNetwork>,
        orchard_witnesses: Option<BridgeTree<MerkleHashOrchard, MERKLE_DEPTH>>,
        remaining: usize,
    ) -> Self {
        ZwlWallet {
            version,
            chain_name,
            birthday,
            wallet_options,
            verified_tree,
            price,
            blocks,
            keys,
            transactions,
            orchard_witnesses,
            remaining,
        }
    }

    pub fn version(&self) -> u64 {
        self.version
    }

    pub fn chain_name(&self) -> &str {
        &self.chain_name
    }

    pub fn birthday(&self) -> u64 {
        self.birthday
    }

    pub fn wallet_options(&self) -> &WalletOptions {
        &self.wallet_options
    }

    pub fn verified_tree(&self) -> &Option<TreeState> {
        &self.verified_tree
    }

    pub fn price(&self) -> &WalletZecPriceInfo {
        &self.price
    }

    pub fn remaining(&self) -> usize {
        self.remaining
    }
}
