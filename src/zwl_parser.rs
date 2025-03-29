use std::{
    collections::BTreeMap,
    io::{self, ErrorKind},
};

use anyhow::{Context, Result, bail};
use byteorder::{LittleEndian, ReadBytesExt};
use incrementalmerkletree::{
    Hashable, Position,
    bridgetree::{AuthFragment, BridgeTree, Checkpoint, Leaf, MerkleBridge, NonEmptyFrontier},
};
use orchard_old::tree::MerkleHashOrchard;
use zcash_client_backend::proto::service::TreeState;
use zcash_encoding::{Optional, Vector};
use zcash_protocol::consensus::MainNetwork;
use zewif::{Data, parse, parser::Parser};

use crate::{
    CompactBlockData, HashSer, Keys, LightClientConfig, SER_V1, WalletOptions, WalletTxns,
    WalletZecPriceInfo, ZwlWallet, read_string,
};

#[derive(Debug)]
pub struct ZwlParser<'a> {
    pub parser: Parser<'a>,
}

impl<'a> ZwlParser<'a> {
    const fn serialized_version() -> u64 {
        31
    }

    pub fn new(dump: &'a Data) -> Self {
        let parser = Parser::new(dump);
        Self { parser }
    }

    pub fn parse(&mut self) -> Result<ZwlWallet> {
        let config = LightClientConfig::create_unconnected(MainNetwork, None);
        self.parse_with_param(config)
    }

    /// Parses a Zecwallet wallet.
    ///
    /// ZWL wallet files use a bespoke binary format to store data.
    /// The following properties are present:
    /// - version
    /// - keys
    /// - blocks
    /// - transactions
    /// - chain name
    /// - wallet options
    /// - birthday
    /// - commitment tree state
    /// - price info
    /// - orchard witnesses
    #[allow(unused_variables, clippy::redundant_closure)]
    pub fn parse_with_param(
        &mut self,
        config: LightClientConfig<MainNetwork>,
    ) -> Result<ZwlWallet> {
        let p = &mut self.parser;

        let external_version = parse!(p, u64, "external_version")?;

        if external_version > Self::serialized_version() {
            bail!(
                "Don't know how to read wallet version {}. Do you have the latest version?",
                external_version
            );
        }

        let keys = parse!(
            p,
            Keys<zcash_protocol::consensus::MainNetwork>,
            param = (config, external_version),
            "keys"
        )?;

        let mut blocks =
            Vector::read(&mut *p, |r| CompactBlockData::read(r)).with_context(|| "BlockData")?;
        if external_version <= 14 {
            // Reverse the order, since after version 20, we need highest-block-first
            // TODO: Consider order between 14 and 20.
            blocks = blocks.into_iter().rev().collect();
        }

        let mut txns = if external_version <= 14 {
            WalletTxns::read_old(&mut *p)
        } else {
            WalletTxns::read(&mut *p)
        }?;

        let chain_name = read_string(&mut *p)?;

        // // TODO: return the error
        // if chain_name != config.chain_name {
        //     return Err(std::io::new(
        //         ErrorKind::InvalidData,
        //         format!(
        //             "Wallet chain name {} doesn't match expected {}",
        //             chain_name, config.chain_name
        //         ),
        //     ));
        // }

        let wallet_options = if external_version <= 23 {
            WalletOptions::default()
        } else {
            WalletOptions::read(&mut *p).with_context(|| "WalletOptions")?
        };

        let birthday = parse!(p, u64, "birthday")?;

        if external_version <= 22 {
            let _sapling_tree_verified = if external_version <= 12 {
                true
            } else {
                // reader.read_u8()? == 1
                parse!(p, u8, "sapling_tree_verified")? == 1
            };
        }

        let verified_tree = if external_version <= 21 {
            None
        } else {
            Optional::read(&mut *p, |r| {
                use prost::Message;

                let buf = Vector::read(r, |r| r.read_u8())?;
                TreeState::decode(&buf[..])
                    .map_err(|e| io::Error::new(ErrorKind::InvalidData, e.to_string()))
            })?
        };

        // If version <= 8, adjust the "is_spendable" status of each note data
        if external_version <= 8 {
            // Collect all spendable keys
            let spendable_keys: Vec<_> = keys
                .get_all_extfvks()
                .into_iter()
                .filter(|extfvk| keys.have_sapling_spending_key(extfvk))
                .collect();

            txns.adjust_spendable_status(spendable_keys);
        }

        let price = if external_version <= 13 {
            WalletZecPriceInfo::default()
        } else {
            WalletZecPriceInfo::read(&mut *p)?
        };

        // Read the orchard tree
        let orchard_witnesses = if external_version <= 24 {
            None
        } else {
            Optional::read(&mut *p, |r| Self::read_tree::<MerkleHashOrchard, _>(r))?
        };

        let remaining = p.remaining();

        Ok(ZwlWallet {
            version: external_version,
            chain_name,
            birthday,
            wallet_options,
            verified_tree,
            price,
            keys: keys,
            blocks: blocks,
            transactions: txns,
            orchard_witnesses,
            remaining,
        })
    }

    #[allow(clippy::redundant_closure)]
    pub fn read_tree<H: Hashable + HashSer + Ord + Clone, R: ReadBytesExt>(
        mut reader: R,
    ) -> io::Result<BridgeTree<MerkleHashOrchard, 32>> {
        let _version = reader.read_u64::<LittleEndian>()?;

        let prior_bridges = Vector::read(&mut reader, |r| Self::read_bridge(r))?;
        let current_bridge = Optional::read(&mut reader, |r| Self::read_bridge(r))?;
        let saved: BTreeMap<Position, usize> = Vector::read_collected(&mut reader, |mut r| {
            Ok((
                Self::read_position(&mut r)?,
                Self::read_leu64_usize(&mut r)?,
            ))
        })?;

        let checkpoints = Vector::read_collected(&mut reader, |r| Self::read_checkpoint_v2(r))?;
        let max_checkpoints = Self::read_leu64_usize(&mut reader)?;

        BridgeTree::from_parts(
            prior_bridges,
            current_bridge,
            saved,
            checkpoints,
            max_checkpoints,
        )
        .map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "Consistency violation found when attempting to deserialize Merkle tree: {:?}",
                    err
                ),
            )
        })
    }

    pub fn read_bridge<H: HashSer + Ord + Clone, R: ReadBytesExt>(
        mut reader: R,
    ) -> io::Result<MerkleBridge<H>> {
        match reader.read_u8()? {
            SER_V1 => ZwlParser::read_bridge_v1(&mut reader),
            flag => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unrecognized serialization version: {:?}", flag),
            )),
        }
    }

    pub fn read_bridge_v1<H: HashSer + Ord + Clone, R: ReadBytesExt>(
        mut reader: R,
    ) -> io::Result<MerkleBridge<H>> {
        let prior_position = Optional::read(&mut reader, ZwlParser::read_position)?;
        let auth_fragments = Vector::read(&mut reader, |mut r| {
            Ok((
                Self::read_position(&mut r)?,
                ZwlParser::read_auth_fragment_v1(r)?,
            ))
        })?
        .into_iter()
        .collect();
        let frontier = Self::read_nonempty_frontier_v1(&mut reader)?;

        Ok(MerkleBridge::from_parts(
            prior_position,
            auth_fragments,
            frontier,
        ))
    }

    pub fn read_position<R: ReadBytesExt>(mut reader: R) -> io::Result<Position> {
        Self::read_leu64_usize(&mut reader).map(Position::from)
    }

    #[allow(clippy::redundant_closure)]
    pub fn read_nonempty_frontier_v1<H: HashSer + Clone, R: ReadBytesExt>(
        mut reader: R,
    ) -> io::Result<NonEmptyFrontier<H>> {
        let position = Self::read_position(&mut reader)?;
        let left = H::read(&mut reader)?;
        let right = Optional::read(&mut reader, H::read)?;

        let leaf = right.map_or_else(
            || Leaf::Left(left.clone()),
            |r| Leaf::Right(left.clone(), r),
        );
        let ommers = Vector::read(&mut reader, |r| H::read(r))?;

        NonEmptyFrontier::from_parts(position, leaf, ommers).map_err(|err| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Parsing resulted in an invalid Merkle frontier: {:?}", err),
            )
        })
    }

    #[allow(clippy::redundant_closure)]
    pub fn read_auth_fragment_v1<H: HashSer, R: ReadBytesExt>(
        mut reader: R,
    ) -> io::Result<AuthFragment<H>> {
        let position = Self::read_position(&mut reader)?;
        let alts_observed = Self::read_leu64_usize(&mut reader)?;
        let values = Vector::read(&mut reader, |r| H::read(r))?;

        Ok(AuthFragment::from_parts(position, alts_observed, values))
    }

    pub fn read_checkpoint_v2<R: ReadBytesExt>(mut reader: R) -> io::Result<Checkpoint> {
        Ok(Checkpoint::from_parts(
            Self::read_leu64_usize(&mut reader)?,
            reader.read_u8()? == 1,
            Vector::read_collected(&mut reader, |r| Self::read_position(r))?,
            Vector::read_collected(&mut reader, |mut r| {
                Ok((
                    ZwlParser::read_position(&mut r)?,
                    Self::read_leu64_usize(&mut r)?,
                ))
            })?,
        ))
    }

    /// Reads a usize value encoded as a u64 in little-endian order. Since usize
    /// is platform-dependent, we consistently represent it as u64 in serialized
    /// formats.
    pub fn read_leu64_usize<R: ReadBytesExt>(mut reader: R) -> io::Result<usize> {
        reader.read_u64::<LittleEndian>()?.try_into().map_err(|e| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "usize could not be decoded from a 64-bit value on this platform: {:?}",
                    e
                ),
            )
        })
    }
}
