use std::io::{self, Error, ErrorKind, Read};

use anyhow::Result;
use byteorder::{LittleEndian, ReadBytesExt};
use sapling::{
    PaymentAddress,
    zip32::{ExtendedFullViewingKey, ExtendedSpendingKey},
};
use zcash_encoding::Vector;
use zewif::parser::{ParseWithParam, Parser};
use zingolib::wallet::{keys::double_sha256, utils::read_string};

use crate::{
    LightClientConfig, walletokey::WalletOKey, wallettkey::WalletTKey, walletzkey::WalletZKey,
};

#[allow(dead_code)]
#[derive(Debug)]
pub struct Keys<P> {
    config: LightClientConfig<P>,
    // Is the wallet encrypted? If it is, then when writing to disk, the seed is always encrypted
    // and the individual spending keys are not written
    pub encrypted: bool,

    pub enc_seed: [u8; 48], // If locked, this contains the encrypted seed
    pub nonce: Vec<u8>,     // Nonce used to encrypt the wallet.

    pub seed: [u8; 32], // Seed phrase for this wallet. If wallet is locked, this is 0

    // List of keys, actually in this wallet. This is a combination of HD keys derived from the seed,
    // viewing keys and imported spending keys.
    pub zkeys: Vec<WalletZKey>,

    // Transparent keys. If the wallet is locked, then the secret keys will be encrypted,
    // but the addresses will be present. This Vec contains both wallet and imported tkeys
    pub tkeys: Vec<WalletTKey>,

    // Unified address (Orchard) keys actually in this wallet.
    // If wallet is locked, only viewing keys are present.
    pub okeys: Vec<WalletOKey>,
}

impl<P: zcash_protocol::consensus::Parameters> Keys<P> {
    pub fn serialized_version() -> u64 {
        22
    }

    pub fn read<R: ReadBytesExt>(mut reader: R, config: LightClientConfig<P>) -> io::Result<Self> {
        let version = reader.read_u64::<LittleEndian>()?;

        if version > Self::serialized_version() {
            let e = format!(
                "Don't know how to read `Keys` struct version {}. Do you have the latest version?",
                version
            );
            return Err(io::Error::new(io::ErrorKind::InvalidData, e));
        }

        // Read if wallet is encrypted
        let encrypted = reader.read_u8()? > 0;

        // Read "possible" encypted seed
        let mut enc_seed = [0u8; 48];
        reader.read_exact(&mut enc_seed)?;

        // Read nounce used for encyption
        let nonce = Vector::read(&mut reader, |r| r.read_u8())?;

        // Read "possible" clear seed
        let mut seed_bytes = [0u8; 32];
        reader.read_exact(&mut seed_bytes)?;

        let okeys = if version <= 21 {
            vec![]
        } else {
            Vector::read(&mut reader, |r| WalletOKey::read(r))?
        };

        // TODO: read old versions of wallet file
        let zkeys = Vector::read(&mut reader, |r| WalletZKey::read(r))?;

        // read wallet tkeys

        let tkeys = if version <= 20 {
            let tkeys = Vector::read(&mut reader, |r| {
                let mut tpk_bytes = [0u8; 32];
                r.read_exact(&mut tpk_bytes)?;
                secp256k1::SecretKey::from_slice(&tpk_bytes)
                    .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
            })?;

            let taddresses = Vector::read(&mut reader, |r| read_string(r))?;

            tkeys
                .iter()
                .zip(taddresses.iter())
                .enumerate()
                .map(|(i, (sk, taddr))| WalletTKey::from_raw(sk, taddr, i as u32))
                .collect::<Vec<_>>()
        } else {
            // Read the TKeys
            Vector::read(&mut reader, |r| WalletTKey::read(r))?
        };

        Ok(Self {
            config: config.clone(),
            encrypted,
            enc_seed,
            nonce,
            seed: seed_bytes,
            zkeys,
            tkeys,
            okeys,
        })
    }

    #[allow(dead_code, deprecated)]
    pub fn read_old<R: ReadBytesExt>(
        version: u64,
        mut reader: R,
        config: LightClientConfig<P>,
    ) -> io::Result<Self> {
        let encrypted = if version >= 4 {
            reader.read_u8()? > 0
        } else {
            false
        };

        let mut enc_seed = [0u8; 48];
        if version >= 4 {
            reader.read_exact(&mut enc_seed)?;
        }

        let nonce = if version >= 4 {
            Vector::read(&mut reader, |r| r.read_u8())?
        } else {
            vec![]
        };

        // Seed
        let mut seed_bytes = [0u8; 32];
        reader.read_exact(&mut seed_bytes)?;

        let zkeys = if version <= 6 {
            // Up until version 6, the wallet keys were written out individually
            // Read the spending keys
            let extsks = Vector::read(&mut reader, |r| {
                sapling::zip32::ExtendedSpendingKey::read(r)
            })?;

            let extfvks = if version >= 4 {
                // Read the viewing keys
                Vector::read(&mut reader, |r| {
                    sapling::zip32::ExtendedFullViewingKey::read(r)
                })?
            } else {
                // Calculate the viewing keys
                extsks
                    .iter()
                    .map(|sk| sk.to_extended_full_viewing_key()) // TODO: This is deprecated
                    .collect::<Vec<sapling::zip32::ExtendedFullViewingKey>>()
            };

            // Calculate the addresses
            let addresses = extfvks
                .iter()
                .map(|fvk| fvk.default_address().1)
                .collect::<Vec<sapling::PaymentAddress>>();

            // If extsks is of len 0, then this wallet is locked
            let zkeys_result = if extsks.len() == 0 {
                // Wallet is locked, so read only the viewing keys.
                extfvks
                    .iter()
                    .zip(addresses.iter())
                    .enumerate()
                    .map(|(i, (extfvk, payment_address))| {
                        let zk = WalletZKey::new_locked_hdkey(i as u32, extfvk.clone());
                        if zk.zaddress != *payment_address {
                            Err(io::Error::new(
                                ErrorKind::InvalidData,
                                "Payment address didn't match",
                            ))
                        } else {
                            Ok(zk)
                        }
                    })
                    .collect::<Vec<io::Result<WalletZKey>>>()
            } else {
                // Wallet is unlocked, read the spending keys as well
                extsks
                    .into_iter()
                    .zip(extfvks.into_iter().zip(addresses.iter()))
                    .enumerate()
                    .map(|(i, (extsk, (extfvk, payment_address)))| {
                        let zk = WalletZKey::new_hdkey(i as u32, extsk);
                        if zk.zaddress != *payment_address {
                            return Err(io::Error::new(
                                ErrorKind::InvalidData,
                                "Payment address didn't match",
                            ));
                        }

                        if zk.extfvk != extfvk {
                            return Err(io::Error::new(
                                ErrorKind::InvalidData,
                                "Full View key didn't match",
                            ));
                        }

                        Ok(zk)
                    })
                    .collect::<Vec<io::Result<WalletZKey>>>()
            };

            // Convert vector of results into result of vector, returning an error if any one of the keys failed the checks above
            zkeys_result.into_iter().collect::<io::Result<_>>()?
        } else {
            // After version 6, we read the WalletZKey structs directly
            Vector::read(&mut reader, |r| WalletZKey::read(r))?
        };

        let tkeys = if version <= 20 {
            let tkeys = Vector::read(&mut reader, |r| {
                let mut tpk_bytes = [0u8; 32];
                r.read_exact(&mut tpk_bytes)?;
                secp256k1::SecretKey::from_slice(&tpk_bytes)
                    .map_err(|e| io::Error::new(ErrorKind::InvalidData, e))
            })?;

            let taddresses = if version >= 4 {
                // Read the addresses
                Vector::read(&mut reader, |r| read_string(r))?
            } else {
                // Calculate the addresses
                tkeys
                    .iter()
                    .map(|sk| {
                        WalletTKey::address_from_prefix_sk(&config.base58_pubkey_address(), sk)
                    })
                    .collect()
            };

            tkeys
                .iter()
                .zip(taddresses.iter())
                .enumerate()
                .map(|(i, (sk, taddr))| WalletTKey::from_raw(sk, taddr, i as u32))
                .collect::<Vec<_>>()
        } else {
            // Read the TKeys
            Vector::read(&mut reader, |r| WalletTKey::read(r))?
        };

        Ok(Self {
            config: config.clone(),
            encrypted,
            enc_seed,
            nonce,
            seed: seed_bytes,
            zkeys,
            tkeys,
            okeys: vec![],
        })
    }

    pub fn get_all_extfvks(&self) -> Vec<sapling::zip32::ExtendedFullViewingKey> {
        self.zkeys.iter().map(|zk| zk.extfvk.clone()).collect()
    }

    pub fn have_sapling_spending_key(
        &self,
        extfvk: &sapling::zip32::ExtendedFullViewingKey,
    ) -> bool {
        self.zkeys
            .iter()
            .find(|zk| zk.extfvk == *extfvk)
            .map(|zk| zk.have_spending_key())
            .unwrap_or(false)
    }

    pub fn get_phrase(&mut self, passwd: String) -> io::Result<bip0039::Mnemonic> {
        if !self.encrypted {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                "Wallet is not encrypted",
            ));
        }

        // && self.unlocked this was only used in-memory
        if !self.encrypted {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                "Wallet is already unlocked",
            ));
        }

        // Secret key used for encryption
        // let key = crypto_box::SecretKey::from_slice(&double_sha256(passwd.as_bytes())).unwrap();
        let key =
            sodiumoxide::crypto::secretbox::Key::from_slice(&double_sha256(passwd.as_bytes()))
                .unwrap();

        // Nonce
        let nonce = match sodiumoxide::crypto::secretbox::Nonce::from_slice(&self.nonce) {
            Some(n) => n,
            None => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "Nonce is not the right length",
                ));
            }
        };

        let seed = match sodiumoxide::crypto::secretbox::open(&self.enc_seed, &nonce, &key) {
            Ok(s) => s,
            Err(_) => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "Decryption failed. Is your password correct?",
                ));
            }
        };

        // Now that we have the seed, we'll generate the extsks and tkeys, and verify the fvks and addresses
        // respectively match

        // The seed bytes is the raw entropy. To pass it to HD wallet generation,
        // we need to get the 64 byte bip39 entropy

        return Ok(bip0039::Mnemonic::<bip0039::language::English>::from_entropy(seed).unwrap());
    }

    pub fn unlock_wallet(&mut self, passwd: String) -> io::Result<&mut Self> {
        if !self.encrypted {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                "Wallet is not encrypted",
            ));
        }

        // && self.unlocked this was only used in-memory
        if !self.encrypted {
            return Err(Error::new(
                ErrorKind::AlreadyExists,
                "Wallet is already unlocked",
            ));
        }

        let double_shad = double_sha256(passwd.as_bytes());

        // Get the doublesha256 of the password
        let key = sodiumoxide::crypto::secretbox::Key::from_slice(&double_shad).unwrap();

        // Nonce
        let nonce = match sodiumoxide::crypto::secretbox::Nonce::from_slice(&self.nonce) {
            Some(n) => n,
            None => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "Nonce is not the right length",
                ));
            }
        };

        let seed = match sodiumoxide::crypto::secretbox::open(&self.enc_seed, &nonce, &key) {
            Ok(s) => s,
            Err(_) => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "Decryption failed. Is your password correct?",
                ));
            }
        };

        let mnemonic = bip0039::Mnemonic::<bip0039::English>::from_entropy(seed.clone()).unwrap();

        let bip39_seed = mnemonic.to_seed("");
        // Now that we have the seed, we'll generate the extsks and tkeys, and verify the fvks and addresses
        // respectively match

        // The seed bytes is the raw entropy. To pass it to HD wallet generation,
        // we need to get the 64 byte bip39 entropy

        let config = self.config.clone();

        // Transparent keys
        self.tkeys
            .iter_mut()
            .map(|tk| tk.unlock(&config, bip39_seed.to_vec()[..].as_ref(), &key))
            .collect::<io::Result<Vec<()>>>()?;

        // Go over the zkeys, and add the spending keys again
        self.zkeys
            .iter_mut()
            .map(|zk| zk.unlock(&config, bip39_seed.to_vec()[..].as_ref(), &key))
            .collect::<io::Result<Vec<()>>>()?;

        self.seed.copy_from_slice(&seed);

        self.encrypted = true;
        return Ok(self);
    }

    pub fn get_zaddr_from_bip39seed(
        config: &LightClientConfig<P>,
        bip39_seed: &[u8],
        pos: u32,
    ) -> (ExtendedSpendingKey, ExtendedFullViewingKey, PaymentAddress) {
        assert_eq!(bip39_seed.len(), 64);

        let extsk: ExtendedSpendingKey = ExtendedSpendingKey::from_path(
            &ExtendedSpendingKey::master(bip39_seed),
            &[
                zcash_primitives::zip32::ChildIndex::hardened(32),
                zcash_primitives::zip32::ChildIndex::hardened(config.get_coin_type()),
                zcash_primitives::zip32::ChildIndex::hardened(pos),
            ],
        );
        let extfvk: ExtendedFullViewingKey = extsk.to_extended_full_viewing_key();
        let address = extfvk.default_address().1;

        (extsk, extfvk, address)
    }
}

impl<P: zcash_protocol::consensus::Parameters> ParseWithParam<(LightClientConfig<P>, u64)>
    for Keys<P>
{
    fn parse(p: &mut Parser, param: (LightClientConfig<P>, u64)) -> Result<Self> {
        let (config, version) = param;

        let keys = if version <= 14 {
            Keys::read_old(version, p, config)?
        } else {
            Keys::read(p, config)?
        };

        Ok(keys)
    }
}
