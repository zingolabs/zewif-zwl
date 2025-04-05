use byteorder::{LittleEndian, ReadBytesExt};
use core::fmt;
use sha2::{Digest, Sha256};
use std::io::{self, Read};
use zcash_encoding::{Optional, Vector};
use zingolib::wallet::keys::ToBase58Check;

use crate::extended_keys::{ExtendedPrivKey, KeyIndex};

use super::lightclient::LightClientConfig;

#[derive(Debug, PartialEq, Clone, Copy)]
pub enum WalletTKeyType {
    HdKey = 0,
    ImportedKey = 1,
}

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct WalletTKey {
    pub keytype: WalletTKeyType,
    pub locked: bool,
    pub key: Option<secp256k1::SecretKey>,
    pub address: String,

    // If this is a HD key, what is the key number
    pub hdkey_num: Option<u32>,

    // If locked, the encrypted private key is stored here
    pub enc_key: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
}

impl WalletTKey {
    fn serialized_version() -> u8 {
        1
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let version = reader.read_u8()?;
        assert!(version <= Self::serialized_version());

        // read type of the key
        let keytype: WalletTKeyType = match reader.read_u32::<LittleEndian>()? {
            0 => Ok(WalletTKeyType::HdKey),
            1 => Ok(WalletTKeyType::ImportedKey),
            n => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!("Unknown tkey type: {}", n),
            )),
        }?;

        // read if address is locked
        let locked = reader.read_u8()? > 0;

        let key = Optional::read(&mut reader, |r| {
            let mut tpk_bytes = [0u8; 32];
            r.read_exact(&mut tpk_bytes)?;
            secp256k1::SecretKey::from_slice(&tpk_bytes)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
        })?;

        // read encoded t address as String
        // Strings are written as <littleendian> len + bytes
        let str_len = reader.read_u64::<LittleEndian>()?;
        let mut str_bytes = vec![0; str_len as usize];
        reader.read_exact(&mut str_bytes)?;

        // The actual encoded address
        let address = String::from_utf8(str_bytes)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;

        // If HD derived, read the key index
        let hdkey_num = Optional::read(&mut reader, |r| r.read_u32::<LittleEndian>())?;

        // read "possible" encrypted key
        let enc_key = Optional::read(&mut reader, |r| Vector::read(r, |r| r.read_u8()))?;

        // read ""possible" nounce used for encryption
        let nonce = Optional::read(&mut reader, |r| Vector::read(r, |r| r.read_u8()))?;

        Ok(Self {
            keytype,
            locked,
            key,
            hdkey_num,
            enc_key,
            nonce,
            address,
        })
    }

    pub fn address_from_prefix_sk(prefix: &[u8; 2], sk: &secp256k1::SecretKey) -> String {
        let secp = secp256k1::Secp256k1::new();
        let pk = secp256k1::PublicKey::from_secret_key(&secp, &sk);

        // Encode into t address
        let mut hash160 = ripemd::Ripemd160::new();
        hash160.update(Sha256::digest(&pk.serialize()[..].to_vec()));

        let finalized_pk = hash160.finalize().to_base58check(prefix, &[]);

        finalized_pk
    }

    pub fn from_raw(sk: &secp256k1::SecretKey, taddr: &String, num: u32) -> Self {
        WalletTKey {
            keytype: WalletTKeyType::HdKey,
            key: Some(sk.clone()),
            address: taddr.clone(),
            hdkey_num: Some(num),
            locked: false,
            enc_key: None,
            nonce: None,
        }
    }

    pub fn get_taddr_from_bip39seed<P: zcash_protocol::consensus::Parameters>(
        config: &LightClientConfig<P>,
        bip39_seed: &[u8],
        pos: u32,
    ) -> secp256k1::SecretKey {
        assert_eq!(bip39_seed.len(), 64);

        let ext_t_key = ExtendedPrivKey::with_seed(bip39_seed).unwrap();
        let r = ext_t_key
            .derive_private_key(KeyIndex::hardened_from_normalize_index(44).unwrap())
            .unwrap()
            .derive_private_key(
                KeyIndex::hardened_from_normalize_index(config.get_coin_type()).unwrap(),
            )
            .unwrap()
            .derive_private_key(KeyIndex::hardened_from_normalize_index(0).unwrap())
            .unwrap()
            .derive_private_key(KeyIndex::Normal(0))
            .unwrap()
            .derive_private_key(KeyIndex::Normal(pos))
            .unwrap()
            .private_key;

        r
    }

    pub fn unlock<P: zcash_protocol::consensus::Parameters>(
        &mut self,
        config: &LightClientConfig<P>,
        bip39_seed: &[u8],
        key: &sodiumoxide::crypto::secretbox::Key,
    ) -> io::Result<()> {
        match self.keytype {
            WalletTKeyType::HdKey => {
                let sk =
                    Self::get_taddr_from_bip39seed(&config, &bip39_seed, self.hdkey_num.unwrap());

                // Transparent address generation
                let address = Self::address_from_prefix_sk(&config.base58_pubkey_address(), &sk);

                assert_eq!(
                    address,
                    self.address,
                    "Transparent addresses mismatch at {}. {:?} vs {:?}",
                    self.hdkey_num.unwrap(),
                    address,
                    self.address
                );
                if address != self.address {
                    return Err(io::Error::new(
                        std::io::ErrorKind::InvalidData,
                        format!(
                            "address mismatch at {}. {:?} vs {:?}",
                            self.hdkey_num.unwrap(),
                            address,
                            self.address
                        ),
                    ));
                }

                self.key = Some(sk)
            }
            WalletTKeyType::ImportedKey => {
                // For imported keys, we need to decrypt from the encrypted key
                let nonce = sodiumoxide::crypto::secretbox::Nonce::from_slice(
                    &self.nonce.as_ref().unwrap(),
                )
                .unwrap();
                let sk_bytes = match sodiumoxide::crypto::secretbox::open(
                    &self.enc_key.as_ref().unwrap(),
                    &nonce,
                    &key,
                ) {
                    Ok(s) => s,
                    Err(_) => {
                        return Err(io::Error::new(
                            std::io::ErrorKind::InvalidData,
                            "Decryption failed. Is your password correct?",
                        ));
                    }
                };

                let key = secp256k1::SecretKey::from_slice(&sk_bytes[..])
                    .map_err(|e| io::Error::new(std::io::ErrorKind::InvalidData, e))?;
                self.key = Some(key);
            }
        };

        self.locked = false;
        Ok(())
    }
}

impl fmt::Display for WalletTKey {
    #[allow(unreachable_patterns)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.keytype {
            WalletTKeyType::HdKey => {
                writeln!(f, "Type: HD key").unwrap();
            }
            WalletTKeyType::ImportedKey => {
                writeln!(f, "Type: Imported key").unwrap();
            }
            _ => {
                writeln!(f, "Type: Unknown").unwrap();
            }
        }

        match self.locked {
            true => {
                writeln!(f, "Status: Encrypted").unwrap();
            }
            false => {
                writeln!(f, "Status: Decrypted").unwrap();
            }
        }

        if let Some(private_key) = &self.key {
            writeln!(
                f,
                "Private key: {}",
                hex::encode(private_key.secret_bytes())
            )
            .unwrap();
        }

        writeln!(f, "Address: {}", self.address).unwrap();

        Ok(())
    }
}
