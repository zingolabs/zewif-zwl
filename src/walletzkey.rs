use std::fmt;
use std::io::{self, ErrorKind, Read};

use byteorder::{LittleEndian, ReadBytesExt};
use sapling::PaymentAddress;
use sapling::zip32::{ExtendedFullViewingKey, ExtendedSpendingKey};
use zcash_encoding::{Optional, Vector};

use super::keys::Keys;
use super::lightclient::LightClientConfig;

#[derive(PartialEq, Debug, Clone)]
pub enum WalletZKeyType {
    HdKey = 0,
    ImportedSpendingKey = 1,
    ImportedViewKey = 2,
}

#[derive(Clone, Debug, PartialEq)]
pub struct WalletZKey {
    pub keytype: WalletZKeyType,
    locked: bool,
    pub extsk: Option<ExtendedSpendingKey>,
    pub extfvk: ExtendedFullViewingKey,
    pub zaddress: PaymentAddress,

    // If this is a HD key, what is the key number
    pub hdkey_num: Option<u32>,

    // If locked, the encrypted private key is stored here
    pub enc_key: Option<Vec<u8>>,
    pub nonce: Option<Vec<u8>>,
}

impl WalletZKey {
    pub fn serialized_version() -> u8 {
        1
    }

    pub fn read<R: Read>(mut reader: R) -> io::Result<Self> {
        let version = reader.read_u8()?;
        assert!(version <= Self::serialized_version());

        // read type of the key
        let keytype: WalletZKeyType = match reader.read_u32::<LittleEndian>()? {
            0 => Ok(WalletZKeyType::HdKey),
            1 => Ok(WalletZKeyType::ImportedSpendingKey),
            2 => Ok(WalletZKeyType::ImportedViewKey),
            n => Err(io::Error::new(
                ErrorKind::InvalidInput,
                format!("Unknown zkey type {}", n),
            )),
        }?;

        // read if address is locked
        let locked = reader.read_u8()? > 0;

        // read address extsk
        let extsk = Optional::read(&mut reader, ExtendedSpendingKey::read)?;

        // read address extfvk
        let extfvk = ExtendedFullViewingKey::read(&mut reader)?;

        // derive zaddress from extfvk
        let (_, zaddress) = extfvk.default_address();

        // If HD derived, read the key index
        let hdkey_num = Optional::read(&mut reader, |r| r.read_u32::<LittleEndian>())?;

        // read "possible" encrypted key
        let enc_key = Optional::read(&mut reader, |r| Vector::read(r, |r| r.read_u8()))?;

        // read ""possible" nounce used for encryption
        let nonce = Optional::read(&mut reader, |r| Vector::read(r, |r| r.read_u8()))?;

        Ok(Self {
            keytype,
            locked,
            extsk,
            extfvk,
            zaddress,
            hdkey_num,
            enc_key,
            nonce,
        })
    }

    #[allow(deprecated)]
    pub fn new_hdkey(hdkey_num: u32, extsk: ExtendedSpendingKey) -> Self {
        let extfvk = extsk.to_extended_full_viewing_key(); // TODO: This is deprecated
        let zaddress = extfvk.default_address().1;

        WalletZKey {
            keytype: WalletZKeyType::HdKey,
            locked: false,
            extsk: Some(extsk),
            extfvk,
            zaddress,
            hdkey_num: Some(hdkey_num),
            enc_key: None,
            nonce: None,
        }
    }

    pub fn new_locked_hdkey(hdkey_num: u32, extfvk: ExtendedFullViewingKey) -> Self {
        let zaddress = extfvk.default_address().1;

        WalletZKey {
            keytype: WalletZKeyType::HdKey,
            locked: true,
            extsk: None,
            extfvk,
            zaddress,
            hdkey_num: Some(hdkey_num),
            enc_key: None,
            nonce: None,
        }
    }

    pub fn have_spending_key(&self) -> bool {
        self.extsk.is_some() || self.enc_key.is_some() || self.hdkey_num.is_some()
    }

    pub fn unlock<P: zcash_protocol::consensus::Parameters>(
        &mut self,
        config: &LightClientConfig<P>,
        bip39_seed: &[u8],
        key: &sodiumoxide::crypto::secretbox::Key,
    ) -> io::Result<()> {
        match self.keytype {
            WalletZKeyType::HdKey => {
                let (extsk, extfvk, address) =
                    Keys::get_zaddr_from_bip39seed(config, bip39_seed, self.hdkey_num.unwrap());

                if address != self.zaddress {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        format!(
                            "zaddress mismatch at {}. {:?} vs {:?}",
                            self.hdkey_num.unwrap(),
                            address,
                            self.zaddress
                        ),
                    ));
                }

                if extfvk != self.extfvk {
                    return Err(io::Error::new(
                        ErrorKind::InvalidData,
                        format!(
                            "fvk mismatch at {}. {:?} vs {:?}",
                            self.hdkey_num.unwrap(),
                            extfvk,
                            self.extfvk
                        ),
                    ));
                }

                self.extsk = Some(extsk);
            }
            WalletZKeyType::ImportedSpendingKey => {
                // For imported keys, we need to decrypt from the encrypted key
                let nonce = sodiumoxide::crypto::secretbox::Nonce::from_slice(
                    self.nonce.as_ref().unwrap(),
                )
                .unwrap();
                let extsk_bytes = match sodiumoxide::crypto::secretbox::open(
                    self.enc_key.as_ref().unwrap(),
                    &nonce,
                    key,
                ) {
                    Ok(s) => s,
                    Err(_) => {
                        return Err(io::Error::new(
                            ErrorKind::InvalidData,
                            "Decryption failed. Is your password correct?",
                        ));
                    }
                };

                self.extsk = Some(ExtendedSpendingKey::read(&extsk_bytes[..])?);
            }
            WalletZKeyType::ImportedViewKey => {
                // Viewing key unlocking is basically a no op
            }
        };

        self.locked = false;
        Ok(())
    }
}

impl fmt::Display for WalletZKey {
    #[allow(unreachable_patterns)]
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.keytype {
            WalletZKeyType::HdKey => {
                writeln!(f, "Type: HD key").unwrap();
            }
            WalletZKeyType::ImportedSpendingKey => {
                writeln!(f, "Type: Imported spending key").unwrap();
            }
            WalletZKeyType::ImportedViewKey => {
                writeln!(f, "Type: Imported view key").unwrap();
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

        if let Some(extsk) = &self.extsk {
            writeln!(f, "{:?}", extsk).unwrap();
        }

        writeln!(f, "{:?}", self.extfvk).unwrap();

        writeln!(f, "{:?}", self.zaddress).unwrap();

        Ok(())
    }
}
