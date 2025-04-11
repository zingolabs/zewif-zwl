use anyhow::Result;
use zewif::Blob32;

use crate::ZwlWallet;

/// Convert Zecwallet mnemonic seed to Zewif SeedMaterial
pub fn convert_seed_material(wallet: &ZwlWallet) -> Result<Option<zewif::SeedMaterial>> {
    // Even if the wallet was encrypted, the seed should be available at this point
    let seed_material =
        zewif::SeedMaterial::PreBIP39Seed(Blob32::from_slice(wallet.keys.seed.as_ref())?);

    Ok(Some(seed_material))
}
