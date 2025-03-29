#[allow(dead_code)]
#[derive(Clone, Debug)]
pub struct LightClientConfig<P> {
    pub chain_name: String,
    pub sapling_activation_height: u64,
    pub anchor_offset: u32,
    pub monitor_mempool: bool,
    pub data_dir: Option<String>,
    pub params: P,
}

impl<P: zcash_protocol::consensus::NetworkConstants> LightClientConfig<P> {
    // Create an unconnected (to any server) config to test for local wallet etc...
    pub fn create_unconnected(params: P, dir: Option<String>) -> LightClientConfig<P> {
        LightClientConfig {
            chain_name: params.hrp_sapling_payment_address().to_string(),
            sapling_activation_height: 1,
            monitor_mempool: false,
            anchor_offset: 1,
            data_dir: dir,
            params: params.clone(),
        }
    }

    #[allow(dead_code)]
    pub fn hrp_sapling_address(&self) -> &str {
        self.params.hrp_sapling_payment_address()
    }

    #[allow(dead_code)]
    pub fn hrp_sapling_private_key(&self) -> &str {
        self.params.hrp_sapling_extended_spending_key()
    }

    #[allow(dead_code)]
    pub fn hrp_sapling_viewing_key(&self) -> &str {
        self.params.hrp_sapling_extended_full_viewing_key()
    }

    #[allow(dead_code)]
    pub fn base58_pubkey_address(&self) -> [u8; 2] {
        self.params.b58_pubkey_address_prefix()
    }

    #[allow(dead_code)]
    pub fn base58_script_address(&self) -> [u8; 2] {
        self.params.b58_script_address_prefix()
    }

    pub fn get_coin_type(&self) -> u32 {
        self.params.coin_type()
    }
}
