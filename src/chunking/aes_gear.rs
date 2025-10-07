use aes::{
    cipher::{generic_array::GenericArray, BlockEncrypt},
    Aes128Enc,
};

use crate::chunking::aes_gear_table::DEFAULT_TABLE;

pub struct AesGearConfig<'a> {
    table: &'a [u64; 256],
    aes: Aes128Enc,
}

impl AesGearConfig<'static> {
    pub fn new(aes: Aes128Enc) -> Self {
        AesGearConfig {
            table: &DEFAULT_TABLE,
            aes,
        }
    }
}

pub struct AesGearHash<'a> {
    config: &'a AesGearConfig<'a>,
    state: u64,
}

impl<'a> AesGearHash<'a> {
    pub fn new(config: &'a AesGearConfig<'a>) -> Self {
        Self { config, state: 0 }
    }

    /// Consume one byte of input, updating the internal state.
    #[inline(always)]
    pub fn update(&mut self, byte: u8) {
        self.state = (self.state << 1).wrapping_add(self.config.table[byte as usize]);
    }

    /// Get current hash value.
    #[inline]
    pub fn hash(&self) -> u64 {
        // This is doing a reduced AES-128 on gear hash value. AES is used as a PRF primitive.
        let mut block = [0u8; 16];
        block[0..8].copy_from_slice(&self.state.to_le_bytes());
        let mut block = GenericArray::from(block);
        self.config.aes.encrypt_block(&mut block);
        u64::from_le_bytes(
            block[0..8]
                .try_into()
                .expect("8 bytes are convertible to u64"),
        )
    }
}
