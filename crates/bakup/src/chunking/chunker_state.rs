use crate::chunking::aes_gear::AesGearConfig;

use super::aes_gear::AesGearHash;

pub struct ChunkerConfig<'a> {
    gear_config: AesGearConfig<'a>,
    min_size: usize,
    avg_size: usize,
    max_size: usize,
    before_avg_size_mask: u64,
    after_avg_size_mask: u64,
}

impl<'a> ChunkerConfig<'a> {
    pub fn new(
        gear_config: AesGearConfig<'a>,
        min_size: usize,
        avg_size: usize,
        max_size: usize,
        normalization_bits: u32,
    ) -> Self {
        assert!(
            avg_size & (avg_size - 1) == 0,
            "avg_size should be a power of 2"
        );
        let avg_base = avg_size.ilog2();
        assert!(avg_base > normalization_bits);
        let before_avg_size_mask = (2 << (avg_base + normalization_bits) as u64) - 1;
        let after_avg_size_mask = (2 << (avg_base - normalization_bits) as u64) - 1;
        ChunkerConfig {
            gear_config,
            min_size,
            avg_size,
            max_size,
            before_avg_size_mask,
            after_avg_size_mask,
        }
    }
}

pub struct ChunkerState<'a> {
    config: &'a ChunkerConfig<'a>,
    gear: AesGearHash<'a>,
    /// Size of the currently running chunk.
    size: usize,
}

impl<'a> ChunkerState<'a> {
    pub fn new(config: &'a ChunkerConfig) -> ChunkerState<'a> {
        ChunkerState {
            config,
            gear: AesGearHash::new(&config.gear_config),
            size: 0,
        }
    }

    /// Process `buf` and return `Some(consumed)` if chunk boundary is found (where `consumed` is
    /// offset into `buf`). If no chunk boundary is found, returns `None`, which means that the
    /// whole `buf` was consumed.
    pub fn update(&mut self, buf: &[u8]) -> Option<usize> {
        // Offset into `buf` where we're reading now.
        let mut i = 0;

        // Skip hashing the first min_size-64 bytes as their hash does not influence chunking
        // decision.
        if self.size < self.config.min_size - 64 {
            let to_skip = self.config.min_size - 64 - self.size;
            if to_skip >= buf.len() {
                // consume whole buf
                self.size += buf.len();
                return None;
            }

            self.size += to_skip;
            i += to_skip;
        }

        // Hash 63 bytes before min_size without checking for boundary.
        while self.size < self.config.min_size - 1 {
            // Consume without checking boundary.
            if i >= buf.len() {
                return None;
            }

            self.gear.update(buf[i]);
            self.size += 1;
            i += 1;
        }

        // Starting from min_size up to expected avg_size, hash and check for boundaries using more
        // strict mask, to make it less likely that we produce small chunks (leaning towards avg
        // size).
        while self.size < self.config.avg_size {
            if i >= buf.len() {
                return None;
            }

            self.gear.update(buf[i]);
            self.size += 1;
            i += 1;
            if self.gear.hash() & self.config.before_avg_size_mask == 0 {
                self.size = 0;
                return Some(i);
            }
        }

        // After avg size, compare against relaxed boundary mask, so it's more likely that we chunk
        // now (leaning towards avg size).
        while self.size < self.config.max_size {
            if i >= buf.len() {
                return None;
            }

            self.gear.update(buf[i]);
            self.size += 1;
            i += 1;
            if self.gear.hash() & self.config.after_avg_size_mask == 0 {
                self.size = 0;
                return Some(i);
            }
        }

        // reached max size
        self.size = 0;
        Some(i)
    }
}
