use std::io::{self, BufRead};

use super::chunker_state::{ChunkerConfig, ChunkerState};

pub struct StreamChunker<'a, R> {
    reader: R,
    /// `true` if we reached end of stream or an error.
    ended: bool,
    state: ChunkerState<'a>,
}

impl<'a, R: BufRead> StreamChunker<'a, R> {
    pub fn new(config: &'a ChunkerConfig<'a>, reader: R) -> Self {
        StreamChunker {
            reader,
            ended: false,
            state: ChunkerState::new(config),
        }
    }
}

impl<'a, R: BufRead> Iterator for StreamChunker<'a, R> {
    type Item = io::Result<Vec<u8>>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.ended {
            return None;
        }

        let mut data = Vec::new();

        loop {
            let buf = match self.reader.fill_buf() {
                Ok([]) => {
                    // reached end of input
                    self.ended = true;
                    return if data.is_empty() {
                        None
                    } else {
                        Some(Ok(data))
                    };
                }
                Ok(buf) => buf,
                Err(err) => {
                    self.ended = true;
                    return Some(Err(err));
                }
            };

            let maybe_chunk_boundary = self.state.update(buf);
            let consumed = maybe_chunk_boundary.unwrap_or(buf.len());
            data.extend_from_slice(&buf[..consumed]);
            self.reader.consume(consumed);

            if maybe_chunk_boundary.is_some() {
                return Some(Ok(data));
            }
            // else loop read next chunk
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::chunking::aes_gear::AesGearConfig;

    use super::*;
    use aes::cipher::KeyInit;
    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_chunk_sizes(bytes in prop::collection::vec(any::<u8>(), 0..=4096)) {
            const MIN_SIZE: usize = 128;
            const AVG_SIZE: usize = 256;
            const MAX_SIZE: usize = 1024;

            let aes = aes::Aes128Enc::new_from_slice(&[0u8; 16]).unwrap();
            let gear_config = AesGearConfig::new(aes);
            let chunker_config = ChunkerConfig::new(gear_config, MIN_SIZE, AVG_SIZE, MAX_SIZE, 3);
            let stream_chunker = StreamChunker::new(&chunker_config, bytes.as_ref());

            let chunks = stream_chunker.collect::<Result<Vec<_>, _>>().unwrap();

            if chunks.len() >= 1 {
                for chunk in &chunks[..chunks.len() - 1] {
                    // All but last chunk should satisfy the min_size..=max_size condiition.
                    prop_assert!((MIN_SIZE..=MAX_SIZE).contains(&chunk.len()));
                }
                prop_assert!((1..=MAX_SIZE).contains(&chunks[chunks.len()-1].len()));
            }

            prop_assert_eq!(chunks.concat(), bytes, "Chunks should reconstruct input bytes");
        }
    }
}
