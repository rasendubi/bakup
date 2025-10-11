use std::io::{self, ErrorKind, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct IndexEntry<const HASH_SIZE: usize> {
    pub hash: [u8; HASH_SIZE],
    pub offset: u32,
}

#[derive(Debug)]
pub struct FinalizedPack<W, const HASH_SIZE: usize> {
    pub writer: W,
    pub index: Vec<IndexEntry<HASH_SIZE>>,
}

pub struct PackWriter<W, const HASH_SIZE: usize> {
    writer: W,
    written_size: usize,
    index: Vec<IndexEntry<HASH_SIZE>>,
}

impl<W: Write, const HASH_SIZE: usize> PackWriter<W, HASH_SIZE> {
    pub fn new(writer: W) -> PackWriter<W, HASH_SIZE> {
        PackWriter {
            writer,
            written_size: 0,
            index: Vec::new(),
        }
    }

    pub fn write(&mut self, hash: [u8; HASH_SIZE], data: &[u8]) -> io::Result<()> {
        let data_size = u32::try_from(data.len()).map_err(|_| ErrorKind::InvalidInput)?;
        let offset = u32::try_from(self.written_size).map_err(|_| ErrorKind::FileTooLarge)?;

        // header
        self.writer.write_all(&hash)?;
        self.writer.write_all(&data_size.to_le_bytes())?;
        // data
        self.writer.write_all(data)?;

        self.written_size += HASH_SIZE + size_of::<u32>() + data.len();

        self.index.push(IndexEntry { hash, offset });

        Ok(())
    }

    pub fn size(&self) -> usize {
        self.written_size + self.index_size() + size_of::<u32>()
    }

    /// How much adding the item would contribute to pack size.
    pub const fn item_size(data_size: usize) -> usize {
        let header = /* hash: */ HASH_SIZE + /* size: */ size_of::<u32>();
        let index_overhead = /* hash: */ HASH_SIZE + /* offset: */ size_of::<u32>();
        header + data_size + index_overhead
    }

    fn index_size(&self) -> usize {
        // Index format is: (N-bit hash, u32 offset)
        self.index.len() * (HASH_SIZE + size_of::<u32>())
    }

    /// Finalize the pack file by writing its index at the end of the file.
    ///
    /// Returns the writer and the index.
    pub fn finalize(mut self) -> io::Result<FinalizedPack<W, HASH_SIZE>> {
        self.finalize_inner()?;
        Ok(FinalizedPack {
            writer: self.writer,
            index: self.index,
        })
    }

    fn finalize_inner(&mut self) -> io::Result<()> {
        self.index.sort_unstable_by(|a, b| a.hash.cmp(&b.hash));

        for idx in &self.index {
            self.writer.write_all(&idx.hash)?;
            self.writer.write_all(&idx.offset.to_le_bytes())?;
        }

        self.writer.write_all(
            &u32::try_from(self.index_size())
                .expect("given we control pack data to be below 4GiB, index size shouldn't exceed that either")
                .to_le_bytes())?;

        self.writer.flush()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashSet;

    use super::*;

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn test_final_size(blobs: Vec<Vec<u8>>) {
            let mut output = Vec::new();

            let mut pack_writer = PackWriter::new(&mut output);
            for blob in &blobs {
                let hash: [u8; 32] = blake3::hash(blob).into();
                pack_writer.write(hash, blob).unwrap();
            }

            let estimated_size = pack_writer.size();
            let _ = pack_writer.finalize().unwrap();

            prop_assert_eq!(estimated_size, output.len());
        }
    }

    proptest! {
        #[test]
        fn test_index(blobs: Vec<Vec<u8>>) {
            let mut output = Vec::new();

            let mut pack_writer = PackWriter::new(&mut output);

            let mut input_hashes = HashSet::new();
            for blob in &blobs {
                let hash: [u8; 32] = blake3::hash(blob).into();
                input_hashes.insert(hash);
                pack_writer.write(hash, blob).unwrap();
            }

            let pack = pack_writer.finalize().unwrap();

            prop_assert_eq!(input_hashes, pack.index.into_iter().map(|it| it.hash).collect());
        }
    }

    proptest! {
        #[test]
        fn test_index_is_sorted(blobs: Vec<Vec<u8>>) {
            let mut output = Vec::new();

            let mut pack_writer = PackWriter::new(&mut output);

            for blob in &blobs {
                let hash: [u8; 32] = blake3::hash(blob).into();
                pack_writer.write(hash, blob).unwrap();
            }

            let pack = pack_writer.finalize().unwrap();

            prop_assert!(pack.index.is_sorted_by(|a,b| a.hash <= b.hash));
        }
    }
}
