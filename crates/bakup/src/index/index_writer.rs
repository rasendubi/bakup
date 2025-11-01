use std::io::{self, Write};

use rayon::slice::ParallelSliceMut;

use crate::pack;

pub struct IndexEntry<const HASH_SIZE: usize> {
    hash: [u8; HASH_SIZE],
    pack_id: [u8; HASH_SIZE],
    offset: u32,
}

pub struct IndexWriter<const HASH_SIZE: usize> {
    index: Vec<IndexEntry<HASH_SIZE>>,
}

impl<const HASH_SIZE: usize> IndexEntry<HASH_SIZE> {
    const fn size() -> usize {
        HASH_SIZE + HASH_SIZE + size_of::<u32>()
    }
}

impl<const HASH_SIZE: usize> IndexWriter<HASH_SIZE> {
    pub fn new() -> Self {
        IndexWriter { index: Vec::new() }
    }

    pub fn size(&self) -> usize {
        self.index.len() * IndexEntry::<HASH_SIZE>::size()
    }

    pub fn extend_from_pack(
        &mut self,
        pack_id: [u8; HASH_SIZE],
        indices: Vec<pack::IndexEntry<HASH_SIZE>>,
    ) {
        self.index.extend(indices.into_iter().map(|it| IndexEntry {
            hash: it.hash,
            pack_id,
            offset: it.offset,
        }));
    }

    pub fn write<W: Write>(&mut self, w: &mut W) -> io::Result<()> {
        self.index.par_sort_by(|a, b| a.hash.cmp(&b.hash));

        for entry in &self.index {
            w.write_all(&entry.hash)?;
            w.write_all(&entry.pack_id)?;
            w.write_all(&entry.offset.to_le_bytes())?;
        }

        w.flush()
    }
}
