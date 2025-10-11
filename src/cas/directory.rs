use std::{io, marker::PhantomData};

use bytes::Bytes;
use camino::Utf8PathBuf;
use digest::{Digest, Output};
use itertools::Itertools;
use tracing::{debug, instrument};

use super::ContentAddressableStorage;

pub struct DirectoryCas<H> {
    base_path: Utf8PathBuf,
    _digest: PhantomData<H>,
}

impl<H: Digest> DirectoryCas<H> {
    pub fn new(base_path: impl Into<Utf8PathBuf>) -> Self {
        DirectoryCas {
            base_path: base_path.into(),
            _digest: PhantomData,
        }
    }

    fn path_for(&self, hash: &Output<H>) -> Utf8PathBuf {
        self.base_path.join(const_hex::encode(hash))
    }
}

impl<H: Digest> ContentAddressableStorage for DirectoryCas<H> {
    type Error = io::Error;
    type Hash = Output<H>;

    fn list(&self) -> impl Iterator<Item = Result<Self::Hash, Self::Error>> {
        std::iter::once(self.base_path.read_dir_utf8())
            .flatten_ok()
            .flatten_ok()
            .filter_map_ok(|entry| {
                let mut hash = Self::Hash::default();
                const_hex::decode_to_slice(entry.file_name(), &mut hash).ok()?;
                Some(hash)
            })
    }

    fn get(&self, hash: Self::Hash) -> Result<Option<bytes::Bytes>, Self::Error> {
        match std::fs::read(self.path_for(&hash)) {
            Ok(buf) => Ok(Some(Bytes::from(buf))),
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    #[instrument(skip_all)]
    fn store(&self, bytes: bytes::Bytes) -> Result<Self::Hash, Self::Error> {
        let hash = H::digest(&bytes);
        let path = self.path_for(&hash);
        if path.exists() {
            debug!("skipping saving {path:?}: already exists");
        } else {
            debug!("saving new content at {path:?}");
            std::fs::write(self.path_for(&hash), &bytes)?;
        }
        Ok(hash)
    }
}
