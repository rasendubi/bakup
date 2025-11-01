use bytes::Bytes;

pub trait ContentAddressableStorage {
    type Hash: Clone + Eq + Ord + std::hash::Hash;
    type Error: std::error::Error;

    // Return a list of all known stored hashes.
    fn list(&self) -> impl Iterator<Item = Result<Self::Hash, Self::Error>>;

    // Get bytes by their content hash.
    fn get(&self, hash: Self::Hash) -> Result<Option<Bytes>, Self::Error>;

    // Store bytes and return their content hash. This may be a no-op if bytes are already stored.
    fn store(&self, bytes: Bytes) -> Result<Self::Hash, Self::Error>;
}
