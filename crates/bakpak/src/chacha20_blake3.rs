use std::marker::PhantomData;

use aead::{
    consts::{U0, U12, U32},
    generic_array::GenericArray,
    AeadCore, AeadInPlace, KeyInit, KeySizeUser,
};
use blake3::Hash;
use chacha20::{
    cipher::{KeyIvInit, StreamCipher},
    ChaCha20,
};
use generic_array::ArrayLength;
use zeroize::{Zeroize, ZeroizeOnDrop};

pub type Key = GenericArray<u8, U32>;

pub type Nonce = GenericArray<u8, U12>;

pub type Tag = GenericArray<u8, U32>;

/// Size of a ChaCha20 block in bytes
const BLOCK_SIZE: usize = 64;

/// Maximum number of blocks that can be encrypted with ChaCha20 before the
/// counter overflows.
const MAX_BLOCKS: usize = core::u32::MAX as usize;

pub type ChaCha20Blake3 = ChaChaBlake3<ChaCha20, U12>;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ChaChaBlake3<C, N: ArrayLength<u8> = U12> {
    key: Key,
    stream_cipher: PhantomData<C>,
    nonce_size: PhantomData<N>,
}

trait KeyDerivationCtx {
    const KEY_DERIVATION_CTX: &str;
}
impl KeyDerivationCtx for ChaCha20 {
    const KEY_DERIVATION_CTX: &str = "ChaCha20.Encrypt()";
}

impl<C, N> KeySizeUser for ChaChaBlake3<C, N>
where
    N: ArrayLength<u8>,
{
    type KeySize = U32;
}

impl<C, N> KeyInit for ChaChaBlake3<C, N>
where
    N: ArrayLength<u8>,
{
    fn new(key: &Key) -> Self {
        ChaChaBlake3 {
            key: *key,
            stream_cipher: PhantomData,
            nonce_size: PhantomData,
        }
    }
}

impl<C, N> AeadCore for ChaChaBlake3<C, N>
where
    N: ArrayLength<u8>,
{
    type NonceSize = N;
    type TagSize = U32;
    type CiphertextOverhead = U0;
}

impl<C, N> AeadInPlace for ChaChaBlake3<C, N>
where
    C: KeyIvInit<KeySize = U32, IvSize = N> + StreamCipher + KeyDerivationCtx,
    N: ArrayLength<u8>,
{
    fn encrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
    ) -> aead::Result<Tag> {
        if buffer.len() / BLOCK_SIZE >= MAX_BLOCKS {
            return Err(aead::Error);
        }

        let mut encryption_key = blake3::derive_key(C::KEY_DERIVATION_CTX, &self.key);
        let mut cipher = C::new_from_slices(&encryption_key, nonce).unwrap();
        encryption_key.zeroize();

        cipher.apply_keystream(buffer);

        let tag = self.compute_tag(nonce, associated_data, buffer)?;
        let tag = GenericArray::from(<[u8; 32]>::from(tag));

        Ok(tag)
    }

    fn decrypt_in_place_detached(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        buffer: &mut [u8],
        tag: &Tag,
    ) -> aead::Result<()> {
        if buffer.len() / BLOCK_SIZE >= MAX_BLOCKS {
            return Err(aead::Error);
        }

        let computed_tag = self.compute_tag(nonce, associated_data, buffer)?;
        if computed_tag == **tag {
            let mut encryption_key = blake3::derive_key(C::KEY_DERIVATION_CTX, &self.key);
            let mut cipher = C::new_from_slices(&encryption_key, nonce).unwrap();
            encryption_key.zeroize();

            cipher.apply_keystream(buffer);
            Ok(())
        } else {
            Err(aead::Error)
        }
    }
}

impl<C, N> ChaChaBlake3<C, N>
where
    N: ArrayLength<u8>,
{
    fn compute_tag(
        &self,
        nonce: &aead::Nonce<Self>,
        associated_data: &[u8],
        ciphertext: &[u8],
    ) -> aead::Result<Hash> {
        let mut mac_key = blake3::derive_key("BLAKE3-256.KeyedHash()", &self.key);

        let mut mac = blake3::Hasher::new_keyed(&mac_key);
        mac_key.zeroize();

        mac.update(nonce);
        mac.update(associated_data);
        mac.update(ciphertext);
        mac.update(
            &u64::try_from(associated_data.len())
                .map_err(|_| aead::Error)?
                .to_le_bytes(),
        );
        mac.update(
            &u64::try_from(ciphertext.len())
                .map_err(|_| aead::Error)?
                .to_le_bytes(),
        );

        Ok(mac.finalize())
    }
}
