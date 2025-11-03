use std::io::Write;

use aead::{AeadInPlace, KeyInit};
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::ReusableSecret;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    chacha20_blake3::{self, ChaCha20Blake3},
    common, StreamWriter,
};

/// Encryptor for creating bakpak files.
pub struct Encryptor {
    header: Vec<u8>,
    signing_key: ed25519_dalek::SigningKey,
    payload_encryption_key: EncryptionKey,
}

impl Drop for Encryptor {
    fn drop(&mut self) {
        self.payload_encryption_key.zeroize();
    }
}

impl ZeroizeOnDrop for Encryptor {}

type Recipient = x25519_dalek::PublicKey;

pub(crate) type EncryptionKey = chacha20_blake3::Key;

impl Encryptor {
    pub fn new(
        sender: &ed25519_dalek::SigningKey,
        recipients: &[Recipient],
    ) -> Result<Encryptor, crate::Error> {
        Encryptor::with_random(rand_core::OsRng, sender, recipients)
    }

    pub fn with_random(
        mut csprng: impl CryptoRng + RngCore,
        sender: &ed25519_dalek::SigningKey,
        recipients: &[Recipient],
    ) -> Result<Encryptor, crate::Error> {
        if recipients.len() > u32::MAX as usize {
            return Err(crate::Error::TooManyRecipients);
        }

        let mut file_key = [0u8; 32];
        csprng.fill_bytes(file_key.as_mut());

        let sender_encryption_key = Zeroizing::new(EncryptionKey::from(blake3::derive_key(
            common::SENDER_ENCRYPTION_KEY_CTX,
            file_key.as_ref(),
        )));
        let header_mac_key = Zeroizing::new(blake3::derive_key(
            common::HEADER_MAC_KEY_CTX,
            file_key.as_ref(),
        ));
        let payload_encryption_key = Zeroizing::new(EncryptionKey::from(blake3::derive_key(
            common::PAYLOAD_ENCRYPTION_KEY_CTX,
            file_key.as_ref(),
        )));

        file_key.zeroize();

        let ephemeral_key = Zeroizing::new(ReusableSecret::random_from_rng(&mut csprng));

        let header_size = /* magic: */ 4 +
            /* recipient count: */ 4 +
            /* ephemeral share: */ 32 +
            /* recipients section: */ recipients.len() * (32 + 32+32) +
            /* sender_id: */ 32 + 32 +
            /* header mac: */ 32;
        let mut header = Vec::with_capacity(header_size);
        header.extend_from_slice(&common::BAKPAK_MAGIC);

        header.extend_from_slice(&(recipients.len() as u32).to_le_bytes());
        header.extend_from_slice(x25519_dalek::PublicKey::from(&*ephemeral_key).as_bytes());

        for r in recipients {
            let mut shared_secret = ephemeral_key.diffie_hellman(&r);
            let mut recipient_mac_key =
                blake3::derive_key(common::RECIPIENT_MAC_KEY_CTX, shared_secret.as_bytes());
            let recipient_id = blake3::keyed_hash(&recipient_mac_key, r.as_bytes());
            recipient_mac_key.zeroize();

            let mut wrap_key = blake3::derive_key(common::WRAP_KEY_CTX, shared_secret.as_bytes());
            shared_secret.zeroize();
            let cipher = ChaCha20Blake3::new((&wrap_key).into());
            wrap_key.zeroize();

            let mut wrapped_key = file_key.clone();
            let tag =
                cipher.encrypt_in_place_detached(&Default::default(), &[], &mut wrapped_key)?;

            header.extend_from_slice(recipient_id.as_bytes());
            header.extend_from_slice(&wrapped_key);
            header.extend_from_slice(&tag);
        }

        let mut sender_id = sender.verifying_key().to_bytes();
        let sender_id_tag = ChaCha20Blake3::new(&sender_encryption_key).encrypt_in_place_detached(
            &Default::default(),
            &[],
            &mut sender_id,
        )?;
        header.extend_from_slice(&sender_id);
        header.extend_from_slice(&sender_id_tag);

        let header_mac = blake3::keyed_hash(&*header_mac_key, &header);
        header.extend_from_slice(header_mac.as_bytes());

        debug_assert_eq!(header.len(), header_size, "header size miscalculation");

        Ok(Encryptor {
            header,
            signing_key: sender.clone(),
            payload_encryption_key: *payload_encryption_key,
        })
    }

    /// Creates a wrapper around the `writer` that will wrap its input into bakpak format.
    ///
    /// Returns error if the underlying writer errored out while writing the header.
    ///
    /// You must call `StreamWriter::finish()` to finalize bakpak stream. Failing to do that will
    /// result in truncated file that will fail to decrypt.
    pub fn wrap_output<W: Write>(self, writer: W) -> Result<StreamWriter<W>, std::io::Error> {
        StreamWriter::wrap_writer(
            writer,
            &self.header,
            &self.signing_key,
            &self.payload_encryption_key,
        )
    }
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;

    #[test]
    fn test_encryptor_constructor() {
        let sender = SigningKey::generate(&mut rand_core::OsRng);
        let recipients = vec![x25519_dalek::PublicKey::from(
            &x25519_dalek::StaticSecret::random_from_rng(rand_core::OsRng),
        )];
        let encryptor = Encryptor::new(&sender, &recipients);
        assert!(encryptor.is_ok());
    }
}
