use std::io::Write;

use chacha20poly1305::{aead::Aead, ChaCha20Poly1305, KeyInit};
use rand_core::{CryptoRng, RngCore};
use x25519_dalek::ReusableSecret;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::StreamWriter;

const BAKPAK_MAGIC: [u8; 4] = *b"bak0";
const SENDER_ENCRYPTION_KEY_CTX: &str = "bakpak.rasen.dev 2025-11-01 sender encryption key";
const HEADER_MAC_KEY_CTX: &str = "bakpak.rasen.dev 2025-11-01 header mac key";
const PAYLOAD_ENCRYPTION_KEY_CTX: &str = "bakpak.rasen.dev 2025-11-01 payload encryption";
const RECIPIENT_MAC_KEY_CTX: &str = "bakpak.rasen.dev 2025-11-01 recipient mac key";
const WRAP_KEY_CTX: &str = "bakpak.rasen.dev 2025-11-01 wrap key";

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

pub(crate) type EncryptionKey = chacha20poly1305::Key;

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
        if recipients.len() > u16::MAX as usize {
            return Err(crate::Error::TooManyRecipients);
        }

        let mut file_key = Zeroizing::new([0u8; 32]);
        csprng.fill_bytes(file_key.as_mut());

        let sender_encryption_key = Zeroizing::new(EncryptionKey::from(blake3::derive_key(
            SENDER_ENCRYPTION_KEY_CTX,
            file_key.as_ref(),
        )));
        let header_mac_key =
            Zeroizing::new(blake3::derive_key(HEADER_MAC_KEY_CTX, file_key.as_ref()));
        let payload_encryption_key = Zeroizing::new(EncryptionKey::from(blake3::derive_key(
            PAYLOAD_ENCRYPTION_KEY_CTX,
            file_key.as_ref(),
        )));

        let ephemeral_key = Zeroizing::new(ReusableSecret::random_from_rng(&mut csprng));

        let header_size = /* magic: */ 4 +
                /* ephemeral share: */ 32 +
                /* sender_id: */ 32 + 16 +
                /* recipients section: */ 2 + recipients.len() * (32 + 32+16) +
                /* header mac: */ 32;
        let mut header = Vec::with_capacity(header_size);
        header.extend_from_slice(&BAKPAK_MAGIC);
        header.extend_from_slice(x25519_dalek::PublicKey::from(&*ephemeral_key).as_bytes());

        let sender_id = {
            ChaCha20Poly1305::new(&sender_encryption_key).encrypt(
                &Default::default(),
                sender.verifying_key().as_bytes().as_slice(),
            )?
        };
        header.extend_from_slice(&sender_id);

        header.extend_from_slice(&(recipients.len() as u16).to_le_bytes());
        for r in recipients {
            let shared_secret = Zeroizing::new(ephemeral_key.diffie_hellman(&r));
            let recipient_mac_key = Zeroizing::new(blake3::derive_key(
                RECIPIENT_MAC_KEY_CTX,
                shared_secret.as_bytes(),
            ));
            let wrap_key = Zeroizing::new(EncryptionKey::from(blake3::derive_key(
                WRAP_KEY_CTX,
                shared_secret.as_bytes(),
            )));

            let recipient_id = blake3::keyed_hash(&recipient_mac_key, r.as_bytes());
            let wrapped_key = ChaCha20Poly1305::new(&*wrap_key)
                .encrypt(&Default::default(), file_key.as_slice())?;

            header.extend_from_slice(recipient_id.as_bytes());
            header.extend_from_slice(&wrapped_key);
        }

        let header_mac = blake3::keyed_hash(&*header_mac_key, &header);
        header.extend_from_slice(header_mac.as_bytes());

        debug_assert_eq!(header.len(), header_size);

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
