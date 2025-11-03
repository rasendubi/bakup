use std::io::Write;

use aead::{AeadCore, AeadInPlace, KeyInit};
use arrayvec::ArrayVec;
use ed25519_dalek::ed25519::signature::Signer;
use generic_array::{typenum::Unsigned, GenericArray};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{chacha20_blake3::ChaCha20Blake3, encryptor::EncryptionKey};

const SIGNATURE_DOMAIN_LEN: usize = 15;
const SIGNATURE_DOMAIN: &[u8; SIGNATURE_DOMAIN_LEN] = b"bakpak segment\0";

const SEGMENT_SIZE: usize = 64 * 1024;

type Segment = Box<
    ArrayVec<
        u8,
        {
            SEGMENT_SIZE
                + ed25519_dalek::Signature::BYTE_SIZE
                + <ChaCha20Blake3 as AeadCore>::TagSize::USIZE
        },
    >,
>;

struct StreamState {
    signing_key: ed25519_dalek::SigningKey,
    encryption_key: EncryptionKey,
    segment_count: usize,
    segment: Segment,
}

impl Drop for StreamState {
    fn drop(&mut self) {
        &self.signing_key as &dyn ZeroizeOnDrop;
        self.encryption_key.zeroize();
        self.segment.zeroize();
    }
}

impl ZeroizeOnDrop for StreamState {}

impl StreamState {
    pub fn new(
        signing_key: &ed25519_dalek::SigningKey,
        encryption_key: &EncryptionKey,
    ) -> StreamState {
        StreamState {
            signing_key: signing_key.clone(),
            encryption_key: *encryption_key,
            segment_count: 0,
            segment: Box::new(ArrayVec::new()),
        }
    }

    /// Try writing `buf` into the stream.
    ///
    /// Returns number of bytes consumed and potentially a completed segment.
    pub fn write(&mut self, buf: &[u8]) -> Result<(usize, Option<Segment>), crate::Error> {
        let len = usize::min(buf.len(), self.segment_capacity());
        let buf = &buf[..len];
        self.segment
            .try_extend_from_slice(buf)
            .expect("should have enough capacity");

        let segment = if self.segment_capacity() == 0 {
            Some(self.signcrypt_segment(false)?)
        } else {
            None
        };

        Ok((len, segment))
    }

    pub fn finish(mut self) -> Result<Segment, crate::Error> {
        self.signcrypt_segment(true)
    }

    fn pad_segment(segment: &mut Segment) {
        let to_pad = SEGMENT_SIZE - segment.len();
        debug_assert!(to_pad > 0);
        debug_assert!(to_pad <= u16::MAX as usize);

        if let Ok(byte) = u8::try_from(to_pad) {
            segment.extend(std::iter::repeat_n(0, to_pad - 1));
            segment.push(byte);
        } else {
            segment.extend(std::iter::repeat_n(0, to_pad - 3));
            segment
                .try_extend_from_slice(&(to_pad as u16).to_le_bytes())
                .unwrap();
            segment.push(0);
        }
    }

    fn signcrypt_segment(&mut self, last_segment: bool) -> Result<Segment, crate::Error> {
        if last_segment {
            debug_assert!(
                self.segment_capacity() > 0,
                "segment should have at least one byte of capacity"
            );

            Self::pad_segment(&mut self.segment);
        }

        debug_assert_eq!(self.segment.len(), SEGMENT_SIZE);

        let nonce = Self::nonce(self.segment_count as u64, last_segment);

        // 15 bytes signature domain, 32 bytes key, 12 bytes nonce, 32 bytes content hash
        let mut signature_base =
            Zeroizing::new(ArrayVec::<u8, { SIGNATURE_DOMAIN_LEN + 32 + 12 + 32 }>::new());
        signature_base
            .try_extend_from_slice(SIGNATURE_DOMAIN)
            .unwrap();
        signature_base
            .try_extend_from_slice(&self.encryption_key)
            .unwrap();
        signature_base.try_extend_from_slice(&nonce).unwrap();
        signature_base
            .try_extend_from_slice(blake3::hash(&self.segment).as_bytes())
            .unwrap();
        debug_assert_eq!(signature_base.remaining_capacity(), 0);

        let signature = self.signing_key.sign(&signature_base);
        self.segment
            .try_extend_from_slice(&signature.to_bytes())
            .unwrap();

        let cipher = ChaCha20Blake3::new(&self.encryption_key);
        &cipher as &dyn ZeroizeOnDrop;

        let tag = cipher.encrypt_in_place_detached(
            GenericArray::from_slice(&nonce),
            &[],
            &mut self.segment,
        )?;

        self.segment.try_extend_from_slice(&tag).unwrap();

        self.segment_count += 1;
        Ok(std::mem::take(&mut self.segment))
    }

    fn segment_capacity(&self) -> usize {
        SEGMENT_SIZE - self.segment.len()
    }

    fn nonce(counter: u64, last_segment: bool) -> [u8; 12] {
        debug_assert!(counter <= (u64::MAX >> 1));

        let nonce = counter | (last_segment as u64) << 63;

        let mut result = [0u8; 12];
        let (_, right) = result.split_at_mut(4);
        right.copy_from_slice(&nonce.to_le_bytes());

        result
    }
}

pub struct StreamWriter<W> {
    writer: W,
    state: StreamState,
    pending_segment: Option<(Segment, usize)>,
}

impl<W> StreamWriter<W> {
    fn new(
        writer: W,
        signing_key: &ed25519_dalek::SigningKey,
        encryption_key: &EncryptionKey,
    ) -> Self {
        StreamWriter {
            writer,
            state: StreamState::new(signing_key, encryption_key),
            pending_segment: None,
        }
    }
}

impl<W: Write> StreamWriter<W> {
    pub(crate) fn wrap_writer(
        mut writer: W,
        header: &[u8],
        signing_key: &ed25519_dalek::SigningKey,
        payload_encryption_key: &EncryptionKey,
    ) -> Result<Self, std::io::Error> {
        writer.write_all(header)?;
        Ok(Self::new(writer, signing_key, payload_encryption_key))
    }

    pub fn finish(mut self) -> Result<W, crate::Error> {
        let segment = self.state.finish()?;
        self.writer.write_all(&segment)?;
        Ok(self.writer)
    }

    fn write_pending(&mut self) -> std::io::Result<()> {
        while let Some((segment, pos)) = &mut self.pending_segment {
            let written = self.writer.write(&segment[*pos..])?;
            if written == 0 {
                return Err(std::io::Error::from(std::io::ErrorKind::WriteZero));
            }

            *pos += written;
            if *pos == segment.len() {
                self.pending_segment.take();
            }
        }

        Ok(())
    }
}

impl<W: Write> Write for StreamWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Returning error from Write::write() is interpreted as if no bytes were consumed and the
        // caller is allowed to retry writing the same buffer. In case we consume some bytes from
        // buf but then writing to the underlying writer fails, we store pending segment in
        // self.pending_segment and retry writing it the next time StreamWriter::write() is called.

        // We need to deal with pending segment before we can accept more input.
        self.write_pending()?;

        let (consumed, segment) = self.state.write(buf)?;
        debug_assert!(consumed > 0);

        if let Some(segment) = segment {
            self.pending_segment = Some((segment, 0));
            // Ignoring error, so we can return the number of bytes consumed from buf.
            let _ = self.write_pending();
        }

        Ok(consumed)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.write_pending()?;
        self.writer.flush()
    }
}
