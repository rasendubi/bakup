pub(crate) const BAKPAK_MAGIC: [u8; 4] = *b"bak0";

pub(crate) const SENDER_ENCRYPTION_KEY_CTX: &str =
    "bakpak.rasen.dev 2025-11-01 sender encryption key";

pub(crate) const HEADER_MAC_KEY_CTX: &str = "bakpak.rasen.dev 2025-11-01 header mac key";

pub(crate) const PAYLOAD_ENCRYPTION_KEY_CTX: &str =
    "bakpak.rasen.dev 2025-11-01 payload encryption";

pub(crate) const RECIPIENT_MAC_KEY_CTX: &str = "bakpak.rasen.dev 2025-11-01 recipient mac key";

pub(crate) const WRAP_KEY_CTX: &str = "bakpak.rasen.dev 2025-11-01 wrap key";
