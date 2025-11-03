#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum Error {
    #[error("too many recipients")]
    TooManyRecipients,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error("encryption error")]
    EncryptionError,
}

impl From<Error> for std::io::Error {
    fn from(value: Error) -> Self {
        match value {
            Error::Io(err) => err,
            err => std::io::Error::other(err),
        }
    }
}

impl From<aead::Error> for Error {
    fn from(_: aead::Error) -> Self {
        Error::EncryptionError
    }
}
