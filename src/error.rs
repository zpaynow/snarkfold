use ark_std::fmt;

#[derive(Debug, Clone)]
pub enum SnarkFoldError {
    InvalidProof,
    InvalidInstance,
    FoldingError(String),
    HashError(String),
    SerializationError(String),
    VerificationError(String),
}

impl fmt::Display for SnarkFoldError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SnarkFoldError::InvalidProof => write!(f, "Invalid proof"),
            SnarkFoldError::InvalidInstance => write!(f, "Invalid instance"),
            SnarkFoldError::FoldingError(msg) => write!(f, "Folding error: {}", msg),
            SnarkFoldError::HashError(msg) => write!(f, "Hash error: {}", msg),
            SnarkFoldError::SerializationError(msg) => write!(f, "Serialization error: {}", msg),
            SnarkFoldError::VerificationError(msg) => write!(f, "Verification error: {}", msg),
        }
    }
}

impl std::error::Error for SnarkFoldError {}

pub type SnarkFoldResult<T> = core::result::Result<T, SnarkFoldError>;
