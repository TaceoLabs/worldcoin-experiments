use thiserror::Error;

/// An Error enum capturing the errors produced by this crate.
#[derive(Error, Debug)]
pub enum Error {
    /// Type conversion error
    #[error("Conversion error")]
    ConversionError,
    /// Mask HW is to small
    #[error("Mask HW is to small")]
    MaskHWError,
    /// Size is invalid
    #[error("Size is invalid")]
    InvalidSizeError,
    /// Code size is invalid
    #[error("Code size is invalid")]
    InvalidCodeSizeError,
    /// Message size is invalid
    #[error("Message size is invalid")]
    InvalidMessageSize,
    /// Commit was invalid
    #[error("Commit was invalid: Party {0}")]
    InvalidCommitment(usize),
    /// JMP verify failed Error
    #[error("JMP verify failed")]
    JmpVerifyError,
    /// Verify failed Error
    #[error("Verify failed")]
    VerifyError,
    /// DZKP verify failed Error
    #[error("DZKP verify failed")]
    DZKPVerifyError,
    /// Not enough triples error
    #[error("Not enough triples error")]
    NotEnoughTriplesError,
    /// Config Error
    #[error("Invalid Configuration")]
    ConfigError,
    /// No inverse error
    #[error("No inverse exists error")]
    NoInverseError,
    /// Serialization error
    #[error("Serialization error")]
    SerializationError,
    /// A IO error has orccured
    #[error("IO error")]
    IOError(#[from] std::io::Error),
    /// Invalid party id provided
    #[error("Invalid Party id {0}")]
    IdError(usize),
    /// Invalid number of parties
    #[error("Invalid number of parties {0}")]
    NumPartyError(usize),
    /// Invalid value provided
    #[error("Invalid value: {0}")]
    ValueError(String),
    /// Error from the color_eyre crate
    #[error("ColorEyre error")]
    ColorEyreError(#[from] color_eyre::Report),
    /// Some other error has occurred.
    #[error("Err: {0}")]
    Other(String),
}

impl From<String> for Error {
    fn from(mes: String) -> Self {
        Self::Other(mes)
    }
}
impl From<&str> for Error {
    fn from(mes: &str) -> Self {
        Self::Other(mes.to_owned())
    }
}
