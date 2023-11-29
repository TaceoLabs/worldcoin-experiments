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
    /// Code size is invalid
    #[error("Code size is invalid")]
    InvlidCodeSizeError,
    /// Config Error
    #[error("Invalid Configuration")]
    ConfigError,
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
    /// Some other error has occured.
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
