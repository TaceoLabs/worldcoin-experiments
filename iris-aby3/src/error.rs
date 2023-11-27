use thiserror::Error;

/// An Error enum capturing the errors produced by this crate.
#[derive(Error, Debug)]
pub enum Error {
    /// Type conversion error
    #[error("Conversion error")]
    ConversionError,
    /// A IO error has orccured
    #[error("IO error")]
    IOError(#[from] std::io::Error),

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
