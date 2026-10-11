use thiserror::Error;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AssertionError {
    #[error("device identity assertion input is too large")]
    InputTooLarge,
    #[error("device identity assertion contract is invalid")]
    ContractInvalid,
    #[error("device identity assertion context does not match")]
    ContextMismatch,
    #[error("device identity assertion is outside its validity window")]
    TimeInvalid,
    #[error("device identity assertion signature is invalid")]
    SignatureInvalid,
}
