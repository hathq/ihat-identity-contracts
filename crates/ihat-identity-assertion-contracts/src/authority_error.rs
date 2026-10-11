use thiserror::Error;

#[derive(Clone, Debug, Error, Eq, PartialEq)]
pub enum AuthorityWireError {
    #[error("authority wire document is empty or too large")]
    InputTooLarge,
    #[error("authority wire contract is invalid")]
    ContractInvalid,
    #[error("authority wire context does not match")]
    ContextMismatch,
    #[error("authority wire document is outside its validity window")]
    TimeInvalid,
    #[error("authority wire signature is invalid")]
    SignatureInvalid,
    #[error("authority wire canonical encoding failed")]
    CanonicalInvalid,
}
