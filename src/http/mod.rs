//! The module implements the client side of the HTTP/2 protocol and exposes
//! an API for using it.
use std::io;

pub mod frame;
pub mod transport;
pub mod connection;

/// An alias for the type that represents the ID of an HTTP/2 stream
pub type StreamId = u32;
/// An alias for the type that represents HTTP/2 haders. For now we only alias
/// the tuple of byte vectors instead of going with a full struct representation.
pub type Header = (Vec<u8>, Vec<u8>);

/// An enum representing errors that can arise when performing operations
/// involving an HTTP/2 connection.
pub enum HttpError {
    IoError(io::Error),
    UnknownFrameType,
    InvalidFrame,
}

/// A convenience `Result` type that has the `HttpError` type as the error
/// type and a generic Ok result type.
pub type HttpResult<T> = Result<T, HttpError>;
