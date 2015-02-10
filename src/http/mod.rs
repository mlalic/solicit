//! The module implements the client side of the HTTP/2 protocol and exposes
//! an API for using it.
use std::old_io::IoError;

pub mod frame;
pub mod transport;
pub mod connection;

/// An alias for the type that represents the ID of an HTTP/2 stream
pub type StreamId = u32;

/// An enum representing errors that can arise when performing operations
/// involving an HTTP/2 connection.
pub enum HttpError {
    IoError(IoError),
    UnknownFrameType,
    InvalidFrame,
}
