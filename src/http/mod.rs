//! The module implements the client side of the HTTP/2 protocol and exposes
//! an API for using it.

pub mod frame;

/// An alias for the type that represents the ID of an HTTP/2 stream
pub type StreamId = u32;
