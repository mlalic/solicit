//! The module contains the implementation of an HTTP/2 connection.
//!
//! This provides an API to read and write raw HTTP/2 frames.

use super::transport::TransportStream;
use super::frame::{
    Frame,
    DataFrame,
    HeadersFrame,
    SettingsFrame,
};

/// An enum representing all frame variants that can be returned by an
/// `HttpConnection`.
///
/// The variants wrap the appropriate `Frame` implementation.
#[derive(PartialEq)]
#[derive(Debug)]
pub enum HttpFrame {
    DataFrame(DataFrame),
    HeadersFrame(HeadersFrame),
    SettingsFrame(SettingsFrame),
}

/// The struct implements the HTTP/2 connection level logic.
///
/// It provides an API for writing and reading HTTP/2 frames. It also takes
/// care to validate the received frames.
pub struct HttpConnection<S> where S: TransportStream {
    stream: S,
}

impl<S> HttpConnection<S> where S: TransportStream {
    /// Creates a new `HttpConnection` that will use the given stream as its
    /// underlying transport layer.
    pub fn with_stream(stream: S) -> HttpConnection<S> {
        HttpConnection {
            stream: stream,
        }
    }
 }
