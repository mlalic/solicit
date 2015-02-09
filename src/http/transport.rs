//! The module contains implementations of the transport layer functionality
//! that HTTP/2 requires. It exposes APIs that allow the HTTP/2 connection to
//! use the transport layer without requiring it to know which exact
//! implementation they are using (i.e. a clear-text TCP connection, a TLS
//! protected connection, or even a mock implementation).

use std::old_io::Stream;
use std::old_io::net::tcp::TcpStream;

/// A trait that any struct that wants to provide the transport layer for
/// HTTP/2 needs to implement.
///
/// For now, we do not define any additional methods on top of those required
/// by the `Stream` trait.
pub trait TransportStream: Stream {}

/// Since `TcpStream` already implements `Stream` and we do not define any
/// additional required methods on `TransportStream`, we get this for free.
impl TransportStream for TcpStream {}
