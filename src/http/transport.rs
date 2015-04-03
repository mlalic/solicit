//! The module contains implementations of the transport layer functionality
//! that HTTP/2 requires. It exposes APIs that allow the HTTP/2 connection to
//! use the transport layer without requiring it to know which exact
//! implementation they are using (i.e. a clear-text TCP connection, a TLS
//! protected connection, or even a mock implementation).

use std::io;
use std::io::{Read, Write};
use std::net::TcpStream;

/// A trait that any struct that wants to provide the transport layer for
/// HTTP/2 needs to implement.
///
/// It provides default implementations for some convenience methods, backed
/// by the `Read` and `Write` implementations.
pub trait TransportStream: Read + Write {
    /// A convenience method that performs as many `read` calls on the
    /// underlying `Read` implementation as it takes to fill the given buffer.
    ///
    /// The implementation simply calls the `read` in a loop until the
    /// buffer is filled or an aparent end of file is reached, upon which
    /// an error is returned.
    ///
    /// However, no particular care is taken to limit the number of loop
    /// iterations and it could theoretically be possible to end up reading
    /// a single byte at a time into a large buffer, taking a long time to
    /// return.
    ///
    /// Any errors raised by the underlying `Read` implementations are
    /// propagated.
    ///
    /// When an error is raised, the given buffer is only partially filled,
    /// but there is no way to know how many bytes were actually written to
    /// the underlying buffer, which means that, effectively, all read bytes
    /// are lost on any error.
    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let mut total = 0;
        while total < buf.len() {
            let read = try!(self.read(&mut buf[total..]));
            if read == 0 {
                // We consider this an unexpected end of file and return an
                // error since we were unable to read the minimum amount of
                // bytes.
                return Err(io::Error::new(io::ErrorKind::Other,
                                          "Not enough bytes"));
            }
            total += read;
        }

        Ok(())
    }
}

/// Since `TcpStream` already implements `Read` and `Write` we do not define any
/// additional required methods on `TransportStream`, we get this for free.
impl TransportStream for TcpStream {}
