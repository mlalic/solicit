//! The module implements the client side of the HTTP/2 protocol and exposes
//! an API for using it.
use std::io;
use std::convert::From;
use std::error::Error;

use hpack::decoder::DecoderError;

pub mod frame;
pub mod transport;
pub mod connection;
pub mod session;

/// An alias for the type that represents the ID of an HTTP/2 stream
pub type StreamId = u32;
/// An alias for the type that represents HTTP/2 haders. For now we only alias
/// the tuple of byte vectors instead of going with a full struct representation.
pub type Header = (Vec<u8>, Vec<u8>);

/// An enum representing errors that can arise when performing operations
/// involving an HTTP/2 connection.
#[derive(Debug)]
pub enum HttpError {
    IoError(io::Error),
    UnknownFrameType,
    InvalidFrame,
    CompressionError(DecoderError),
    UnknownStreamId,
    UnableToConnect,
    MalformedResponse,
}

/// Implement the trait that allows us to automatically convert `io::Error`s
/// into an `HttpError` by wrapping the given `io::Error` into an `HttpError::IoError` variant.
impl From<io::Error> for HttpError {
    fn from(err: io::Error) -> HttpError {
        HttpError::IoError(err)
    }
}

/// Implementation of the `PartialEq` trait as a convenience for tests.
#[cfg(test)]
impl PartialEq for HttpError {
    fn eq(&self, other: &HttpError) -> bool {
        match (self, other) {
            (&HttpError::IoError(ref e1), &HttpError::IoError(ref e2)) => {
                e1.kind() == e2.kind() && e1.description() == e2.description()
            },
            (&HttpError::UnknownFrameType, &HttpError::UnknownFrameType) => true,
            (&HttpError::InvalidFrame, &HttpError::InvalidFrame) => true,
            (&HttpError::CompressionError(ref e1), &HttpError::CompressionError(ref e2)) => {
                e1 == e2
            },
            (&HttpError::UnknownStreamId, &HttpError::UnknownStreamId) => true,
            (&HttpError::UnableToConnect, &HttpError::UnableToConnect) => true,
            (&HttpError::MalformedResponse, &HttpError::MalformedResponse) => true,
            _ => false,
        }
    }
}

/// A convenience `Result` type that has the `HttpError` type as the error
/// type and a generic Ok result type.
pub type HttpResult<T> = Result<T, HttpError>;

/// A struct representing the full raw response received on an HTTP/2 connection.
///
/// The full body of the response is included, regardless how large it may be.
/// The headers contain both the meta-headers, as well as the actual headers.
#[derive(Clone)]
pub struct Response {
    /// The ID of the stream to which the response is associated. HTTP/1.1 does
    /// not really have an equivalent to this.
    pub stream_id: StreamId,
    /// Exposes *all* the raw response headers, including the meta-headers.
    /// (For now the only meta header allowed in HTTP/2 responses is the
    /// `:status`.)
    pub headers: Vec<Header>,
    /// The full body of the response as an uninterpreted sequence of bytes.
    pub body: Vec<u8>,
}

impl Response {
    /// Creates a new `Response` with all the components already provided.
    pub fn new(stream_id: StreamId, headers: Vec<Header>, body: Vec<u8>)
            -> Response {
        Response {
            stream_id: stream_id,
            headers: headers,
            body: body,
        }
    }

    /// Gets the response status code from the pseudo-header. If the response
    /// does not contain the response as the first pseuo-header, an error is
    /// returned as such a response is malformed.
    pub fn status_code(&self) -> HttpResult<u16> {
        // Since pseudo-headers MUST be found before any regular header fields
        // and the *only* pseudo-header defined for responses is the `:status`
        // field, the `:status` MUST be the first header; otherwise, the
        // response is malformed.
        if self.headers.len() < 1 {
            return Err(HttpError::MalformedResponse)
        }
        if &self.headers[0].0 != &b":status" {
            Err(HttpError::MalformedResponse)
        } else {
            Ok(try!(Response::parse_status_code(&self.headers[0].1)))
        }
    }

    /// A helper function that parses a given buffer as a status code and
    /// returns it as a `u16`, if it is valid.
    fn parse_status_code(buf: &[u8]) -> HttpResult<u16> {
        // "The status-code element is a three-digit integer code [...]"
        if buf.len() != 3 {
            return Err(HttpError::MalformedResponse);
        }

        // "There are five values for the first digit"
        if buf[0] < b'1' || buf[0] > b'5' {
            return Err(HttpError::MalformedResponse);
        }

        // The rest of them just have to be digits
        if buf[1] < b'0' || buf[1] > b'9' || buf[2] < b'0' || buf[2] > b'9' {
            return Err(HttpError::MalformedResponse);
        }

        // Finally, we can merge them into an integer
        Ok(100 * ((buf[0] - b'0') as u16) +
           10 * ((buf[1] - b'0') as u16) +
           1 * ((buf[2] - b'0') as u16))
    }
}

/// A struct representing a full HTTP/2 request, along with the full body, as a
/// sequence of bytes.
#[derive(Clone)]
pub struct Request {
    pub stream_id: u32,
    pub headers: Vec<Header>,
    pub body: Vec<u8>,
}

#[cfg(test)]
mod tests {
    use super::{Response, HttpError};

    /// Tests that the `Response` struct correctly parses a status code from
    /// its headers list.
    #[test]
    fn test_parse_status_code_response() {
        {
            // Only status => Ok
            let resp = Response::new(
                1,
                vec![(b":status".to_vec(), b"200".to_vec())],
                vec![]);
            assert_eq!(resp.status_code().ok().unwrap(), 200);
        }
        {
            // Extra headers => still works
            let resp = Response::new(
                1,
                vec![(b":status".to_vec(), b"200".to_vec()),
                     (b"key".to_vec(), b"val".to_vec())],
                vec![]);
            assert_eq!(resp.status_code().ok().unwrap(), 200);
        }
        {
            // Status is not the first header => malformed
            let resp = Response::new(
                1,
                vec![(b"key".to_vec(), b"val".to_vec()),
                     (b":status".to_vec(), b"200".to_vec())],
                vec![]);
            assert_eq!(resp.status_code().err().unwrap(),
                       HttpError::MalformedResponse);
        }
        {
            // No headers at all => Malformed
            let resp = Response::new(1, vec![], vec![]);
            assert_eq!(resp.status_code().err().unwrap(),
                       HttpError::MalformedResponse);
        }
    }
}
