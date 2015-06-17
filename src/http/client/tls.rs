//! The module contains helpers for implementing TLS-based client connections.
//!
//! Available only when the `"tls"` crate feature is enabled.
//!
//! Depends on the `openssl` crate.
//!
//! # Example
//!
//! Establishing a new client connection using the `TlsConnector` and issuing a `GET` request.
//!
//! ```no_run
//! // Remember to enable the "tls" feature for `solicit`
//! use solicit::http::client::tls::TlsConnector;
//! use solicit::client::SimpleClient;
//! use std::str;
//!
//! // Connect to an HTTP/2 aware server
//! let path = "/path/to/certs.pem";
//! let connector = TlsConnector::new("http2bin.org", &path);
//! let mut client = SimpleClient::with_connector(connector).unwrap();
//! let response = client.get(b"/get", &[]).unwrap();
//! assert_eq!(response.stream_id, 1);
//! assert_eq!(response.status_code().unwrap(), 200);
//! // Dump the headers and the response body to stdout.
//! // They are returned as raw bytes for the user to do as they please.
//! // (Note: in general directly decoding assuming a utf8 encoding might not
//! // always work -- this is meant as a simple example that shows that the
//! // response is well formed.)
//! for header in response.headers.iter() {
//!     println!("{}: {}",
//!         str::from_utf8(&header.0).unwrap(),
//!         str::from_utf8(&header.1).unwrap());
//! }
//! println!("{}", str::from_utf8(&response.body).unwrap());
//! ```

use std::convert::AsRef;
use std::net::TcpStream;
use std::path::Path;
use std::error;
use std::fmt;
use std::str;
use std::io;
use http::{HttpScheme, ALPN_PROTOCOLS};

use super::{ClientStream, write_preface, HttpConnect, HttpConnectError};

use openssl::ssl::{Ssl, SslStream, SslContext};
use openssl::ssl::{SSL_VERIFY_PEER, SSL_VERIFY_FAIL_IF_NO_PEER_CERT};
use openssl::ssl::SSL_OP_NO_COMPRESSION;
use openssl::ssl::error::SslError;
use openssl::ssl::SslMethod;

/// A struct implementing the functionality of establishing a TLS-backed TCP stream
/// that can be used by an HTTP/2 connection. Takes care to set all the TLS options
/// to those allowed by the HTTP/2 spec, as well as of the protocol negotiation.
///
/// # Example
///
/// Issue a GET request over `https` using the `TlsConnector`
///
/// ```no_run
/// use solicit::http::client::tls::TlsConnector;
/// use solicit::client::SimpleClient;
/// use std::str;
///
/// // Connect to an HTTP/2 aware server
/// let path = "/path/to/certs.pem";
/// let connector = TlsConnector::new("http2bin.org", &path);
/// let mut client = SimpleClient::with_connector(connector).unwrap();
/// let response = client.get(b"/get", &[]).unwrap();
/// assert_eq!(response.stream_id, 1);
/// assert_eq!(response.status_code().unwrap(), 200);
/// // Dump the headers and the response body to stdout.
/// // They are returned as raw bytes for the user to do as they please.
/// // (Note: in general directly decoding assuming a utf8 encoding might not
/// // always work -- this is meant as a simple example that shows that the
/// // response is well formed.)
/// for header in response.headers.iter() {
///     println!("{}: {}",
///         str::from_utf8(&header.0).unwrap(),
///         str::from_utf8(&header.1).unwrap());
/// }
/// println!("{}", str::from_utf8(&response.body).unwrap());
/// ```
pub struct TlsConnector<'a, 'ctx> {
    pub host: &'a str,
    context: Http2TlsContext<'ctx>,
}

/// A private enum that represents the two options for configuring the
/// `TlsConnector`
enum Http2TlsContext<'a> {
    /// This means that the `TlsConnector` will use the referenced `SslContext`
    /// instance when creating a new `SslStream`
    Wrapped(&'a SslContext),
    /// This means that the `TlsConnector` will create a new context with the
    /// certificates file being found at the given path.
    CertPath(&'a Path),
}

/// An enum representing possible errors that can arise when trying to
/// establish an HTTP/2 connection over TLS.
pub enum TlsConnectError {
    /// The variant corresponds to the underlying raw TCP connection returning
    /// an error.
    IoError(io::Error),
    /// The variant corresponds to the TLS negotiation returning an error.
    SslError(SslError),
    /// The variant corresponds to the case when the TLS connection is
    /// established, but the application protocol that was negotiated didn't
    /// end up being HTTP/2.
    /// It wraps the established SSL stream in order to allow the client to
    /// decide what to do with it (and the application protocol that was
    /// chosen).
    Http2NotSupported(SslStream<TcpStream>),
}

// Note: TcpStream does not implement `Debug` in 1.0.0, so deriving is not possible.
impl fmt::Debug for TlsConnectError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        // The enum variant...
        try!(write!(fmt, "TlsConnectError::{}", match *self {
            TlsConnectError::IoError(_) => "IoError",
            TlsConnectError::SslError(_) => "SslError",
            TlsConnectError::Http2NotSupported(_) => "Http2NotSupported",
        }));
        // ...and the wrapped value, except for when it's the stream.
        match *self {
            TlsConnectError::IoError(ref err) => try!(write!(fmt, "({:?})", err)),
            TlsConnectError::SslError(ref err) => try!(write!(fmt, "({:?})", err)),
            TlsConnectError::Http2NotSupported(_) => try!(write!(fmt, "(...)")),
        };

        Ok(())
    }
}

impl fmt::Display for TlsConnectError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt, "TLS HTTP/2 connect error: {}", (self as &error::Error).description())
    }
}

impl error::Error for TlsConnectError {
    fn description(&self) -> &str {
        match *self {
            TlsConnectError::IoError(ref err) => err.description(),
            TlsConnectError::SslError(ref err) => err.description(),
            TlsConnectError::Http2NotSupported(_) => "HTTP/2 not supported by the server",
        }
    }

    fn cause(&self) -> Option<&error::Error> {
        match *self {
            TlsConnectError::IoError(ref err) => Some(err),
            TlsConnectError::SslError(ref err) => Some(err),
            TlsConnectError::Http2NotSupported(_) => None,
        }
    }
}

impl From<io::Error> for TlsConnectError {
    fn from(err: io::Error) -> TlsConnectError {
        TlsConnectError::IoError(err)
    }
}

impl From<SslError> for TlsConnectError {
    fn from(err: SslError) -> TlsConnectError {
        TlsConnectError::SslError(err)
    }
}

impl HttpConnectError for TlsConnectError {}

impl<'a, 'ctx> TlsConnector<'a, 'ctx> {
    /// Creates a new `TlsConnector` that will create a new `SslContext` before
    /// trying to establish the TLS connection. The path to the CA file that the
    /// context will use needs to be provided.
    pub fn new<P: AsRef<Path>>(host: &'a str, ca_file_path: &'ctx P) -> TlsConnector<'a, 'ctx> {
        TlsConnector {
            host: host,
            context: Http2TlsContext::CertPath(ca_file_path.as_ref()),
        }
    }

    /// Creates a new `TlsConnector` that will use the provided context to
    /// create the `SslStream` that will back the HTTP/2 connection.
    pub fn with_context(host: &'a str, context: &'ctx SslContext) -> TlsConnector<'a, 'ctx> {
        TlsConnector {
            host: host,
            context: Http2TlsContext::Wrapped(context),
        }
    }

    /// Builds up a default `SslContext` instance wth TLS settings that the
    /// HTTP/2 spec mandates. The path to the CA file needs to be provided.
    pub fn build_default_context(ca_file_path: &Path) -> Result<SslContext, TlsConnectError> {
        // HTTP/2 connections need to be on top of TLSv1.2 or newer.
        let mut context = try!(SslContext::new(SslMethod::Tlsv1_2));

        // This makes the certificate required (only VERIFY_PEER would mean optional)
        context.set_verify(SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, None);
        try!(context.set_CA_file(ca_file_path));
        // Compression is not allowed by the spec
        context.set_options(SSL_OP_NO_COMPRESSION);
        // The HTTP/2 protocol identifiers are constant at the library level...
        context.set_npn_protocols(ALPN_PROTOCOLS);

        Ok(context)
    }
}

impl<'a, 'ctx> HttpConnect for TlsConnector<'a, 'ctx> {
    type Stream = SslStream<TcpStream>;
    type Err = TlsConnectError;

    fn connect(self) -> Result<ClientStream<SslStream<TcpStream>>, TlsConnectError> {
        // First, create a TCP connection to port 443
        let raw_tcp = try!(TcpStream::connect(&(self.host, 443)));
        // Now build the SSL instance, depending on which SSL context should be
        // used...
        let ssl = match self.context {
            Http2TlsContext::CertPath(path) => {
                let ctx = try!(TlsConnector::build_default_context(&path));
                try!(Ssl::new(&ctx))
            },
            Http2TlsContext::Wrapped(ctx) => try!(Ssl::new(ctx)),
        };
        // SNI must be used
        try!(ssl.set_hostname(self.host));

        // Wrap the Ssl instance into an `SslStream`
        let mut ssl_stream = try!(SslStream::new_from(ssl, raw_tcp));
        // This connector only understands HTTP/2, so if that wasn't chosen in
        // NPN, we raise an error.
        let fail = match ssl_stream.get_selected_npn_protocol() {
            None => true,
            Some(proto) => {
                // Make sure that the protocol is one of the HTTP/2 protocols.
                debug!("Selected protocol -> {:?}", str::from_utf8(proto));
                let found = ALPN_PROTOCOLS.iter().any(|&http2_proto| http2_proto == proto);

                // We fail if we don't find an HTTP/2 protcol match...
                !found
            }
        };
        if fail {
            // We need the fail flag (instead of returning from one of the match
            // arms above because we need to move the `ssl_stream` and that is
            // not possible above (since it's borrowed at that point).
            return Err(TlsConnectError::Http2NotSupported(ssl_stream));
        }

        // Now that the stream is correctly established, we write the client preface.
        try!(write_preface(&mut ssl_stream));

        // All done.
        Ok(ClientStream(ssl_stream, HttpScheme::Https, self.host.into()))
    }
}
