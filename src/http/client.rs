//! The module contains a number of reusable components for implementing the client side of an
//! HTTP/2 connection.

use std::net::TcpStream;
use std::convert::AsRef;
use std::path::Path;
use std::io;
use std::str;

use openssl::ssl::{Ssl, SslStream, SslContext};
use openssl::ssl::{SSL_VERIFY_PEER, SSL_VERIFY_FAIL_IF_NO_PEER_CERT};
use openssl::ssl::SSL_OP_NO_COMPRESSION;
use openssl::ssl::error::SslError;
use openssl::ssl::SslMethod;

use http::{HttpScheme, HttpResult, Request, StreamId, Header, ALPN_PROTOCOLS};
use http::transport::TransportStream;
use http::frame::{SettingsFrame, HttpSetting, Frame};
use http::connection::{
    SendFrame, ReceiveFrame,
    HttpConnection,
};
use http::session::{Session, Stream, DefaultStream, DefaultSessionState, SessionState};

/// Writes the client preface to the underlying HTTP/2 connection.
///
/// According to the HTTP/2 spec, a client preface is first a specific
/// sequence of octets, followed by a settings frame.
///
/// # Returns
/// Any error raised by the underlying connection is propagated.
pub fn write_preface<W: io::Write>(stream: &mut W) -> Result<(), io::Error> {
    // The first part of the client preface is always this sequence of 24
    // raw octets.
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    try!(stream.write_all(preface));

    // It is followed by the client's settings.
    let settings = {
        let mut frame = SettingsFrame::new();
        frame.add_setting(HttpSetting::EnablePush(0));
        frame
    };
    try!(stream.write_all(&settings.serialize()));
    debug!("Sent client preface");

    Ok(())
}

/// A convenience wrapper type that represents an established client network transport stream.
/// It wraps the stream itself, the scheme of the protocol to be used, and the remote
/// host name.
pub struct ClientStream<TS: TransportStream>(pub TS, pub HttpScheme, pub String);

/// A marker trait for errors raised by attempting to establish an HTTP/2
/// connection.
pub trait HttpConnectError {}

/// A trait that can be implemented by structs that want to provide the
/// functionality of establishing network connections for use by HTTP/2 connections.
///
/// The `ClientStream` instance returned from the `connect` method needs to contain
/// the `TransportStream` that can be used by an HTTP/2 connection, along with the
/// appropriate scheme (depending on how the connection was established), and the remote
/// host name.
///
/// The transport stream needs to have already been initialized by writing the client
/// preface. The helper function `write_preface` can be used for this purpose.
pub trait HttpConnect {
    /// The type of the underlying transport stream that the `HttpConnection`s
    /// produced by this `HttpConnect` implementation will be based on.
    type Stream: TransportStream;
    /// The type of the error that can be produced by trying to establish the
    /// connection (i.e. calling the `connect` method).
    type Err;

    /// Establishes a network connection that can be used by HTTP/2 connections.
    fn connect(self) -> Result<ClientStream<Self::Stream>, Self::Err>;
}

/// A struct implementing the functionality of establishing a TLS-backed TCP stream
/// that can be used by an HTTP/2 connection. Takes care to set all the TLS options
/// to those allowed by the HTTP/2 spec, as well as of the protocol negotiation.
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

/// A struct that establishes a cleartext TCP connection that can be used by an HTTP/2
/// connection. Defaults to using port 80.
///
/// It assumes that the connection is based on prior knowledge of the server's
/// support for HTTP/2.
///
/// More information in the [spec](http://http2.github.io/http2-spec/#known-http)
pub struct CleartextConnector<'a> {
    /// The host to which the connection should be established
    pub host: &'a str,
}

/// A newtype wrapping the `io::Error`, as it occurs when attempting to
/// establish an HTTP/2 connection over cleartext TCP (with prior knowledge).
pub struct CleartextConnectError(io::Error);

/// For convenience we make sure that `io::Error`s are easily convertable to
/// the `CleartextConnectError`, if needed.
impl From<io::Error> for CleartextConnectError {
    fn from(e: io::Error) -> CleartextConnectError { CleartextConnectError(e) }
}

/// The error is marked as an `HttpConnectError`
impl HttpConnectError for CleartextConnectError {}

impl<'a> HttpConnect for CleartextConnector<'a> {
    type Stream = TcpStream;
    type Err = CleartextConnectError;

    /// Establishes a cleartext TCP connection to the host on port 80.
    /// If it is not possible, returns an `HttpError`.
    fn connect(self) -> Result<ClientStream<TcpStream>, CleartextConnectError> {
        let mut stream = try!(TcpStream::connect((self.host, 80)));
        // Once the stream has been established, we need to write the client preface,
        // to ensure that the connection is indeed initialized.
        try!(write_preface(&mut stream));

        // All done.
        Ok(ClientStream(stream, HttpScheme::Http, self.host.into()))
    }
}

/// The struct extends the `HttpConnection` API with client-specific methods (such as
/// `send_request`) and wires the `HttpConnection` to the client `Session` callbacks.
pub struct ClientConnection<S, R, Sess>
        where S: SendFrame, R: ReceiveFrame, Sess: Session {
    /// The underlying `HttpConnection` that will be used for any HTTP/2
    /// communication.
    conn: HttpConnection<S, R>,
    /// The `Session` associated with this connection. It is essentially a set
    /// of callbacks that are triggered by the connection when different states
    /// in the HTTP/2 communication arise.
    pub session: Sess,
}

impl<S, R, Sess> ClientConnection<S, R, Sess> where S: SendFrame, R: ReceiveFrame, Sess: Session {
    /// Creates a new `ClientConnection` that will use the given `HttpConnection`
    /// for all its underlying HTTP/2 communication.
    ///
    /// The given `session` instance will receive all events that arise from reading frames from
    /// the underlying HTTP/2 connection.
    pub fn with_connection(conn: HttpConnection<S, R>, session: Sess)
            -> ClientConnection<S, R, Sess> {
        ClientConnection {
            conn: conn,
            session: session,
        }
    }

    /// Returns the scheme of the underlying `HttpConnection`.
    #[inline]
    pub fn scheme(&self) -> HttpScheme {
        self.conn.scheme
    }

    /// Performs the initialization of the `ClientConnection`.
    ///
    /// This means that it expects the next frame that it receives to be the server preface -- i.e.
    /// a `SETTINGS` frame. Returns an `HttpError` if this is not the case.
    pub fn init(&mut self) -> HttpResult<()> {
        try!(self.read_preface());
        Ok(())
    }

    /// Reads and handles the server preface from the underlying HTTP/2
    /// connection.
    ///
    /// According to the HTTP/2 spec, a server preface consists of a single
    /// settings frame.
    ///
    /// # Returns
    ///
    /// Any error raised by the underlying connection is propagated.
    ///
    /// Additionally, if it is not possible to decode the server preface,
    /// it returns the `HttpError::UnableToConnect` variant.
    fn read_preface(&mut self) -> HttpResult<()> {
        self.conn.expect_settings(&mut self.session)
    }

    /// A method that sends the given `Request` to the server.
    ///
    /// The method blocks until the entire request has been sent.
    ///
    /// All errors are propagated.
    pub fn send_request(&mut self, req: Request) -> HttpResult<()> {
        let end_of_stream = req.body.len() == 0;
        try!(self.conn.send_headers(req.headers, req.stream_id, end_of_stream));
        if !end_of_stream {
            // Queue the entire request body for transfer now...
            // Also assumes that the entire body fits into a single frame.
            // TODO Stash the body locally (associated to a stream) and send it out depending on a
            //      pluggable stream prioritization strategy.
            try!(self.conn.send_data(req.body, req.stream_id, true));
        }

        Ok(())
    }

    /// Fully handles the next incoming frame. Events are passed on to the internal `session`
    /// instance.
    #[inline]
    pub fn handle_next_frame(&mut self) -> HttpResult<()> {
        self.conn.handle_next_frame(&mut self.session)
    }
}

/// A simple implementation of the `Session` trait.
///
/// Relies on the `DefaultSessionState` to keep track of its currently open streams.
///
/// The purpose of the type is to make it easier for client implementations to
/// only handle stream-level events by providing a `Stream` implementation,
/// instead of having to implement the entire session management (tracking active
/// streams, etc.).
///
/// For example, by varying the `Stream` implementation it is easy to implement
/// a client that streams responses directly into a file on the local file system,
/// instead of keeping it in memory (like the `DefaultStream` does), without
/// having to change any HTTP/2-specific logic.
pub struct ClientSession<S=DefaultStream> where S: Stream {
    state: DefaultSessionState<S>,
}

impl<S> ClientSession<S> where S: Stream {
    /// Returns a new `ClientSession` with no active streams.
    pub fn new() -> ClientSession<S> {
        ClientSession {
            state: DefaultSessionState::new(),
        }
    }

    /// Returns a reference to a stream with the given ID, if such a stream is
    /// found in the `ClientSession`.
    #[inline]
    pub fn get_stream(&self, stream_id: StreamId) -> Option<&S> {
        self.state.get_stream_ref(stream_id)
    }

    #[inline]
    pub fn get_stream_mut(&mut self, stream_id: StreamId) -> Option<&mut S> {
        self.state.get_stream_mut(stream_id)
    }

    /// Creates a new stream with the given ID in the session.
    #[inline]
    pub fn new_stream(&mut self, stream_id: StreamId) {
        self.state.insert_stream(Stream::new(stream_id));
    }

    /// Returns all streams that are closed and tracked by the session.
    ///
    /// The streams are moved out of the session.
    #[inline]
    pub fn get_closed(&mut self) -> Vec<S> {
        self.state.get_closed()
    }
}

impl<S> Session for ClientSession<S> where S: Stream {
    fn new_data_chunk(&mut self, stream_id: StreamId, data: &[u8]) {
        debug!("Data chunk for stream {}", stream_id);
        let mut stream = match self.state.get_stream_mut(stream_id) {
            None => {
                debug!("Received a frame for an unknown stream!");
                return;
            },
            Some(stream) => stream,
        };
        // Now let the stream handle the data chunk
        stream.new_data_chunk(data);
    }

    fn new_headers(&mut self, stream_id: StreamId, headers: Vec<Header>) {
        debug!("Headers for stream {}", stream_id);
        let mut stream = match self.state.get_stream_mut(stream_id) {
            None => {
                debug!("Received a frame for an unknown stream!");
                return;
            },
            Some(stream) => stream,
        };
        // Now let the stream handle the headers
        stream.set_headers(headers);
    }

    fn end_of_stream(&mut self, stream_id: StreamId) {
        debug!("End of stream {}", stream_id);
        let mut stream = match self.state.get_stream_mut(stream_id) {
            None => {
                debug!("Received a frame for an unknown stream!");
                return;
            },
            Some(stream) => stream,
        };
        stream.close()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClientConnection,
        ClientSession,
        write_preface,
    };

    use std::mem;

    use http::Request;
    use http::tests::common::{
        TestSession,
        build_mock_http_conn,
    };
    use http::frame::{
        SettingsFrame,
        DataFrame,
        RawFrame,
        Frame,
        unpack_header,
    };
    use http::connection::{
        HttpFrame,
    };
    use http::session::{Session, SessionState, Stream};

    /// Tests that a client connection is correctly initialized, by reading the
    /// server preface (i.e. a settings frame) as the first frame of the connection.
    #[test]
    fn test_init_client_conn() {
        let frames = vec![HttpFrame::SettingsFrame(SettingsFrame::new())];
        let mut conn = ClientConnection::with_connection(
            build_mock_http_conn(frames),
            TestSession::new());

        conn.init().unwrap();

        // We have read the server's response (the settings frame only, since no panic
        // ocurred)
        assert_eq!(conn.conn.receiver.recv_list.len(), 0);
        // We also sent an ACK already.
        let frame = match conn.conn.sender.sent.remove(0) {
            HttpFrame::SettingsFrame(frame) => frame,
            _ => panic!("ACK not sent!"),
        };
        assert!(frame.is_ack());
    }

    /// Tests that a client connection fails to initialize when the server does
    /// not send a settings frame as its first frame (i.e. server preface).
    #[test]
    fn test_init_client_conn_no_settings() {
        let frames = vec![HttpFrame::DataFrame(DataFrame::new(1))];
        let mut conn = ClientConnection::with_connection(
            build_mock_http_conn(frames),
            TestSession::new());

        // We get an error since the first frame sent by the server was not
        // SETTINGS.
        assert!(conn.init().is_err());
    }

    /// Tests that a `ClientConnection` correctly sends a `Request` with no
    /// body.
    #[test]
    fn test_client_conn_send_request_no_body() {
        let req = Request {
            stream_id: 1,
            // An incomplete header list, but this does not matter for this test.
            headers: vec![
                (b":method".to_vec(), b"GET".to_vec()),
                (b":path".to_vec(), b"/".to_vec()),
             ],
            body: Vec::new(),
        };
        let mut conn = ClientConnection::with_connection(
            build_mock_http_conn(vec![]), TestSession::new());

        conn.send_request(req).unwrap();

        let frame = match conn.conn.sender.sent.remove(0) {
            HttpFrame::HeadersFrame(frame) => frame,
            _ => panic!("Headers not sent!"),
        };
        // We sent a headers frame with end of headers and end of stream flags
        assert!(frame.is_headers_end());
        assert!(frame.is_end_of_stream());
        // ...and nothing else!
        assert_eq!(conn.conn.sender.sent.len(), 0);
    }

    /// Tests that a `ClientConnection` correctly sends a `Request` with a small body (i.e. a body
    /// that fits into a single HTTP/2 DATA frame).
    #[test]
    fn test_client_conn_send_request_with_small_body() {
        let body = vec![1, 2, 3];
        let req = Request {
            stream_id: 1,
            // An incomplete header list, but this does not matter for this test.
            headers: vec![
                (b":method".to_vec(), b"GET".to_vec()),
                (b":path".to_vec(), b"/".to_vec()),
             ],
            body: body.clone(),
        };
        let mut conn = ClientConnection::with_connection(
            build_mock_http_conn(vec![]), TestSession::new());

        conn.send_request(req).unwrap();

        let frame = match conn.conn.sender.sent.remove(0) {
            HttpFrame::HeadersFrame(frame) => frame,
            _ => panic!("Headers not sent!"),
        };
        // The headers were sent, but didn't close the stream
        assert!(frame.is_headers_end());
        assert!(!frame.is_end_of_stream());
        // A single data frame is found that *did* close the stream
        let frame = match conn.conn.sender.sent.remove(0) {
            HttpFrame::DataFrame(frame) => frame,
            _ => panic!("Headers not sent!"),
        };
        assert!(frame.is_end_of_stream());
        // The data bore the correct payload
        assert_eq!(frame.data, body);
        // ...and nothing else was sent!
        assert_eq!(conn.conn.sender.sent.len(), 0);
    }

    /// Tests that a `ClientSession` notifies the correct stream when the
    /// appropriate callback is invoked.
    ///
    /// A better unit test would give a mock Stream to the `ClientSession`,
    /// instead of testing both the `ClientSession` and the `DefaultStream`
    /// in the same time...
    #[test]
    fn test_client_session_notifies_stream() {
        let mut session: ClientSession = ClientSession::new();
        session.new_stream(1);

        // Registering some data to stream 1...
        session.new_data_chunk(1, &[1, 2, 3]);
        // ...works.
        assert_eq!(session.get_stream(1).unwrap().body, vec![1, 2, 3]);
        // Some more...
        session.new_data_chunk(1, &[4]);
        // ...works.
        assert_eq!(session.get_stream(1).unwrap().body, vec![1, 2, 3, 4]);
        // Now headers?
        let headers = vec![(b":method".to_vec(), b"GET".to_vec())];
        session.new_headers(1, headers.clone());
        assert_eq!(session.get_stream(1).unwrap().headers.clone().unwrap(),
                   headers);
        // Add another stream in the mix
        session.new_stream(3);
        // and send it some data
        session.new_data_chunk(3, &[100]);
        assert_eq!(session.get_stream(3).unwrap().body, vec![100]);
        // Finally, the stream 1 ends...
        session.end_of_stream(1);
        // ...and gets closed.
        assert!(session.get_stream(1).unwrap().closed);
        // but not the other one.
        assert!(!session.get_stream(3).unwrap().closed);
        // Sanity check: both streams still found in the session
        assert_eq!(session.state.iter().collect::<Vec<_>>().len(), 2);
        // The closed stream is returned...
        let closed = session.get_closed();
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].id(), 1);
        // ...and is also removed from the session!
        assert_eq!(session.state.iter().collect::<Vec<_>>().len(), 1);
    }

    /// Tests that the `write_preface` function correctly writes a client preface to
    /// a given `io::Write`.
    #[test]
    fn test_write_preface() {
        /// A helper function that parses out the first frame contained in the
        /// given buffer, expecting it to be the frame type of the generic parameter
        /// `F`. Returns the size of the raw frame read and the frame itself.
        ///
        /// Panics if unable to obtain such a frame.
        fn get_frame_from_buf<F: Frame>(buf: &[u8]) -> (F, usize) {
            let headers = unpack_header(unsafe {
                assert!(buf.len() >= 9);
                mem::transmute(buf.as_ptr())
            });
            let len = headers.0 as usize;

            let raw = RawFrame::from_buf(&buf[..9 + len]).unwrap();
            let frame = Frame::from_raw(raw).unwrap();

            (frame, len + 9)
        }

        // The buffer (`io::Write`) into which we will write the preface.
        let mut written: Vec<u8> = Vec::new();

        // Do it...
        write_preface(&mut written).unwrap();

        // The first bytes written to the underlying transport layer are the
        // preface bytes.
        let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        let frames_buf = &written[preface.len()..];
        // Immediately after that we sent a settings frame...
        assert_eq!(preface, &written[..preface.len()]);
        let (frame, _): (SettingsFrame, _) = get_frame_from_buf(frames_buf);
        // ...which was not an ack, but our own settings.
        assert!(!frame.is_ack());
    }
}
