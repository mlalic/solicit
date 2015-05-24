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

use http::{HttpScheme, HttpResult, StreamId, Header, ALPN_PROTOCOLS};
use http::transport::TransportStream;
use http::frame::{SettingsFrame, HttpSetting, Frame};
use http::connection::{
    SendFrame, ReceiveFrame,
    SendStatus,
    HttpConnection,
    EndStream,
};
use http::session::{
    Session,
    Stream, DefaultStream,
    DefaultSessionState, SessionState,
};
use http::priority::SimplePrioritizer;

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
    /// The port on which the connection should be established
    pub port: u16,
}

impl<'a> CleartextConnector<'a> {
    /// Creates a new `CleartextConnector` that will attempt to establish a connection to the given
    /// host on port 80.
    pub fn new(host: &'a str) -> CleartextConnector {
        CleartextConnector { host: host, port: 80 }
    }

    /// Creates a new `CleartextConnector` that will attempt to establish a connection to the given
    /// host on the given port.
    pub fn with_port(host: &'a str, port: u16) -> CleartextConnector {
        CleartextConnector { host: host, port: port }
    }
}

/// A newtype wrapping the `io::Error`, as it occurs when attempting to
/// establish an HTTP/2 connection over cleartext TCP (with prior knowledge).
pub struct CleartextConnectError(io::Error);

/// For convenience we make sure that `io::Error`s are easily convertible to
/// the `CleartextConnectError`, if needed.
impl From<io::Error> for CleartextConnectError {
    fn from(e: io::Error) -> CleartextConnectError { CleartextConnectError(e) }
}

/// The error is marked as an `HttpConnectError`
impl HttpConnectError for CleartextConnectError {}

impl<'a> HttpConnect for CleartextConnector<'a> {
    type Stream = TcpStream;
    type Err = CleartextConnectError;

    /// Establishes a cleartext TCP connection based on the host and port.
    /// If it is not possible, returns an `HttpError`.
    fn connect(self) -> Result<ClientStream<TcpStream>, CleartextConnectError> {
        let mut stream = try!(TcpStream::connect((self.host, self.port)));
        // Once the stream has been established, we need to write the client preface,
        // to ensure that the connection is indeed initialized.
        try!(write_preface(&mut stream));

        // All done.
        Ok(ClientStream(stream, HttpScheme::Http, self.host.into()))
    }
}

/// A struct representing a request stream. It provides the headers that are to be sent when
/// initiating the request, as well as a `Stream` instance that handles the received response and
/// provides the request body.
pub struct RequestStream<S> where S: Stream {
    /// The list of headers that will be sent with the request.
    pub headers: Vec<Header>,
    /// The underlying `Stream` instance, which will handle the response, as well as optionally
    /// provide the body of the request.
    pub stream: S,
}

/// The struct extends the `HttpConnection` API with client-specific methods (such as
/// `start_request`) and wires the `HttpConnection` to the client `Session` callbacks.
pub struct ClientConnection<S, R, State=DefaultSessionState<DefaultStream>>
        where S: SendFrame, R: ReceiveFrame, State: SessionState {
    /// The underlying `HttpConnection` that will be used for any HTTP/2
    /// communication.
    conn: HttpConnection<S, R>,
    /// The state of the session associated to this client connection. Maintains the status of the
    /// connection streams.
    pub state: State,
}

impl<S, R, State> ClientConnection<S, R, State>
        where S: SendFrame, R: ReceiveFrame, State: SessionState {
    /// Creates a new `ClientConnection` that will use the given `HttpConnection`
    /// for all its underlying HTTP/2 communication.
    ///
    /// The given `state` instance will handle the maintenance of the session's state.
    pub fn with_connection(conn: HttpConnection<S, R>, state: State)
            -> ClientConnection<S, R, State> {
        ClientConnection {
            conn: conn,
            state: state,
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
        let mut session = ClientSession::new(&mut self.state);
        self.conn.expect_settings(&mut session)
    }

    /// Starts a new request based on the given `RequestStream`.
    ///
    /// For now it does not perform any validation whether the given `RequestStream` is valid.
    pub fn start_request(&mut self, req: RequestStream<State::Stream>) -> HttpResult<()> {
        let end_stream = if req.stream.is_closed_local() { EndStream::Yes } else { EndStream::No };
        try!(self.conn.send_headers(req.headers, req.stream.id(), end_stream));
        // Start tracking the stream if the headers are queued successfully.
        self.state.insert_stream(req.stream);

        Ok(())
    }

    /// Fully handles the next incoming frame. Events are passed on to the internal `session`
    /// instance.
    #[inline]
    pub fn handle_next_frame(&mut self) -> HttpResult<()> {
        let mut session = ClientSession::new(&mut self.state);
        self.conn.handle_next_frame(&mut session)
    }

    /// Queues a new DATA frame onto the underlying `SendFrame`.
    ///
    /// Currently, no prioritization of streams is taken into account and which stream's data is
    /// queued cannot be relied on.
    pub fn send_next_data(&mut self) -> HttpResult<SendStatus> {
        debug!("Sending next data...");
        // A default "maximumum" chunk size of 8 KiB is set on all data frames.
        // TODO: Account for the current stream and connection window sizes, as well as the
        //       SETTINGS_MAX_FRAME_SIZE setting, when deciding on the maximum chunk size.
        const MAX_CHUNK_SIZE: usize = 8 * 1024;
        let mut buf = Vec::with_capacity(MAX_CHUNK_SIZE);
        unsafe { buf.set_len(MAX_CHUNK_SIZE); }

        let mut prioritizer = SimplePrioritizer::new(&mut self.state, &mut buf);

        self.conn.send_next_data(&mut prioritizer)
    }
}

/// An implementation of the `Session` trait specific to handling client HTTP/2 connections.
///
/// While handling the events signaled by the `HttpConnection`, the struct will modify the given
/// session state appropriately.
///
/// The purpose of the type is to make it easier for client implementations to
/// only handle stream-level events by providing a `Stream` implementation,
/// instead of having to implement all session management callbacks.
///
/// For example, by varying the `Stream` implementation it is easy to implement
/// a client that streams responses directly into a file on the local file system,
/// instead of keeping it in memory (like the `DefaultStream` does), without
/// having to change any HTTP/2-specific logic.
pub struct ClientSession<'a, State> where State: SessionState + 'a {
    state: &'a mut State,
}

impl<'a, State> ClientSession<'a, State> where State: SessionState + 'a {
    /// Returns a new `ClientSession` associated to the given state.
    #[inline]
    pub fn new(state: &'a mut State) -> ClientSession<State> {
        ClientSession {
            state: state,
        }
    }
}

impl<'a, State> Session for ClientSession<'a, State> where State: SessionState + 'a {
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
        // Since this implies that the server has closed the stream (i.e. provided a response), we
        // close the local end of the stream, as well as the remote one; there's no need to keep
        // sending out the request body if the server's decided that it doesn't want to see it.
        stream.close()
    }
}

#[cfg(test)]
mod tests {
    use super::{
        ClientSession,
        write_preface,
        RequestStream,
    };

    use std::mem;

    use http::StreamId;
    use http::tests::common::{
        TestStream,
        build_mock_client_conn,
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
        SendStatus,
    };
    use http::session::{Session, SessionState, Stream, DefaultSessionState};

    /// Tests that a client connection is correctly initialized, by reading the
    /// server preface (i.e. a settings frame) as the first frame of the connection.
    #[test]
    fn test_init_client_conn() {
        let frames = vec![HttpFrame::SettingsFrame(SettingsFrame::new())];
        let mut conn = build_mock_client_conn(frames);

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
        let mut conn = build_mock_client_conn(frames);

        // We get an error since the first frame sent by the server was not
        // SETTINGS.
        assert!(conn.init().is_err());
    }

    /// A helper function that prepares a `TestStream` with an optional outgoing data stream.
    fn prepare_stream(id: StreamId, data: Option<Vec<u8>>) -> TestStream {
        let mut stream = TestStream::new(id);
        match data {
            None => stream.close_local(),
            Some(d) => stream.set_outgoing(d),
        };
        return stream;
    }

    /// Tests that the `ClientConnection` correctly sends the next data, depending on the streams
    /// known to it.
    #[test]
    fn test_client_conn_send_next_data() {
        {
            // No streams => nothing sent.
            let mut conn = build_mock_client_conn(vec![]);
            let res = conn.send_next_data().unwrap();
            assert_eq!(res, SendStatus::Nothing);
        }
        {
            // A locally closed stream (i.e. nothing to send)
            let mut conn = build_mock_client_conn(vec![]);
            conn.state.insert_stream(prepare_stream(1, None));
            let res = conn.send_next_data().unwrap();
            assert_eq!(res, SendStatus::Nothing);
        }
        {
            // A stream with some data
            let mut conn = build_mock_client_conn(vec![]);
            conn.state.insert_stream(prepare_stream(1, Some(vec![1, 2, 3])));
            let res = conn.send_next_data().unwrap();
            assert_eq!(res, SendStatus::Sent);

            // All of it got sent in the first go, so now we've got nothing?
            let res = conn.send_next_data().unwrap();
            assert_eq!(res, SendStatus::Nothing);
        }
        {
            // Multiple streams with data
            let mut conn = build_mock_client_conn(vec![]);
            conn.state.insert_stream(prepare_stream(1, Some(vec![1, 2, 3])));
            conn.state.insert_stream(prepare_stream(3, Some(vec![1, 2, 3])));
            conn.state.insert_stream(prepare_stream(5, Some(vec![1, 2, 3])));
            for _ in 0..3 {
                let res = conn.send_next_data().unwrap();
                assert_eq!(res, SendStatus::Sent);
            }
            // All of it got sent in the first go, so now we've got nothing?
            let res = conn.send_next_data().unwrap();
            assert_eq!(res, SendStatus::Nothing);
        }
    }

    /// Tests that the `ClientConnection::start_request` method correctly starts a new request.
    #[test]
    fn test_client_conn_start_request() {
        {
            // No body
            let mut conn = build_mock_client_conn(vec![]);

            conn.start_request(RequestStream {
                headers: vec![
                    (b":method".to_vec(), b"GET".to_vec()),
                ],
                stream: prepare_stream(1, None),
            }).unwrap();

            // The stream is in the connection state?
            assert!(conn.state.get_stream_ref(1).is_some());
            // The headers got sent?
            // (It'd be so much nicer to assert that the `send_headers` method got called)
            assert_eq!(conn.conn.sender.sent.len(), 1);
            match conn.conn.sender.sent[0] {
                HttpFrame::HeadersFrame(ref frame) => {
                    // The frame closed the stream?
                    assert!(frame.is_end_of_stream());
                },
                _ => panic!("Expected a Headers frame"),
            };
        }
        {
            // With a body
            let mut conn = build_mock_client_conn(vec![]);

            conn.start_request(RequestStream {
                headers: vec![
                    (b":method".to_vec(), b"POST".to_vec()),
                ],
                stream: prepare_stream(1, Some(vec![1, 2, 3])),
            }).unwrap();

            // The stream is in the connection state?
            assert!(conn.state.get_stream_ref(1).is_some());
            // The headers got sent?
            // (It'd be so much nicer to assert that the `send_headers` method got called)
            assert_eq!(conn.conn.sender.sent.len(), 1);
            match conn.conn.sender.sent[0] {
                HttpFrame::HeadersFrame(ref frame) => {
                    // The stream is still open
                    assert!(!frame.is_end_of_stream());
                },
                _ => panic!("Expected a Headers frame"),
            };
        }
    }

    /// Tests that a `ClientSession` notifies the correct stream when the
    /// appropriate callback is invoked.
    ///
    /// A better unit test would give a mock Stream to the `ClientSession`,
    /// instead of testing both the `ClientSession` and the `DefaultStream`
    /// in the same time...
    #[test]
    fn test_client_session_notifies_stream() {
        let mut state = DefaultSessionState::<TestStream>::new();
        state.insert_stream(Stream::new(1));

        {
            // Registering some data to stream 1...
            let mut session = ClientSession::new(&mut state);
            session.new_data_chunk(1, &[1, 2, 3]);
        }
        // ...works.
        assert_eq!(state.get_stream_ref(1).unwrap().body, vec![1, 2, 3]);
        {
            // Some more...
            let mut session = ClientSession::new(&mut state);
            session.new_data_chunk(1, &[4]);
        }
        // ...works.
        assert_eq!(state.get_stream_ref(1).unwrap().body, vec![1, 2, 3, 4]);
        // Now headers?
        let headers = vec![(b":method".to_vec(), b"GET".to_vec())];
        {
            let mut session = ClientSession::new(&mut state);
            session.new_headers(1, headers.clone());
        }
        assert_eq!(state.get_stream_ref(1).unwrap().headers.clone().unwrap(),
                   headers);
        // Add another stream in the mix
        state.insert_stream(Stream::new(3));
        {
            // and send it some data
            let mut session = ClientSession::new(&mut state);
            session.new_data_chunk(3, &[100]);
        }
        assert_eq!(state.get_stream_ref(3).unwrap().body, vec![100]);
        {
            // Finally, the stream 1 ends...
            let mut session = ClientSession::new(&mut state);
            session.end_of_stream(1);
        }
        // ...and gets closed.
        assert!(state.get_stream_ref(1).unwrap().is_closed());
        // but not the other one.
        assert!(!state.get_stream_ref(3).unwrap().is_closed());
        // Sanity check: both streams still found in the session
        assert_eq!(state.iter().collect::<Vec<_>>().len(), 2);
        // The closed stream is returned...
        let closed = state.get_closed();
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].id(), 1);
        // ...and is also removed from the session!
        assert_eq!(state.iter().collect::<Vec<_>>().len(), 1);
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
