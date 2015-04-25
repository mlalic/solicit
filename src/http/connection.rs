//! The module contains the implementation of an HTTP/2 connection.
//!
//! This provides an API to read and write raw HTTP/2 frames.
//!
//! The basic `HttpConnection` provides an API to read and write raw HTTP/2
//! frames.
//!
//! The `ClientConnection` provides a slightly higher level API (based on the
//! `HttpConnection`) that exposes client-specific functions of an HTTP/2
//! connection, such as sending requests.

use std::net::TcpStream;
use std::convert::AsRef;
use std::borrow::Cow;
use std::path::Path;
use std::io;
use std::str;

use openssl::ssl::{Ssl, SslStream, SslContext};
use openssl::ssl::{SSL_VERIFY_PEER, SSL_VERIFY_FAIL_IF_NO_PEER_CERT};
use openssl::ssl::SSL_OP_NO_COMPRESSION;
use openssl::ssl::error::SslError;
use openssl::ssl::SslMethod;

use super::session::Session;
use super::ALPN_PROTOCOLS;
use super::{HttpError, HttpResult, Request, HttpScheme};
use super::transport::TransportStream;
use super::frame::{
    Frame,
    RawFrame,
    DataFrame,
    DataFlag,
    HeadersFrame,
    HeadersFlag,
    SettingsFrame,
    HttpSetting,
    unpack_header,
};
use hpack;

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

impl HttpFrame {
    pub fn from_raw(raw_frame: RawFrame) -> HttpResult<HttpFrame> {
        let frame = match raw_frame.header.1 {
            0x0 => HttpFrame::DataFrame(try!(HttpFrame::parse_frame(raw_frame))),
            0x1 => HttpFrame::HeadersFrame(try!(HttpFrame::parse_frame(raw_frame))),
            0x4 => HttpFrame::SettingsFrame(try!(HttpFrame::parse_frame(raw_frame))),
            _ => return Err(HttpError::UnknownFrameType),
        };

        Ok(frame)
    }

    /// A helper method that parses the given `RawFrame` into the given `Frame`
    /// implementation.
    ///
    /// # Returns
    ///
    /// Failing to decode the given `Frame` from the `raw_frame`, an
    /// `HttpError::InvalidFrame` error is returned.
    #[inline]
    fn parse_frame<F: Frame>(raw_frame: RawFrame) -> HttpResult<F> {
        // TODO: The reason behind being unable to decode the frame should be
        //       extracted to allow an appropriate connection-level action to be
        //       taken (e.g. responding with a PROTOCOL_ERROR).
        Frame::from_raw(raw_frame).ok_or(HttpError::InvalidFrame)
    }
}
/// The struct implements the HTTP/2 connection level logic.
///
/// It provides an API for writing and reading HTTP/2 frames. It also takes
/// care to validate the received frames.
pub struct HttpConnection<S> where S: TransportStream {
    /// The stream to which the raw bytes will be written
    stream: S,
    /// The scheme of the connection
    pub scheme: HttpScheme,
    /// The host to which the connection is established
    pub host: String,
}

impl<S> HttpConnection<S> where S: TransportStream {
    /// Creates a new `HttpConnection` that will use the given stream as its
    /// underlying transport layer.
    ///
    /// The host to which the connection is established, as well as the connection
    /// scheme are provided.
    pub fn new<'a>(stream: S, scheme: HttpScheme, host: Cow<'a, str>) -> HttpConnection<S> {
        HttpConnection {
            stream: stream,
            scheme: scheme,
            host: host.into_owned(),
        }
    }

    /// Sends the given frame to the peer.
    ///
    /// # Returns
    ///
    /// Any IO errors raised by the underlying transport layer are wrapped in a
    /// `HttpError::IoError` variant and propagated upwards.
    ///
    /// If the frame is successfully written, returns a unit Ok (`Ok(())`).
    pub fn send_frame<F: Frame>(&mut self, frame: F) -> HttpResult<()> {
        debug!("Sending frame ... {:?}", frame.get_header());
        try!(self.stream.write_all(&frame.serialize()));
        Ok(())
    }

    /// Reads a new frame from the transport layer.
    ///
    /// # Returns
    ///
    /// Any IO errors raised by the underlying transport layer are wrapped in a
    /// `HttpError::IoError` variant and propagated upwards.
    ///
    /// If the frame type is unknown the `HttpError::UnknownFrameType` variant
    /// is returned.
    ///
    /// If the frame type is recognized, but the frame cannot be successfully
    /// decoded, the `HttpError::InvalidFrame` variant is returned. For now,
    /// invalid frames are not further handled by informing the peer (e.g.
    /// sending PROTOCOL_ERROR) nor can the exact reason behind failing to
    /// decode the frame be extracted.
    ///
    /// If a frame is successfully read and parsed, returns the frame wrapped
    /// in the appropriate variant of the `HttpFrame` enum.
    pub fn recv_frame(&mut self) -> HttpResult<HttpFrame> {
        let header = unpack_header(&try!(self.read_header_bytes()));
        debug!("Received frame header {:?}", header);

        let payload = try!(self.read_payload(header.0));
        let raw_frame = RawFrame::with_payload(header, payload);

        // TODO: The reason behind being unable to decode the frame should be
        //       extracted to allow an appropriate connection-level action to be
        //       taken (e.g. responding with a PROTOCOL_ERROR).
        let frame = try!(HttpFrame::from_raw(raw_frame));
        Ok(frame)
    }

    /// Reads the header bytes of the next frame from the underlying stream.
    ///
    /// # Returns
    ///
    /// Since each frame header is exactly 9 octets long, returns an array of
    /// 9 bytes if the frame header is successfully read.
    ///
    /// Any IO errors raised by the underlying transport layer are wrapped in a
    /// `HttpError::IoError` variant and propagated upwards.
    fn read_header_bytes(&mut self) -> HttpResult<[u8; 9]> {
        let mut buf = [0; 9];
        try!(self.stream.read_exact(&mut buf));

        Ok(buf)
    }

    /// Reads the payload of an HTTP/2 frame with the given length.
    ///
    /// # Returns
    ///
    /// A newly allocated buffer containing the entire payload of the frame.
    ///
    /// Any IO errors raised by the underlying transport layer are wrapped in a
    /// `HttpError::IoError` variant and propagated upwards.
    fn read_payload(&mut self, len: u32) -> HttpResult<Vec<u8>> {
        debug!("Trying to read {} bytes of frame payload", len);
        let length = len as usize;
        let mut buf: Vec<u8> = Vec::with_capacity(length);
        // This is completely safe since we *just* allocated the vector with
        // the same capacity.
        unsafe { buf.set_len(length); }
        try!(self.stream.read_exact(&mut buf));

        Ok(buf)
    }

}

/// A marker trait for errors raised by attempting to establish an HTTP/2
/// connection.
pub trait HttpConnectError {}

/// A trait that can be implemented by structs that want to provide the
/// functionality of establishing HTTP/2 connections.
pub trait HttpConnect {
    /// The type of the underlying transport stream that the `HttpConnection`s
    /// produced by this `HttpConnect` implementation will be based on.
    type Stream: TransportStream;
    /// The type of the error that can be produced by trying to establish the
    /// connection (i.e. calling the `connect` method).
    type Err;

    /// Establishes an HTTP/2 connection...
    fn connect(self) -> Result<HttpConnection<Self::Stream>, Self::Err>;
}

/// A struct implementing the functionality of establishing an HTTP/2
/// connection over a TLS-backed stream. The protocol negotiation also takes
/// place within the TLS negotiation.
pub struct TlsConnector<'a, 'ctx> {
    pub host: &'a str,
    // pub context: Option<&'ctx SslContext>,
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

    fn connect(self) -> Result<HttpConnection<SslStream<TcpStream>>, TlsConnectError> {
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
        let ssl_stream = try!(SslStream::new_from(ssl, raw_tcp));
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

        // Finally, we can wrap it all up into an `HttpConnection`
        Ok(HttpConnection::new(ssl_stream, HttpScheme::Https, self.host.into()))
    }
}

/// A struct that establishes an HTTP/2 connection based on a prior-knowledge
/// cleartext TCP connection. It defaults to using port 80 on the given host.
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

    /// Establishes a cleartext TCP-backed HTTP/2 connection to the host on
    /// port 80.
    /// If it is not possible, returns an `HttpError`.
    fn connect(self) -> Result<HttpConnection<TcpStream>, CleartextConnectError> {
        let stream = try!(TcpStream::connect((self.host, 80)));
        let conn = HttpConnection::new(stream, HttpScheme::Http, self.host.into());

        Ok(conn)
    }
}

/// A struct implementing the client side of an HTTP/2 connection.
///
/// It builds on top of an `HttpConnection` and provides additional methods
/// that are only used by clients.
pub struct ClientConnection<TS, S>
        where TS: TransportStream, S: Session {
    /// The underlying `HttpConnection` that will be used for any HTTP/2
    /// communication.
    conn: HttpConnection<TS>,
    /// HPACK encoder
    encoder: hpack::Encoder<'static>,
    /// HPACK decoder
    decoder: hpack::Decoder<'static>,
    /// The `Session` associated with this connection. It is essentially a set
    /// of callbacks that are triggered by the connection when different states
    /// in the HTTP/2 communication arise.
    pub session: S,
}

impl<TS, S> ClientConnection<TS, S> where TS: TransportStream, S: Session {
    /// Creates a new `ClientConnection` that will use the given `HttpConnection`
    /// for all its underlying HTTP/2 communication.
    pub fn with_connection(conn: HttpConnection<TS>, session: S)
            -> ClientConnection<TS, S> {
        ClientConnection {
            conn: conn,
            encoder: hpack::Encoder::new(),
            decoder: hpack::Decoder::new(),
            session: session,
        }
    }

    /// Returns the host to which the underlying `HttpConnection` is established.
    #[inline]
    pub fn host(&self) -> &str {
        &self.conn.host
    }

    /// Returns the scheme of the underlying `HttpConnection`.
    #[inline]
    pub fn scheme(&self) -> HttpScheme {
        self.conn.scheme
    }

    /// Performs the initialization of the `ClientConnection`.
    ///
    /// Sends the client preface, followed by validating the receipt of the
    /// server preface.
    pub fn init(&mut self) -> HttpResult<()> {
        try!(self.write_preface());
        try!(self.read_preface());
        Ok(())
    }

    /// Writes the client preface to the underlying HTTP/2 connection.
    ///
    /// According to the HTTP/2 spec, a client preface is first a specific
    /// sequence of octets, followed by a settings frame.
    ///
    /// # Returns
    /// Any error raised by the underlying connection is propagated.
    fn write_preface(&mut self) -> HttpResult<()> {
        // The first part of the client preface is always this sequence of 24
        // raw octets.
        let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        try!(self.conn.stream.write(preface));

        // It is followed by the client's settings.
        let settings = {
            let mut frame = SettingsFrame::new();
            frame.add_setting(HttpSetting::EnablePush(0));
            frame
        };
        try!(self.conn.send_frame(settings));
        debug!("Sent client preface");

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
        match self.conn.recv_frame() {
            Ok(HttpFrame::SettingsFrame(settings)) => {
                debug!("Correctly received a SETTINGS frame from the server");
                try!(self.handle_settings_frame(settings));
            },
            // Wrong frame received...
            Ok(_) => return Err(HttpError::UnableToConnect),
            // Already an error -- propagate that.
            Err(e) => return Err(e),
        }
        Ok(())
    }

    /// A method that sends the given `Request` to the server.
    ///
    /// The method blocks until the entire request has been sent.
    ///
    /// All errors are propagated.
    ///
    /// # Note
    ///
    /// Request body is ignored for now.
    pub fn send_request(&mut self, req: Request) -> HttpResult<()> {
        let headers_fragment = self.encoder.encode(&req.headers);
        // For now, sending header fragments larger than 16kB is not supported
        // (i.e. the encoded representation cannot be split into CONTINUATION
        // frames).
        let mut frame = HeadersFrame::new(headers_fragment, req.stream_id);
        frame.set_flag(HeadersFlag::EndHeaders);
        // Since we are not supporting methods which require request bodies to
        // be sent, we end the stream from this side already.
        // TODO: Support bodies!
        frame.set_flag(HeadersFlag::EndStream);

        // Sending this HEADER frame opens the new stream and is equivalent to
        // sending the given request to the server.
        try!(self.conn.send_frame(frame));

        Ok(())
    }

    /// Fully handle the next incoming frame, blocking to read it from the
    /// underlying transport stream if not available yet.
    ///
    /// All communication errors are propagated.
    pub fn handle_next_frame(&mut self) -> HttpResult<()> {
        debug!("Waiting for frame...");
        let frame = match self.conn.recv_frame() {
            Ok(frame) => frame,
            Err(HttpError::UnknownFrameType) => {
                debug!("Ignoring unknown frame type");
                return Ok(())
            },
            Err(e) => {
                debug!("Encountered an HTTP/2 error, stopping.");
                return Err(e);
            },
        };

        self.handle_frame(frame)
    }

    /// Private helper method that actually handles a received frame.
    fn handle_frame(&mut self, frame: HttpFrame) -> HttpResult<()> {
        match frame {
            HttpFrame::DataFrame(frame) => {
                debug!("Data frame received");
                self.handle_data_frame(frame)
            },
            HttpFrame::HeadersFrame(frame) => {
                debug!("Headers frame received");
                self.handle_headers_frame(frame)
            },
            HttpFrame::SettingsFrame(frame) => {
                debug!("Settings frame received");
                self.handle_settings_frame(frame)
            }
        }
    }

    /// Private helper method that handles a received `DataFrame`.
    fn handle_data_frame(&mut self, frame: DataFrame) -> HttpResult<()> {
        self.session.new_data_chunk(frame.get_stream_id(), &frame.data);

        if frame.is_set(DataFlag::EndStream) {
            debug!("End of stream {}", frame.get_stream_id());
            self.session.end_of_stream(frame.get_stream_id())
        }

        Ok(())
    }

    /// Private helper method that handles a received `HeadersFrame`.
    fn handle_headers_frame(&mut self, frame: HeadersFrame) -> HttpResult<()> {
        let headers = try!(self.decoder.decode(&frame.header_fragment)
                                       .map_err(|e| HttpError::CompressionError(e)));
        self.session.new_headers(frame.get_stream_id(), headers);

        if frame.is_end_of_stream() {
            debug!("End of stream {}", frame.get_stream_id());
            self.session.end_of_stream(frame.get_stream_id());
        }

        Ok(())
    }

    /// Private helper method that handles a received `SettingsFrame`.
    fn handle_settings_frame(&mut self, frame: SettingsFrame) -> HttpResult<()> {
        if !frame.is_ack() {
            // TODO: Actually handle the settings change before
            //       sending out the ACK.
            debug!("Sending a SETTINGS ack");
            try!(self.conn.send_frame(SettingsFrame::new_ack()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};
    use std::io;

    use super::super::frame::{
        Frame, DataFrame, HeadersFrame,
        SettingsFrame,
        pack_header,
        RawFrame,
    };
    use super::{HttpConnection, HttpFrame, ClientConnection};
    use super::super::transport::TransportStream;
    use super::super::{HttpError, HttpScheme, Request, StreamId, Header, HttpResult};
    use super::super::session::Session;
    use hpack;

    /// A helper stub implementation of a `TransportStream`.
    ///
    /// When read from this stream, it spits out bytes from a predefined `Vec`
    /// in the original given order. Once those are exhausted, it returns an EOF.
    ///
    /// When writng to the stream, the bytes are aggregated to internal buffer.
    /// The contents of the buffer can be accessed using the `get_writted`
    /// method.
    ///
    /// It is possible to "close" the stream (both ends at once) so that
    /// aftwerwards any read or write attempt returns an `io::Error`;
    struct StubTransportStream {
        reader: Cursor<Vec<u8>>,
        writer: Cursor<Vec<u8>>,
        closed: bool,
    }

    impl StubTransportStream {
        /// Initializes the stream with the given byte vector representing
        /// the bytes that will be read from the stream.
        fn with_stub_content(stub: &Vec<u8>) -> StubTransportStream {
            StubTransportStream {
                reader: Cursor::new(stub.clone()),
                writer: Cursor::new(Vec::new()),
                closed: false,
            }
        }

        /// Returns a slice representing the bytes already written to the
        /// stream.
        fn get_written(&self) -> &[u8] {
            self.writer.get_ref()
        }

        /// Returns the position up to which the stream has been read.
        fn get_read_pos(&self) -> u64 {
            self.reader.position()
        }

        /// Closes the stream, making any read or write operation return an
        /// `io::Error` from there on out.
        fn close(&mut self) {
            self.closed = true;
        }
    }

    impl io::Read for StubTransportStream {
        fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
            if self.closed {
                Err(io::Error::new(io::ErrorKind::Other, "Closed"))
            } else {
                self.reader.read(buf)
            }
        }
    }

    impl io::Write for StubTransportStream {
        fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
            if self.closed {
                Err(io::Error::new(io::ErrorKind::Other, "Closed"))
            } else {
                self.writer.write(buf)
            }
        }

        fn flush(&mut self) -> io::Result<()> {
            self.writer.flush()
        }
    }

    impl TransportStream for StubTransportStream {
        fn try_split(&self) -> Result<StubTransportStream, io::Error> {
            panic!("HttpConnection should never need to split the stream.");
        }
    }

    /// A helper struct implementing the `Session` trait, intended for testing
    /// purposes.
    ///
    /// It is basically a poor man's mock, providing us the ability to check
    /// how many times the particular callbacks were called (although not the
    /// order in which they were called).
    ///
    /// Additionally, when created with `new_verify` it is possible to provide
    /// a list of headers and data chunks and make the session verify that it
    /// them from the connection in the exactly given order (i.e. relative
    /// order of chunks and headers; there is no way to check the order between
    /// chunks and headers for now).
    struct TestSession {
        silent: bool,
        /// List of expected headers -- in the order that they are expected
        headers: Vec<Vec<Header>>,
        /// List of expected data chunks -- in the order that they are expected
        chunks: Vec<Vec<u8>>,
        /// The current number of header calls.
        curr_header: usize,
        /// The current number of data chunk calls.
        curr_chunk: usize,
    }

    impl TestSession {
        /// Returns a new `TestSession` that only counts how many times the
        /// callback methods were invoked.
        fn new() -> TestSession {
            TestSession {
                silent: true,
                headers: Vec::new(),
                chunks: Vec::new(),
                curr_header: 0,
                curr_chunk: 0,
            }
        }

        /// Returns a new `TestSession` that veriies that the headers received
        /// in the callbacks are equal to those in the given headers `Vec` and
        /// that they come in exactly the given order. Does the same for chunks.
        fn new_verify(headers: Vec<Vec<Header>>, chunks: Vec<Vec<u8>>)
                -> TestSession {
            TestSession {
                silent: false,
                headers: headers,
                chunks: chunks,
                curr_header: 0,
                curr_chunk: 0,
            }
        }
    }

    impl Session for TestSession {
        fn new_data_chunk(&mut self, _: StreamId, data: &[u8]) {
            if !self.silent {
                assert_eq!(&self.chunks[self.curr_chunk], &data);
            }
            self.curr_chunk += 1;
        }

        fn new_headers(&mut self, _: StreamId, headers: Vec<Header>) {
            if !self.silent {
                assert_eq!(self.headers[self.curr_header], headers);
            }
            self.curr_header += 1;
        }

        fn end_of_stream(&mut self, _: StreamId) {}
    }

    /// A helper function that performs a `send_frame` operation on the given
    /// `HttpConnection` by providing the frame instance wrapped in the given
    /// `HttpFrame`.
    ///
    /// If the `HttpFrame` variant is `HttpFrame::UnknownFrame`, nothing will
    /// be sent and an `Ok(())` is returned.
    fn send_frame<TS: TransportStream>(conn: &mut HttpConnection<TS>, frame: HttpFrame)
            -> HttpResult<()> {
        match frame {
            HttpFrame::DataFrame(frame) => conn.send_frame(frame),
            HttpFrame::SettingsFrame(frame) => conn.send_frame(frame),
            HttpFrame::HeadersFrame(frame) => conn.send_frame(frame),
        }
    }

    /// A test that makes sure that the `StubTransportStream` exhibits
    /// properties that a "real" `TransportStream` would too.
    #[test]
    fn sanity_check_stub_stream() {
        // `read` returns 0 at the "end of file"?
        {
            let mut stream = StubTransportStream::with_stub_content(&vec![]);
            let mut buf = [0u8; 5];
            assert_eq!(stream.read(&mut buf).unwrap(), 0);
            assert_eq!(stream.read(&mut buf).unwrap(), 0);
        }
        // A closed stream always returns an io::Error
        {
            let mut stream = StubTransportStream::with_stub_content(&vec![]);
            stream.close();
            assert!(stream.write(&[1]).is_err());
            assert!(stream.read(&mut [0; 5]).is_err());
        }
    }

    /// A helper function that creates an `HttpConnection` with a `StubTransportStream`
    /// where the content of the stream is defined by the given `stub_data`
    fn build_http_conn(stub_data: &Vec<u8>) -> HttpConnection<StubTransportStream> {
        HttpConnection {
            stream: StubTransportStream::with_stub_content(stub_data),
            scheme: HttpScheme::Http,
            host: "".to_string(),
        }
    }

    /// A helper function that builds a buffer of bytes from the given `Vec` of
    /// `HttpFrame`s, by serializing them in the given order.
    fn build_stub_from_frames(frames: &Vec<HttpFrame>) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        for frame in frames.iter() {
            let serialized = match frame {
                &HttpFrame::DataFrame(ref frame) => frame.serialize(),
                &HttpFrame::HeadersFrame(ref frame) => frame.serialize(),
                &HttpFrame::SettingsFrame(ref frame) => frame.serialize(),
            };
            buf.extend(serialized.into_iter());
        }

        buf
    }

    /// Tests that the `HttpFrame::from_raw` method correctly recognizes the frame
    /// type from the header and returns the corresponding variant.
    #[test]
    fn test_http_frame_from_raw() {
        fn to_raw<F: Frame>(frame: F) -> RawFrame {
            RawFrame::from_buf(&frame.serialize()).unwrap()
        }

        assert!(match HttpFrame::from_raw(to_raw(DataFrame::new(1))) {
            Ok(HttpFrame::DataFrame(_)) => true,
            _ => false,
        });

        assert!(match HttpFrame::from_raw(to_raw(HeadersFrame::new(vec![], 1))) {
            Ok(HttpFrame::HeadersFrame(_)) => true,
            _ => false,
        });

        assert!(match HttpFrame::from_raw(to_raw(SettingsFrame::new())) {
            Ok(HttpFrame::SettingsFrame(_)) => true,
            _ => false,
        });

        // Invalid since it's headers on stream 0
        let invalid_frame = HeadersFrame::new(vec![], 0);
        assert!(HttpFrame::from_raw(to_raw(invalid_frame)).is_err());
    }

    /// Tests that it is possible to read a single frame from the stream.
    #[test]
    fn test_read_single_frame() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
        ];
        let mut conn = build_http_conn(&build_stub_from_frames(&frames));

        let actual: Vec<_> = (0..frames.len()).map(|_| conn.recv_frame().ok().unwrap())
                                      .collect();

        assert_eq!(actual, frames);
    }

    /// Tests that multiple frames are correctly read from the stream.
    #[test]
    fn test_read_multiple_frames() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
            HttpFrame::DataFrame(DataFrame::new(1)),
            HttpFrame::DataFrame(DataFrame::new(3)),
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 3)),
        ];
        let mut conn = build_http_conn(&build_stub_from_frames(&frames));

        let actual: Vec<_> = (0..frames.len()).map(|_| conn.recv_frame().ok().unwrap())
                                      .collect();

        assert_eq!(actual, frames);
    }

    /// Tests that when reading from a stream that initially contains no data,
    /// an `IoError` is returned.
    #[test]
    fn test_read_no_data() {
        let mut conn = build_http_conn(&vec![]);

        let res = conn.recv_frame();

        assert!(match res.err().unwrap() {
            HttpError::IoError(_) => true,
            _ => false,
        });
    }

    /// Tests that a read past the end of file (stream) results in an `IoError`.
    #[test]
    fn test_read_past_eof() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
        ];
        let mut conn = build_http_conn(&build_stub_from_frames(&frames));

        let _: Vec<_> = (0..frames.len()).map(|_| conn.recv_frame().ok().unwrap())
                                      .collect();
        let res = conn.recv_frame();

        assert!(match res.err().unwrap() {
            HttpError::IoError(_) => true,
            _ => false,
        });
    }

    /// Tests that when reading off a stream that doesn't have a complete frame
    /// header causes a graceful failure.
    #[test]
    fn test_read_invalid_stream_incomplete_frame() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
        ];
        let mut conn = build_http_conn(&{
            let mut buf: Vec<u8> = Vec::new();
            buf.extend(build_stub_from_frames(&frames).into_iter());
            // We add an extra trailing byte (a start of the header of another
            // frame).
            buf.push(0);
            buf
        });

        let actual: Vec<_> = (0..frames.len()).map(|_| conn.recv_frame().ok().unwrap())
                                      .collect();
        // The first frame is correctly read
        assert_eq!(actual, frames);
        // ...but now we get an error
        assert!(match conn.recv_frame().err().unwrap() {
            HttpError::IoError(_) => true,
            _ => false,
        });
    }

    /// Tests that when reading off a stream that doesn't have a frame payload
    /// (when it should) causes a graceful failure.
    #[test]
    fn test_read_invalid_stream_incomplete_payload() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
        ];
        let mut conn = build_http_conn(&{
            let mut buf: Vec<u8> = Vec::new();
            buf.extend(build_stub_from_frames(&frames).into_iter());
            // We add a header indicating that there should be 1 byte of payload
            let header = (1u32, 0u8, 0u8, 1u32);
            buf.extend(pack_header(&header).to_vec().into_iter());
            // ...but we don't add any payload!
            buf
        });

        let actual: Vec<_> = (0..frames.len()).map(|_| conn.recv_frame().ok().unwrap())
                                      .collect();
        // The first frame is correctly read
        assert_eq!(actual, frames);
        // ...but now we get an error
        assert!(match conn.recv_frame().err().unwrap() {
            HttpError::IoError(_) => true,
            _ => false,
        });
    }

    /// Tests that when reading off a stream that contains an invalid frame
    /// returns an appropriate indicator.
    #[test]
    fn test_read_invalid_frame() {
        // A DATA header which is attached to stream 0
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 0)),
        ];
        let mut conn = build_http_conn(&build_stub_from_frames(&frames));

        // An error indicating that the frame is invalid.
        assert!(match conn.recv_frame().err().unwrap() {
            HttpError::InvalidFrame => true,
            _ => false,
        });
    }

    /// Tests that when reading a frame with a header that indicates an
    /// unknown frame type, an appropriate error is returned.
    #[test]
    fn test_read_unknown_frame() {
        let mut conn = build_http_conn(&{
            let mut buf: Vec<u8> = Vec::new();
            // Frame type 10 with a payload of length 1 on stream 1
            let header = (1u32, 10u8, 0u8, 1u32);
            buf.extend(pack_header(&header).to_vec().into_iter());
            buf.push(1);
            buf
        });

        // Unknown frame error.
        assert!(match conn.recv_frame().err().unwrap() {
            HttpError::UnknownFrameType => true,
            _ => false,
        });
    }

    /// Tests that it is possible to write a single frame to the connection.
    #[test]
    fn test_write_single_frame() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
        ];
        let expected = build_stub_from_frames(&frames);
        let mut conn = build_http_conn(&vec![]);

        for frame in frames.into_iter() {
            send_frame(&mut conn, frame).unwrap();
        }

        assert_eq!(expected, conn.stream.get_written());
    }


    /// Tests that multiple frames are correctly written to the stream.
    #[test]
    fn test_write_multiple_frames() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
            HttpFrame::DataFrame(DataFrame::new(1)),
            HttpFrame::DataFrame(DataFrame::new(3)),
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 3)),
        ];
        let expected = build_stub_from_frames(&frames);
        let mut conn = build_http_conn(&vec![]);

        for frame in frames.into_iter() {
            send_frame(&mut conn, frame).unwrap();
        }

        assert_eq!(expected, conn.stream.get_written());
    }

    /// Tests that a write to a closed stream fails with an IoError.
    #[test]
    fn test_write_to_closed_stream() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
        ];
        let mut conn = build_http_conn(&vec![]);
        // Close the underlying stream!
        conn.stream.close();

        for frame in frames.into_iter() {
            let res = send_frame(&mut conn, frame);
            assert!(match res {
                Err(HttpError::IoError(_)) => true,
                _ => false,
            });
        }
    }

    /// A helper function that parses out the first frame contained in the
    /// given buffer, expecting it to be the frame type of the generic parameter
    /// `F`. Returns the size of the raw frame read and the frame itself.
    ///
    /// Panics if unable to obtain such a frame.
    fn get_frame_from_buf<F: Frame>(buf: &[u8]) -> (F, usize) {
        let raw = RawFrame::from_buf(buf).unwrap();
        let len = raw.header.0 as usize;
        let frame = Frame::from_raw(raw).unwrap();

        (frame, len + 9)
    }

    /// Tests that a client connection is correctly initialized, by writing the
    /// client preface and reading the server preface.
    #[test]
    fn test_init_client_conn() {
        let frames = vec![HttpFrame::SettingsFrame(SettingsFrame::new())];
        let server_frame_buf = build_stub_from_frames(&frames);
        let mut conn = ClientConnection::with_connection(
            build_http_conn(&server_frame_buf),
            TestSession::new());

        conn.init().ok().unwrap();
        let written = conn.conn.stream.get_written();

        // The first bytes written to the underlying transport layer are the
        // preface bytes.
        let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
        let frames_buf = &written[preface.len()..];
        // Immediately after that we sent a settings frame...
        assert_eq!(preface, &written[..preface.len()]);
        let len_settings = {
            let (frame, sz): (SettingsFrame, _) = get_frame_from_buf(frames_buf);
            // ...which was not an ack, but our own settings.
            assert!(!frame.is_ack());
            sz
        };
        // Then, we have read the server's response
        assert_eq!(
            server_frame_buf.len() as u64,
            conn.conn.stream.get_read_pos());
        // Finally, we also expect that the client has already sent a response
        // (an ack) to this server settings frame.
        let len_ack = {
            let (settings_frame, sz): (SettingsFrame, _) =
                get_frame_from_buf(&frames_buf[len_settings..]);
            assert!(settings_frame.is_ack());
            sz
        };
        // ...and we have not written anything else!
        assert_eq!(len_settings + len_ack, frames_buf.len());
    }

    /// Tests that a client connection fails to initialize when the server does
    /// not send a settings frame as its first frame (i.e. server preface).
    #[test]
    fn test_init_client_conn_no_settings() {
        let frames = vec![HttpFrame::DataFrame(DataFrame::new(1))];
        let server_frame_buf = build_stub_from_frames(&frames);
        let mut conn = ClientConnection::with_connection(
            build_http_conn(&server_frame_buf),
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
            build_http_conn(&vec![]), TestSession::new());

        conn.send_request(req).unwrap();
        let written = conn.conn.stream.get_written();

        let (frame, sz): (HeadersFrame, _) = get_frame_from_buf(written);
        // We sent a headers frame with end of headers and end of stream flags
        assert!(frame.is_headers_end());
        assert!(frame.is_end_of_stream());
        // ...and nothing else!
        assert_eq!(sz, written.len());
    }

    /// Tests that the `ClientConnection` correctly notifies the session on a
    /// new data chunk.
    #[test]
    fn test_client_conn_notifies_session_header() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
        ];
        let mut conn = ClientConnection::with_connection(
            build_http_conn(&build_stub_from_frames(&frames)),
            TestSession::new());

        conn.handle_next_frame().ok().unwrap();

        // A poor man's mock...
        // The header callback was called
        assert_eq!(conn.session.curr_header, 1);
        // ...no chunks were seen.
        assert_eq!(conn.session.curr_chunk, 0);
    }

    /// Tests that the `ClientConnection` correctly notifies the session on
    /// a new data chunk.
    #[test]
    fn test_client_conn_notifies_session_data() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::DataFrame(DataFrame::new(1)),
        ];
        let mut conn = ClientConnection::with_connection(
            build_http_conn(&build_stub_from_frames(&frames)),
            TestSession::new());

        conn.handle_next_frame().ok().unwrap();

        // A poor man's mock...
        // The header callback was not called
        assert_eq!(conn.session.curr_header, 0);
        // and exactly one chunk seen.
        assert_eq!(conn.session.curr_chunk, 1);
    }

    /// Tests that there is no notification for an invalid headers frame.
    #[test]
    fn test_client_conn_invalid_frame_no_notification() {
        let frames: Vec<HttpFrame> = vec![
            // Associated to stream 0!
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 0)),
        ];
        let mut conn = ClientConnection::with_connection(
            build_http_conn(&build_stub_from_frames(&frames)),
            TestSession::new());

        // We get an invalid frame error back...
        assert_eq!(
            conn.handle_next_frame().err().unwrap(),
            HttpError::InvalidFrame);

        // A poor man's mock...
        // No callbacks triggered
        assert_eq!(conn.session.curr_header, 0);
        assert_eq!(conn.session.curr_chunk, 0);
    }

    /// Tests that the session gets the correct values for the headers and data
    /// from the `ClientConnection`.
    #[test]
    fn test_client_conn_session_gets_headers_data_values() {
        let headers = vec![(b":method".to_vec(), b"GET".to_vec())];
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(
                    hpack::Encoder::new().encode(&headers),
                    1)),
            HttpFrame::DataFrame(DataFrame::new(1)), {
                let mut frame = DataFrame::new(1);
                frame.data = b"1234".to_vec();
                HttpFrame::DataFrame(frame)
            },
        ];
        let mut conn = ClientConnection::with_connection(
            build_http_conn(&build_stub_from_frames(&frames)),
            TestSession::new_verify(
                vec![headers],
                vec![b"".to_vec(), b"1234".to_vec()]));

        conn.handle_next_frame().ok().unwrap();
        conn.handle_next_frame().ok().unwrap();
        conn.handle_next_frame().ok().unwrap();

        // Two chunks and one header processed?
        assert_eq!(conn.session.curr_chunk, 2);
        assert_eq!(conn.session.curr_header, 1);
    }
}
