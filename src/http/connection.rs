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
use std::path::Path;
use std::io;
use std::str;

use openssl::ssl::{Ssl, SslStream, SslContext};
use openssl::ssl::{SSL_VERIFY_PEER, SSL_VERIFY_FAIL_IF_NO_PEER_CERT};
use openssl::ssl::SSL_OP_NO_COMPRESSION;
use openssl::ssl::error::SslError;
use openssl::ssl::SslMethod;

use http::{
    Header,
    StreamId,
};
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
#[derive(Clone)]
pub enum HttpFrame {
    DataFrame(DataFrame),
    HeadersFrame(HeadersFrame),
    SettingsFrame(SettingsFrame),
    UnknownFrame(RawFrame),
}

impl HttpFrame {
    pub fn from_raw(raw_frame: RawFrame) -> HttpResult<HttpFrame> {
        let frame = match raw_frame.header().1 {
            0x0 => HttpFrame::DataFrame(try!(HttpFrame::parse_frame(raw_frame))),
            0x1 => HttpFrame::HeadersFrame(try!(HttpFrame::parse_frame(raw_frame))),
            0x4 => HttpFrame::SettingsFrame(try!(HttpFrame::parse_frame(raw_frame))),
            _ => HttpFrame::UnknownFrame(raw_frame),
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
/// This means that the struct is a bridge between the low level raw frame reads/writes (i.e. what
/// the `SendFrame` and `ReceiveFrame` traits do) and the higher session-level logic.
///
/// Therefore, it provides an API that exposes higher-level write operations, such as writing
/// headers or data, that take care of all the underlying frame construction that is required.
///
/// Similarly, it provides an API for handling events that arise from receiving frames, without
/// requiring the higher level to directly look at the frames themselves, rather only the semantic
/// content within the frames.
pub struct HttpConnection<S, R> where S: SendFrame, R: ReceiveFrame {
    /// The instance handling the reading of frames.
    pub receiver: R,
    /// The instance handling the writing of frames.
    pub sender: S,
    /// HPACK decoder used to decode incoming headers before passing them on to the session.
    decoder: hpack::Decoder<'static>,
    /// The HPACK encoder used to encode headers before sending them on this connection.
    encoder: hpack::Encoder<'static>,
    /// The scheme of the connection
    pub scheme: HttpScheme,
}

/// A trait that should be implemented by types that can provide the functionality
/// of sending HTTP/2 frames.
pub trait SendFrame {
    /// Sends the given raw frame.
    fn send_raw_frame(&mut self, frame: RawFrame) -> HttpResult<()>;
    /// Sends the given concrete frame.
    ///
    /// A default implementation based on the `send_raw_frame` method is provided.
    fn send_frame<F: Frame>(&mut self, frame: F) -> HttpResult<()> {
        self.send_raw_frame(RawFrame::from(frame.serialize()))
    }
}

/// A blanket implementation of `SendFrame` is possible for any type that is also an
/// `io::Write`.
impl<W> SendFrame for W where W: io::Write {
    #[inline]
    fn send_frame<F: Frame>(&mut self, frame: F) -> HttpResult<()> {
        try!(self.write_all(&frame.serialize()));
        Ok(())
    }

    #[inline]
    fn send_raw_frame(&mut self, frame: RawFrame) -> HttpResult<()> {
        let serialized: Vec<u8> = frame.into();
        try!(self.write_all(&serialized));
        Ok(())
    }
}

/// A trait that should be implemented by types that can provide the functionality
/// of receiving HTTP/2 frames.
pub trait ReceiveFrame {
    /// Return a new `HttpFrame` instance. Unknown frames can be wrapped in the
    /// `HttpFrame::UnknownFrame` variant (i.e. their `RawFrame` representation).
    fn recv_frame(&mut self) -> HttpResult<HttpFrame>;
}

/// A blanket implementation of the trait for `TransportStream`s.
impl<TS> ReceiveFrame for TS where TS: TransportStream {
    fn recv_frame(&mut self) -> HttpResult<HttpFrame> {
        // A helper function that reads the header of an HTTP/2 frame.
        // Simply reads the next 9 octets (and no more than 9).
        let read_header_bytes = |stream: &mut TS| -> HttpResult<[u8; 9]> {
            let mut buf = [0; 9];
            try!(stream.read_exact(&mut buf));

            Ok(buf)
        };
        // A helper function that reads the payload of a frame with the given length.
        // Reads exactly the length of the frame from the given stream.
        let read_payload = |stream: &mut TS, len: u32| -> HttpResult<Vec<u8>> {
            debug!("Trying to read {} bytes of frame payload", len);
            let length = len as usize;
            let mut buf: Vec<u8> = Vec::with_capacity(length);
            // This is completely safe since we *just* allocated the vector with
            // the same capacity.
            unsafe { buf.set_len(length); }
            try!(stream.read_exact(&mut buf));

            Ok(buf)
        };

        let header = unpack_header(&try!(read_header_bytes(self)));
        debug!("Received frame header {:?}", header);

        let payload = try!(read_payload(self, header.0));
        let raw_frame = RawFrame::with_payload(header, payload);

        // TODO: The reason behind being unable to decode the frame should be
        //       extracted to allow an appropriate connection-level action to be
        //       taken (e.g. responding with a PROTOCOL_ERROR).
        let frame = try!(HttpFrame::from_raw(raw_frame));
        Ok(frame)
    }
}

impl<S, R> HttpConnection<S, R> where S: SendFrame, R: ReceiveFrame {
    /// Creates a new `HttpConnection` that will use the given sender and receiver instances
    /// for writing and reading frames, respectively.
    pub fn new(sender: S, receiver: R, scheme: HttpScheme) -> HttpConnection<S, R> {
        HttpConnection {
            receiver: receiver,
            sender: sender,
            scheme: scheme,
            decoder: hpack::Decoder::new(),
            encoder: hpack::Encoder::new(),
        }
    }

    /// Creates a new `HttpConnection` that will use the given stream as its
    /// underlying transport layer.
    ///
    /// This constructor is provided as a convenience when the underlying IO of the
    /// HTTP/2 connection should be based on the `TransportStream` interface.
    ///
    /// The scheme of the connection is also provided.
    pub fn with_stream<TS>(stream: TS, scheme: HttpScheme) -> HttpConnection<TS, TS>
            where TS: TransportStream {
        let sender = stream.try_split().unwrap();
        let receiver = stream;
        HttpConnection::new(sender, receiver, scheme)
    }

    /// Sends the given frame to the peer.
    ///
    /// # Returns
    ///
    /// Any IO errors raised by the underlying transport layer are wrapped in a
    /// `HttpError::IoError` variant and propagated upwards.
    ///
    /// If the frame is successfully written, returns a unit Ok (`Ok(())`).
    #[inline]
    fn send_frame<F: Frame>(&mut self, frame: F) -> HttpResult<()> {
        debug!("Sending frame ... {:?}", frame.get_header());
        self.sender.send_frame(frame)
    }

    /// Reads a new frame from the transport layer.
    ///
    /// # Returns
    ///
    /// Any IO errors raised by the underlying transport layer are wrapped in a
    /// `HttpError::IoError` variant and propagated upwards.
    ///
    /// If the frame type is unknown the `RawFrame` is wrapped into a
    /// `HttpFrame::UnknownFrame` variant and returned.
    ///
    /// If the frame type is recognized, but the frame cannot be successfully
    /// decoded, the `HttpError::InvalidFrame` variant is returned. For now,
    /// invalid frames are not further handled by informing the peer (e.g.
    /// sending PROTOCOL_ERROR) nor can the exact reason behind failing to
    /// decode the frame be extracted.
    ///
    /// If a frame is successfully read and parsed, returns the frame wrapped
    /// in the appropriate variant of the `HttpFrame` enum.
    #[inline]
    fn recv_frame(&mut self) -> HttpResult<HttpFrame> {
        self.receiver.recv_frame()
    }

    /// A helper function that inserts the frames required to send the given headers onto the
    /// `SendFrame` stream.
    ///
    /// The `HttpConnection` performs the HPACK encoding of the header block using an internal
    /// encoder.
    ///
    /// # Parameters
    ///
    /// - `headers` - a headers list that should be sent.
    /// - `stream_id` - the ID of the stream on which the headers will be sent. The connection
    ///   performs no checks as to whether the stream is a valid identifier.
    /// - `end_stream` - whether the stream should be closed from the peer's side immediately
    ///   after sending the headers
    pub fn send_headers<H: Into<Vec<Header>>>(&mut self,
                                              headers: H,
                                              stream_id: StreamId,
                                              end_stream: bool) -> HttpResult<()> {
        self.send_headers_inner(headers.into(), stream_id, end_stream)
    }

    /// A private helper method: the non-generic implementation of the `send_headers` method.
    fn send_headers_inner(&mut self, headers: Vec<Header>, stream_id: StreamId, end_stream: bool)
            -> HttpResult<()> {
        let headers_fragment = self.encoder.encode(&headers);
        // For now, sending header fragments larger than 16kB is not supported
        // (i.e. the encoded representation cannot be split into CONTINUATION
        // frames).
        let mut frame = HeadersFrame::new(headers_fragment, stream_id);
        frame.set_flag(HeadersFlag::EndHeaders);

        if end_stream {
            frame.set_flag(HeadersFlag::EndStream);
        }

        self.send_frame(frame)
    }

    /// A helper function that inserts a frame representing the given data into the `SendFrame`
    /// stream.
    ///
    /// The `HttpConnection` itself does not track the flow control window and will happily send
    /// data that exceeds a particular stream's or the connection's flow control window size.
    ///
    /// # Parameters
    ///
    /// - `data` - the data that should be sent on the connection
    /// - `stream_id` - the ID of the stream on which the data will be sent
    /// - `end_stream` - whether the stream should be closed from the peer's side immediately after
    ///   sending the data (i.e. the last data frame closes the stream).
    pub fn send_data<D: Into<Vec<u8>>>(&mut self, data: D, stream_id: StreamId, end_stream: bool)
            -> HttpResult<()> {
        self.send_data_inner(data.into(), stream_id, end_stream)
    }

    /// A private helepr method: the non-generic implementation of the `send_data` method.
    fn send_data_inner(&mut self, data: Vec<u8>, stream_id: StreamId, end_stream: bool)
            -> HttpResult<()>{
        // TODO Validate that the given data can fit into the maximum frame size allowed by the
        //      current settings.
        let mut frame = DataFrame::new(stream_id);
        frame.data.extend(data);
        if end_stream {
            frame.set_flag(DataFlag::EndStream);
        }

        self.send_frame(frame)
    }

    /// The method processes the next incoming frame, expecting it to be a SETTINGS frame.
    /// Additionally, the frame cannot be an ACK settings frame, but rather it should contain the
    /// peer's settings.
    ///
    /// The method can be used when the receipt of the peer's preface needs to be asserted.
    ///
    /// If the received frame is not a SETTINGS frame, an `HttpError::UnableToConnect` variant is
    /// returned. (TODO: Change this variant's name, as it is a byproduct of this method's legacy)
    pub fn expect_settings<Sess: Session>(&mut self, session: &mut Sess) -> HttpResult<()> {
        let frame = self.recv_frame();
        match frame {
            Ok(HttpFrame::SettingsFrame(ref settings)) if !settings.is_ack() => {
                debug!("Correctly received a SETTINGS frame from the server");
            },
            // Wrong frame received...
            Ok(_) => return Err(HttpError::UnableToConnect),
            // Already an error -- propagate that.
            Err(e) => return Err(e),
        };
        try!(self.handle_frame(frame.unwrap(), session));
        Ok(())
    }

    /// Handles the next frame incoming on the `ReceiveFrame` instance.
    ///
    /// The `HttpConnection` takes care of parsing the frame and extracting the semantics behind it
    /// and passes this on to the higher level by invoking (possibly multiple) callbacks on the
    /// given `Session` instance. For information on which events can be passed to the session,
    /// check out the `Session` trait.
    ///
    /// If the handling is successful, a unit `Ok` is returned; all HTTP and IO errors are
    /// propagated.
    pub fn handle_next_frame<Sess: Session>(&mut self, session: &mut Sess) -> HttpResult<()> {
        debug!("Waiting for frame...");
        let frame = match self.recv_frame() {
            Ok(frame) => frame,
            Err(e) => {
                debug!("Encountered an HTTP/2 error, stopping.");
                return Err(e);
            },
        };

        self.handle_frame(frame, session)
    }

    /// Private helper method that actually handles a received frame.
    fn handle_frame<Sess: Session>(&mut self, frame: HttpFrame, session: &mut Sess)
            -> HttpResult<()> {
        match frame {
            HttpFrame::DataFrame(frame) => {
                debug!("Data frame received");
                self.handle_data_frame(frame, session)
            },
            HttpFrame::HeadersFrame(frame) => {
                debug!("Headers frame received");
                self.handle_headers_frame(frame, session)
            },
            HttpFrame::SettingsFrame(frame) => {
                debug!("Settings frame received");
                self.handle_settings_frame::<Sess>(frame, session)
            },
            HttpFrame::UnknownFrame(_) => {
                debug!("Unknown frame received");
                // We simply drop any unknown frames...
                // TODO Signal this to the session so that a hook is available
                //      for implementing frame-level protocol extensions.
                Ok(())
            },
        }
    }

    /// Private helper method that handles a received `DataFrame`.
    fn handle_data_frame<Sess: Session>(&mut self, frame: DataFrame, session: &mut Sess)
            -> HttpResult<()> {
        session.new_data_chunk(frame.get_stream_id(), &frame.data);

        if frame.is_set(DataFlag::EndStream) {
            debug!("End of stream {}", frame.get_stream_id());
            session.end_of_stream(frame.get_stream_id())
        }

        Ok(())
    }

    /// Private helper method that handles a received `HeadersFrame`.
    fn handle_headers_frame<Sess: Session>(&mut self, frame: HeadersFrame, session: &mut Sess)
            -> HttpResult<()> {
        let headers = try!(self.decoder.decode(&frame.header_fragment)
                                       .map_err(|e| HttpError::CompressionError(e)));
        session.new_headers(frame.get_stream_id(), headers);

        if frame.is_end_of_stream() {
            debug!("End of stream {}", frame.get_stream_id());
            session.end_of_stream(frame.get_stream_id());
        }

        Ok(())
    }

    /// Private helper method that handles a received `SettingsFrame`.
    fn handle_settings_frame<Sess: Session>(&mut self, frame: SettingsFrame, _session: &mut Session)
            -> HttpResult<()> {
        if !frame.is_ack() {
            // TODO: Actually handle the settings change before sending out the ACK
            //       sending out the ACK.
            debug!("Sending a SETTINGS ack");
            try!(self.send_frame(SettingsFrame::new_ack()));
        }

        Ok(())
    }
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

/// A struct implementing the client side of an HTTP/2 connection.
///
/// It builds on top of an `HttpConnection` and provides additional methods
/// that are only used by clients.
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

#[cfg(test)]
mod tests {
    use std::mem;

    use http::tests::common::{
        build_mock_http_conn,
        build_stub_from_frames,
        StubTransportStream,
        TestSession,
    };

    use super::super::frame::{
        Frame, DataFrame, HeadersFrame,
        SettingsFrame,
        pack_header,
        unpack_header,
        RawFrame,
    };
    use super::{HttpConnection, HttpFrame, ClientConnection, write_preface, SendFrame, ReceiveFrame};
    use super::super::transport::TransportStream;
    use super::super::{HttpError, Request, HttpResult};
    use hpack;

    /// A helper function that performs a `send_frame` operation on the given
    /// `HttpConnection` by providing the frame instance wrapped in the given
    /// `HttpFrame`.
    ///
    /// If the `HttpFrame` variant is `HttpFrame::UnknownFrame`, nothing will
    /// be sent and an `Ok(())` is returned.
    fn send_frame<S: SendFrame, R: ReceiveFrame>(conn: &mut HttpConnection<S, R>, frame: HttpFrame)
            -> HttpResult<()> {
        match frame {
            HttpFrame::DataFrame(frame) => conn.send_frame(frame),
            HttpFrame::SettingsFrame(frame) => conn.send_frame(frame),
            HttpFrame::HeadersFrame(frame) => conn.send_frame(frame),
            HttpFrame::UnknownFrame(_) => Ok(()),
        }
    }

    /// Tests the implementation of the `SendFrame` for `io::Write` types when
    /// writing individual frames.
    #[test]
    fn test_send_frame_for_io_write_individual() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
            HttpFrame::DataFrame(DataFrame::new(1)),
            HttpFrame::DataFrame(DataFrame::new(3)),
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 3)),
            HttpFrame::UnknownFrame(RawFrame::from(vec![1, 2, 3, 4])),
        ];
        for frame in frames.into_iter() {
            let mut writeable = Vec::new();
            let frame_serialized = match frame {
                HttpFrame::DataFrame(frame) => {
                    let ret = frame.serialize();
                    writeable.send_frame(frame).unwrap();
                    ret
                },
                HttpFrame::HeadersFrame(frame) => {
                    let ret = frame.serialize();
                    writeable.send_frame(frame).unwrap();
                    ret
                },
                HttpFrame::SettingsFrame(frame) => {
                    let ret = frame.serialize();
                    writeable.send_frame(frame).unwrap();
                    ret
                },
                HttpFrame::UnknownFrame(frame) => {
                    let ret = frame.serialize();
                    writeable.send_raw_frame(frame).unwrap();
                    ret
                },
            };
            assert_eq!(writeable, frame_serialized);
        }
    }

    /// Tests the implementation of the `SendFrame` for `io::Write` types when multiple
    /// frames are written to the same stream.
    #[test]
    fn test_send_frame_for_io_write_multiple() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
            HttpFrame::DataFrame(DataFrame::new(1)),
            HttpFrame::DataFrame(DataFrame::new(3)),
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 3)),
            HttpFrame::UnknownFrame(RawFrame::from(vec![1, 2, 3, 4])),
        ];
        let mut writeable = Vec::new();
        let mut previous = 0;
        for frame in frames.into_iter() {
            let frame_serialized = match frame {
                HttpFrame::DataFrame(frame) => {
                    let ret = frame.serialize();
                    writeable.send_frame(frame).unwrap();
                    ret
                },
                HttpFrame::HeadersFrame(frame) => {
                    let ret = frame.serialize();
                    writeable.send_frame(frame).unwrap();
                    ret
                },
                HttpFrame::SettingsFrame(frame) => {
                    let ret = frame.serialize();
                    writeable.send_frame(frame).unwrap();
                    ret
                },
                HttpFrame::UnknownFrame(frame) => {
                    let ret = frame.serialize();
                    writeable.send_raw_frame(frame).unwrap();
                    ret
                },
            };
            assert_eq!(&writeable[previous..], &frame_serialized[..]);
            previous = writeable.len();
        }
    }

    /// Tests that trying to send a frame on a closed transport stream results in an error.
    /// (i.e. an error returned by the underlying `io::Write` is propagated).
    #[test]
    fn test_send_frame_closed_stream() {
        let mut stream = StubTransportStream::with_stub_content(&vec![]);
        stream.close().unwrap();

        let res = stream.send_frame(HeadersFrame::new(vec![], 1));

        assert!(res.is_err());
    }

    /// Tests that the implementation of `ReceiveFrame` for `TransportStream` types
    /// works correctly.
    #[test]
    fn test_recv_frame_for_transport_stream() {
        let unknown_frame = RawFrame::from_buf(&{
            let mut buf: Vec<u8> = Vec::new();
            // Frame type 10 with a payload of length 1 on stream 1
            let header = (1u32, 10u8, 0u8, 1u32);
            buf.extend(pack_header(&header).to_vec().into_iter());
            buf.push(1);
            buf
        }).unwrap();
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
            HttpFrame::DataFrame(DataFrame::new(1)),
            HttpFrame::DataFrame(DataFrame::new(3)),
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 3)),
            HttpFrame::UnknownFrame(unknown_frame),
        ];
        let mut stream = StubTransportStream::with_stub_content(&build_stub_from_frames(&frames));

        for frame in frames.into_iter() {
            assert_eq!(frame, stream.recv_frame().unwrap());
        }
        // Attempting to read after EOF yields an error
        assert!(stream.recv_frame().is_err());
    }

    /// Tests that the implementation of `ReceiveFrame` for `TransportStream` types
    /// works correctly when faced with an incomplete frame.
    #[test]
    fn test_recv_frame_for_transport_stream_incomplete_frame() {
        let frame = {
            let mut frame = DataFrame::new(1);
            frame.data = vec![1, 2, 3];
            frame
        };
        let serialized: Vec<u8> = frame.serialize();

        {
            // Incomplete header
            let mut stream = StubTransportStream::with_stub_content(&serialized[..5]);

            assert!(stream.recv_frame().is_err());
        }
        {
            // Incomplete data
            let mut stream = StubTransportStream::with_stub_content(&serialized[..10]);

            assert!(stream.recv_frame().is_err());
        }
    }

    /// Tests that when an invalid, yet syntactically correct, frame is read from the stream,
    /// a corresponding error is returned.
    #[test]
    fn test_recv_frame_invalid() {
        // A DATA header which is attached to stream 0
        let serialized = HeadersFrame::new(vec![], 0).serialize();
        let mut stream = StubTransportStream::with_stub_content(&serialized);

        assert_eq!(stream.recv_frame().err().unwrap(), HttpError::InvalidFrame);
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

        let unknown_frame = RawFrame::from_buf(&{
            let mut buf: Vec<u8> = Vec::new();
            // Frame type 10 with a payload of length 1 on stream 1
            let header = (1u32, 10u8, 0u8, 1u32);
            buf.extend(pack_header(&header).to_vec().into_iter());
            buf.push(1);
            buf
        }).unwrap();
        assert!(match HttpFrame::from_raw(unknown_frame) {
            Ok(HttpFrame::UnknownFrame(_)) => true,
            _ => false,
        });

        // Invalid since it's headers on stream 0
        let invalid_frame = HeadersFrame::new(vec![], 0);
        assert!(HttpFrame::from_raw(to_raw(invalid_frame)).is_err());
    }

    /// Tests that the `write_preface` function correctly writes a client preface to
    /// a given `io::Write`.
    #[test]
    fn test_write_preface() {
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

    /// Tests that it is possible to read a single frame from the stream.
    #[test]
    fn test_read_single_frame() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
        ];
        let mut conn = build_mock_http_conn(frames.clone());

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
        let mut conn = build_mock_http_conn(frames.clone());

        let actual: Vec<_> = (0..frames.len()).map(|_| conn.recv_frame().ok().unwrap())
                                      .collect();

        assert_eq!(actual, frames);
    }

    /// Tests that when reading from a stream that initially contains no data,
    /// an `IoError` is returned.
    #[test]
    fn test_read_no_data() {
        let mut conn = build_mock_http_conn(vec![]);

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
        let mut conn = build_mock_http_conn(frames.clone());

        let _: Vec<_> = (0..frames.len()).map(|_| conn.recv_frame().ok().unwrap())
                                      .collect();
        let res = conn.recv_frame();

        assert!(match res.err().unwrap() {
            HttpError::IoError(_) => true,
            _ => false,
        });
    }

    /// Tests that when reading a frame with a header that indicates an unknown frame type, the
    /// frame is still returned wrapped in an `HttpFrame::UnknownFrame` variant.
    #[test]
    fn test_read_unknown_frame() {
        let unknown_frame = RawFrame::from_buf(&{
            let mut buf: Vec<u8> = Vec::new();
            // Frame type 10 with a payload of length 1 on stream 1
            let header = (1u32, 10u8, 0u8, 1u32);
            buf.extend(pack_header(&header).to_vec().into_iter());
            buf.push(1);
            buf
        }).unwrap();
        let mut conn = build_mock_http_conn(vec![HttpFrame::UnknownFrame(unknown_frame)]);

        // Unknown frame
        assert!(match conn.recv_frame() {
            Ok(HttpFrame::UnknownFrame(_)) => true,
            _ => false,
        });
    }

    /// Tests that it is possible to write a single frame to the connection.
    #[test]
    fn test_write_single_frame() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
        ];
        let expected = frames.clone();
        let mut conn = build_mock_http_conn(vec![]);

        for frame in frames.into_iter() {
            send_frame(&mut conn, frame).unwrap();
        }

        assert_eq!(expected, conn.sender.sent);
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
        let expected = frames.clone();
        let mut conn = build_mock_http_conn(vec![]);

        for frame in frames.into_iter() {
            send_frame(&mut conn, frame).unwrap();
        }

        assert_eq!(expected, conn.sender.sent);
    }

    /// Tests that `HttpConnection::send_headers` correctly sends the given headers when they can
    /// fit into a single frame's payload.
    #[test]
    fn test_send_headers_single_frame() {
        fn assert_correct_headers(headers: &[(Vec<u8>, Vec<u8>)], frame: &HeadersFrame) {
            let buf = &frame.header_fragment;
            let frame_headers = hpack::Decoder::new().decode(buf).unwrap();
            assert_eq!(headers, &frame_headers[..]);
        }
        let headers: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (b":method".to_vec(), b"GET".to_vec()),
            (b":scheme".to_vec(), b"http".to_vec()),
        ];
        {
            let mut conn = build_mock_http_conn(vec![]);

            // Headers when the stream should be closed
            conn.send_headers(&headers[..], 1, true).unwrap();

            // Only 1 frame sent?
            assert_eq!(conn.sender.sent.len(), 1);
            // The headers frame?
            let frame = match conn.sender.sent.remove(0) {
                HttpFrame::HeadersFrame(frame) => frame,
                _ => panic!("Headers frame not sent"),
            };
            // We sent a headers frame with end of headers and end of stream flags
            assert!(frame.is_headers_end());
            assert!(frame.is_end_of_stream());
            // And the headers were also correct -- just for good measure.
            assert_correct_headers(&headers, &frame);
        }
        {
            let mut conn = build_mock_http_conn(vec![]);

            // Headers when the stream should be left open
            conn.send_headers(&headers[..], 1, false).unwrap();

            // Only 1 frame sent?
            assert_eq!(conn.sender.sent.len(), 1);
            // The headers frame?
            let frame = match conn.sender.sent.remove(0) {
                HttpFrame::HeadersFrame(frame) => frame,
                _ => panic!("Headers frame not sent"),
            };
            assert!(frame.is_headers_end());
            // ...but it's not the end of the stream
            assert!(!frame.is_end_of_stream());
            assert_correct_headers(&headers, &frame);
        }
        {
            let mut conn = build_mock_http_conn(vec![]);

            // Make sure it's all peachy when we give a `Vec` instead of a slice
            conn.send_headers(headers.clone(), 1, true).unwrap();

            // Only 1 frame sent?
            assert_eq!(conn.sender.sent.len(), 1);
            // The headers frame?
            let frame = match conn.sender.sent.remove(0) {
                HttpFrame::HeadersFrame(frame) => frame,
                _ => panic!("Headers frame not sent"),
            };
            // We sent a headers frame with end of headers and end of stream flags
            assert!(frame.is_headers_end());
            assert!(frame.is_end_of_stream());
            // And the headers were also correct -- just for good measure.
            assert_correct_headers(&headers, &frame);
        }
    }

    /// Tests that `HttpConnection::send_data` correctly sends the given data when it can fit into
    /// a single frame's payload.
    #[test]
    fn test_send_data_single_frame() {
        {
            // Data shouldn't end the stream...
            let mut conn = build_mock_http_conn(vec![]);
            let data: &[u8] = b"1234";

            conn.send_data(data, 1, false).unwrap();

            // Only 1 frame sent?
            assert_eq!(conn.sender.sent.len(), 1);
            // A data frame?
            let frame = match conn.sender.sent.remove(0) {
                HttpFrame::DataFrame(frame) => frame,
                _ => panic!("Data frame not sent"),
            };
            assert_eq!(&frame.data[..], data);
            assert!(!frame.is_end_of_stream());
        }
        {
            // Data should end the stream...
            let mut conn = build_mock_http_conn(vec![]);
            let data: &[u8] = b"1234";

            conn.send_data(data, 1, true).unwrap();

            // Only 1 frame sent?
            assert_eq!(conn.sender.sent.len(), 1);
            // A data frame?
            let frame = match conn.sender.sent.remove(0) {
                HttpFrame::DataFrame(frame) => frame,
                _ => panic!("Data frame not sent"),
            };
            assert_eq!(&frame.data[..], data);
            assert!(frame.is_end_of_stream());
        }
        {
            // given a `Vec` we're good too?
            let mut conn = build_mock_http_conn(vec![]);
            let data: &[u8] = b"1234";

            conn.send_data(data.to_vec(), 1, true).unwrap();

            // Only 1 frame sent?
            assert_eq!(conn.sender.sent.len(), 1);
            // A data frame?
            let frame = match conn.sender.sent.remove(0) {
                HttpFrame::DataFrame(frame) => frame,
                _ => panic!("Data frame not sent"),
            };
            assert_eq!(&frame.data[..], data);
            assert!(frame.is_end_of_stream());
        }
    }

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

    /// Tests that the `HttpConnection` correctly notifies the session on a
    /// new headers frame, with no continuation.
    #[test]
    fn test_http_conn_notifies_session_header() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
        ];
        let mut conn = build_mock_http_conn(frames);
        let mut session = TestSession::new();

        conn.handle_next_frame(&mut session).unwrap();

        // A poor man's mock...
        // The header callback was called
        assert_eq!(session.curr_header, 1);
        // ...no chunks were seen.
        assert_eq!(session.curr_chunk, 0);
    }

    /// Tests that the `HttpConnection` correctly notifies the session on
    /// a new data chunk.
    #[test]
    fn test_http_conn_notifies_session_data() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::DataFrame(DataFrame::new(1)),
        ];
        let mut conn = build_mock_http_conn(frames);
        let mut session = TestSession::new();

        conn.handle_next_frame(&mut session).unwrap();

        // A poor man's mock...
        // The header callback was not called
        assert_eq!(session.curr_header, 0);
        // and exactly one chunk seen.
        assert_eq!(session.curr_chunk, 1);
    }

    /// Tests that the session gets the correct values for the headers and data
    /// from the `HttpConnection` when multiple frames are handled.
    #[test]
    fn test_http_conn_session_gets_headers_data_values() {
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
        let mut conn = build_mock_http_conn(frames);
        let mut session = TestSession::new_verify(
                vec![headers],
                vec![b"".to_vec(), b"1234".to_vec()]);

        conn.handle_next_frame(&mut session).unwrap();
        conn.handle_next_frame(&mut session).unwrap();
        conn.handle_next_frame(&mut session).unwrap();

        // Two chunks and one header processed?
        assert_eq!(session.curr_chunk, 2);
        assert_eq!(session.curr_header, 1);
    }

    /// Tests that the `HttpConnection::expect_settings` method works correctly.
    #[test]
    fn test_http_conn_expect_settings() {
        {
            // The next frame is indeed a settings frame.
            let frames = vec![HttpFrame::SettingsFrame(SettingsFrame::new())];
            let mut conn = build_mock_http_conn(frames);
            assert!(conn.expect_settings(&mut TestSession::new()).is_ok());
        }
        {
            // The next frame is a data frame...
            let frames = vec![HttpFrame::DataFrame(DataFrame::new(1))];
            let mut conn = build_mock_http_conn(frames);
            assert!(conn.expect_settings(&mut TestSession::new()).is_err());
        }
        {
            // The next frame is an ACK settings frame
            let frames = vec![HttpFrame::SettingsFrame(SettingsFrame::new_ack())];
            let mut conn = build_mock_http_conn(frames);
            assert!(conn.expect_settings(&mut TestSession::new()).is_err());
        }
    }
}
