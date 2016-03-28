//! The module contains a number of reusable components for implementing the client side of an
//! HTTP/2 connection.

use std::net::TcpStream;
use std::io;
use std::fmt;
use std::error;

use http::{HttpScheme, HttpResult, StreamId, Header, HttpError, ErrorCode};
use http::transport::TransportStream;
use http::frame::{SettingsFrame, HttpSetting, FrameIR, PingFrame};
use http::connection::{SendFrame, ReceiveFrame, SendStatus, HttpConnection, EndStream};
use http::session::{Session, Stream, DefaultStream, DefaultSessionState, SessionState};
use http::session::Client as ClientMarker;
use http::priority::SimplePrioritizer;
use http::flow_control::{WindowUpdateStrategy, NoFlowControlStrategy, WindowUpdateAction};

#[cfg(feature="tls")]
pub mod tls;

#[cfg(test)] mod tests;

/// Writes the client preface to the given `io::Write` instance.
///
/// According to the HTTP/2 spec, a client preface is first a specific sequence of octets, followed
/// by a settings frame.
///
/// This helper method can be utilized by different transport layer implementations to prepare the
/// preface that needs to be written before initializing an `HttpConnection` instance.
///
/// # Returns
///
/// Any error raised by the underlying `io::Write` instance is propagated.
pub fn write_preface<W: io::Write>(stream: &mut W) -> Result<(), io::Error> {
    // The first part of the client preface is always this sequence of 24
    // raw octets.
    let preface = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    try!(stream.write_all(preface));

    // It is followed by the client's settings.
    // TODO: It doesn't really make sense to have the initial settings be sent here, outside of the
    //       HttpConnection/Session. This should be moved to the initialization of the session!
    let settings = {
        let mut frame = SettingsFrame::new();
        frame.add_setting(HttpSetting::EnablePush(0));
        frame
    };
    let mut buf = io::Cursor::new(Vec::with_capacity(16));
    try!(settings.serialize_into(&mut buf));
    try!(stream.write_all(buf.get_ref()));
    debug!("Sent client preface");

    Ok(())
}

/// A convenience wrapper type that represents an established client network transport stream.
/// It wraps the stream itself, the scheme of the protocol to be used, and the remote
/// host name.
pub struct ClientStream<TS: TransportStream>(pub TS, pub HttpScheme, pub String);

/// A marker trait for errors raised by attempting to establish an HTTP/2
/// connection.
pub trait HttpConnectError: error::Error + Send + Sync {}

impl<E> From<E> for HttpError
    where E: HttpConnectError + 'static
{
    fn from(e: E) -> HttpError {
        HttpError::Other(Box::new(e))
    }
}

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
    type Err: HttpConnectError + 'static;

    /// Establishes a network connection that can be used by HTTP/2 connections.
    fn connect(self) -> Result<ClientStream<Self::Stream>, Self::Err>;
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
        CleartextConnector {
            host: host,
            port: 80,
        }
    }

    /// Creates a new `CleartextConnector` that will attempt to establish a connection to the given
    /// host on the given port.
    pub fn with_port(host: &'a str, port: u16) -> CleartextConnector {
        CleartextConnector {
            host: host,
            port: port,
        }
    }
}

/// A newtype wrapping the `io::Error`, as it occurs when attempting to
/// establish an HTTP/2 connection over cleartext TCP (with prior knowledge).
#[derive(Debug)]
pub struct CleartextConnectError(io::Error);

impl fmt::Display for CleartextConnectError {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        write!(fmt,
               "Cleartext HTTP/2 connect error: {}",
               (self as &error::Error).description())
    }
}

impl error::Error for CleartextConnectError {
    fn description(&self) -> &str {
        self.0.description()
    }

    fn cause(&self) -> Option<&error::Error> {
        self.0.cause()
    }
}

/// For convenience we make sure that `io::Error`s are easily convertible to
/// the `CleartextConnectError`, if needed.
impl From<io::Error> for CleartextConnectError {
    fn from(e: io::Error) -> CleartextConnectError {
        CleartextConnectError(e)
    }
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
pub struct RequestStream<'n, 'v, S>
    where S: Stream
{
    /// The list of headers that will be sent with the request.
    pub headers: Vec<Header<'n, 'v>>,
    /// The underlying `Stream` instance, which will handle the response, as well as optionally
    /// provide the body of the request.
    pub stream: S,
}

/// The struct extends the `HttpConnection` API with client-specific methods (such as
/// `start_request`) and wires the `HttpConnection` to the client `Session` callbacks.
pub struct ClientConnection<State = DefaultSessionState<ClientMarker, DefaultStream>>
    where State: SessionState
{
    /// The underlying `HttpConnection` that will be used for any HTTP/2
    /// communication.
    conn: HttpConnection,
    /// The state of the session associated to this client connection. Maintains the status of the
    /// connection streams.
    pub state: State,
}

impl<State> ClientConnection<State>
    where State: SessionState
{
    /// Creates a new `ClientConnection` that will use the given `HttpConnection`
    /// for all its underlying HTTP/2 communication.
    ///
    /// The given `state` instance will handle the maintenance of the session's state.
    pub fn with_connection(conn: HttpConnection, state: State) -> ClientConnection<State> {
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

    /// Handles the next frame provided by the given frame receiver and expects it to be a
    /// `SETTINGS` frame. If it is not, it returns an error.
    ///
    /// The method is a convenience method that can be used during the initialization of the
    /// connection, as the first frame that any peer is allowed to send is an initial settings
    /// frame.
    pub fn expect_settings<Recv: ReceiveFrame, Sender: SendFrame>(&mut self,
                                                                  rx: &mut Recv,
                                                                  tx: &mut Sender)
                                                                  -> HttpResult<()> {
        let mut session = ClientSession::new(&mut self.state, tx);
        self.conn.expect_settings(rx, &mut session)
    }

    /// Starts a new request based on the given `RequestStream`.
    ///
    /// For now it does not perform any validation whether the given `RequestStream` is valid.
    pub fn start_request<S: SendFrame>(&mut self,
                                       req: RequestStream<State::Stream>,
                                       sender: &mut S)
                                       -> HttpResult<StreamId> {
        let end_stream = if req.stream.is_closed_local() {
            EndStream::Yes
        } else {
            EndStream::No
        };
        let stream_id = self.state.insert_outgoing(req.stream);
        try!(self.conn.sender(sender).send_headers(req.headers, stream_id, end_stream));

        Ok(stream_id)
    }

    /// Send a PING
    pub fn send_ping<S: SendFrame>(&mut self, sender: &mut S) -> HttpResult<()> {
        try!(self.conn.sender(sender).send_ping(0));
        Ok(())
    }

    /// Fully handles the next incoming frame provided by the given `ReceiveFrame` instance.
    /// Handling a frame may cause changes to the session state exposed by the `ClientConnection`.
    pub fn handle_next_frame<Recv: ReceiveFrame, Sender: SendFrame>(&mut self,
                                                                    rx: &mut Recv,
                                                                    tx: &mut Sender)
                                                                    -> HttpResult<()> {
        let mut session = ClientSession::new(&mut self.state, tx);
        self.conn.handle_next_frame(rx, &mut session)
    }

    /// Queues a new DATA frame onto the underlying `SendFrame`.
    ///
    /// Currently, no prioritization of streams is taken into account and which stream's data is
    /// queued cannot be relied on.
    pub fn send_next_data<S: SendFrame>(&mut self, sender: &mut S) -> HttpResult<SendStatus> {
        debug!("Sending next data...");
        // A default "maximum" chunk size of 8 KiB is set on all data frames.
        const MAX_CHUNK_SIZE: usize = 8 * 1024;
        let mut buf = [0; MAX_CHUNK_SIZE];

        let mut prioritizer = SimplePrioritizer::new(&mut self.state, &mut buf);
        self.conn.sender(sender).send_next_data(&mut prioritizer)
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
pub struct ClientSession<'a, State, S>
    where State: SessionState + 'a,
          S: SendFrame + 'a
{
    state: &'a mut State,
    sender: &'a mut S,
    window_update_strategy: Option<&'a mut WindowUpdateStrategy>,
}

impl<'a, State, S> ClientSession<'a, State, S>
    where State: SessionState + 'a,
          S: SendFrame + 'a
{
    /// Returns a new `ClientSession` associated to the given state.
    #[inline]
    pub fn new(state: &'a mut State, sender: &'a mut S) -> ClientSession<'a, State, S> {
        ClientSession {
            state: state,
            sender: sender,
            window_update_strategy: None,
        }
    }

    /// Creates a new `ClientSession` associated to the given state, which uses the given
    /// `WindowUpdateStrategy` to decide how the flow control windows should be updated.
    pub fn with_window_update_strategy(state: &'a mut State,
                                       sender: &'a mut S,
                                       window_update_strategy: &'a mut WindowUpdateStrategy)
                                       -> ClientSession<'a, State, S> {
        ClientSession {
            state: state,
            sender: sender,
            window_update_strategy: Some(window_update_strategy),
        }
    }
}

impl<'a, State, S> Session for ClientSession<'a, State, S>
    where State: SessionState + 'a,
          S: SendFrame + 'a
{
    fn new_data_chunk(&mut self,
                      stream_id: StreamId,
                      data: &[u8],
                      _: &mut HttpConnection)
                      -> HttpResult<()> {
        debug!("Data chunk for stream {}", stream_id);
        let mut stream = match self.state.get_stream_mut(stream_id) {
            None => {
                debug!("Received a frame for an unknown stream!");
                // TODO(mlalic): This can currently indicate two things:
                //                 1) the stream was idle => PROTOCOL_ERROR
                //                 2) the stream was closed => STREAM_CLOSED (stream error)
                return Ok(());
            }
            Some(stream) => stream,
        };
        // Now let the stream handle the data chunk
        stream.new_data_chunk(data);

        Ok(())
    }

    fn new_headers<'n, 'v>(&mut self,
                           stream_id: StreamId,
                           headers: Vec<Header<'n, 'v>>,
                           _conn: &mut HttpConnection)
                           -> HttpResult<()> {
        debug!("Headers for stream {}", stream_id);
        let mut stream = match self.state.get_stream_mut(stream_id) {
            None => {
                debug!("Received a frame for an unknown stream!");
                // TODO(mlalic): This means that the server's header is not associated to any
                //               request made by the client nor any server-initiated stream (pushed)
                return Ok(());
            }
            Some(stream) => stream,
        };
        // Now let the stream handle the headers
        stream.set_headers(headers);
        Ok(())
    }

    fn end_of_stream(&mut self, stream_id: StreamId, _: &mut HttpConnection) -> HttpResult<()> {
        debug!("End of stream {}", stream_id);
        let mut stream = match self.state.get_stream_mut(stream_id) {
            None => {
                debug!("Received a frame for an unknown stream!");
                return Ok(());
            }
            Some(stream) => stream,
        };
        // Since this implies that the server has closed the stream (i.e. provided a response), we
        // close the local end of the stream, as well as the remote one; there's no need to keep
        // sending out the request body if the server's decided that it doesn't want to see it.
        stream.close();
        Ok(())
    }

    fn rst_stream(&mut self,
                  stream_id: StreamId,
                  error_code: ErrorCode,
                  _: &mut HttpConnection)
                  -> HttpResult<()> {
        debug!("RST_STREAM id={:?}, error={:?}", stream_id, error_code);
        self.state.get_stream_mut(stream_id).map(|stream| stream.on_rst_stream(error_code));
        Ok(())
    }

    fn new_settings(&mut self,
                    _settings: Vec<HttpSetting>,
                    conn: &mut HttpConnection)
                    -> HttpResult<()> {
        debug!("Sending a SETTINGS ack");
        conn.sender(self.sender).send_settings_ack()
    }

    fn on_ping(&mut self, ping: &PingFrame, conn: &mut HttpConnection) -> HttpResult<()> {
        debug!("Sending a PING ack");
        conn.sender(self.sender).send_ping_ack(ping.opaque_data())
    }

    fn on_pong(&mut self, _ping: &PingFrame, _conn: &mut HttpConnection) -> HttpResult<()> {
        debug!("Received a PING ack");
        Ok(())
    }

    fn on_connection_in_window_decrease(&mut self, conn: &mut HttpConnection) -> HttpResult<()> {
        // The default reaction to the inbound window decreasing is to ask the window update
        // strategy what should be done; if the window should be increased, emit the
        // appropriate window update frame.

        let new = conn.in_window_size();
        let conn_update = match self.window_update_strategy.as_mut() {
            Some(strategy) => {
                strategy.on_connection_window(new)
            }
            None => {
                NoFlowControlStrategy::new().on_connection_window(new)
            }
        };
        if let WindowUpdateAction::Increment(delta) = conn_update {
            try!(conn.increase_connection_window_size(delta));
            try!(conn.sender(self.sender).send_connection_window_update(delta));
        }

        Ok(())
    }

    fn on_stream_in_window_decrease(&mut self,
                                    stream_id: StreamId,
                                    size: u32,
                                    conn: &mut HttpConnection)
                                    -> HttpResult<()> {
        // TODO: Get rid of the assert.
        debug_assert!(size <= 0x7fffffff);
        let size: i32 = size as i32;

        if let Some(e) = self.state.get_entry_mut(stream_id) {
            if e.inbound_window().can_accept(size) {
                // First do the actual window update...
                let old = *e.inbound_window();
                e.inbound_window_mut().try_decrease(size)
                                      .ok()
                                      .expect("Already checked that no overflow can happen");
                let new = *e.inbound_window();
                trace!("Stream window update: stream_id={:?}, old={:?}, new={:?}",
                       stream_id,
                       old,
                       new);

                // Now, check if the window update strategy mandates an increase in the window
                // size.
                let stream_update = match self.window_update_strategy.as_mut() {
                    Some(mut strategy) => {
                        strategy.on_stream_window(stream_id, new)
                    }
                    None => {
                        NoFlowControlStrategy::new().on_stream_window(stream_id, new)
                    }
                };
                if let WindowUpdateAction::Increment(delta) = stream_update {
                    if let Err(_) = e.inbound_window_mut().try_increase(delta) {
                        // TODO: Should we perhaps propagate this error upward?
                        warn!("Misbehaving WindowUpdateStrategy would overflow the window size");
                    } else {
                        try!(conn.sender(self.sender).send_stream_window_update(stream_id, delta));
                    }
                }
            } else {
                // This would violate the flow control for the stream.
                let err = ErrorCode::FlowControlError;
                e.stream_mut().on_stream_error(err);
                try!(conn.sender(self.sender).rst_stream(stream_id, err));
            }
        }

        Ok(())
    }
}

