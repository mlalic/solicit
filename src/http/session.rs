//! Defines the interface for the session-level management of HTTP/2
//! communication. This is effectively an API that allows hooking into an
//! HTTP/2 connection in order to handle events arising on the connection.
//!
//! The module also provides a default implementation for some of the traits.
use std::marker::PhantomData;
use std::collections::HashMap;
use std::error::Error;
use std::io::Read;
use std::io::Cursor;
use std::iter::FromIterator;
use http::{StreamId, OwnedHeader, Header, HttpResult, ErrorCode, HttpError, ConnectionError,
           DEFAULT_MAX_WINDOW_SIZE, WindowSize};
use http::frame::{HttpSetting, PingFrame};
use http::connection::HttpConnection;

/// A trait that defines the interface between an `HttpConnection` and the higher-levels that use
/// it. Essentially, it allows the `HttpConnection` to pass information onto those higher levels
/// through a well-defined interface.
///
/// These methods are effectively a set of callbacks that the `HttpConnection` invokes when the
/// corresponding events arise on the HTTP/2 connection (i.e. frame stream).
pub trait Session {
    /// Notifies the `Session` that a new data chunk has arrived on the
    /// connection for a particular stream. Only the raw data is passed
    /// to the callback (all padding is already discarded by the connection).
    fn new_data_chunk(&mut self,
                      stream_id: StreamId,
                      data: &[u8],
                      conn: &mut HttpConnection)
                      -> HttpResult<()>;
    /// Notifies the `Session` that headers have arrived for a particular
    /// stream. The given list of headers is already decoded by the connection.
    /// TODO: The Session should be notified separately for every header that is decoded.
    fn new_headers<'n, 'v>(&mut self,
                           stream_id: StreamId,
                           headers: Vec<Header<'n, 'v>>,
                           conn: &mut HttpConnection)
                           -> HttpResult<()>;
    /// Notifies the `Session` that a particular stream got closed by the peer.
    fn end_of_stream(&mut self, stream_id: StreamId, conn: &mut HttpConnection) -> HttpResult<()>;
    /// Notifies the `Session` that a particular stream was reset by the peer and provides the
    /// reason behind it.
    fn rst_stream(&mut self,
                  stream_id: StreamId,
                  error_code: ErrorCode,
                  conn: &mut HttpConnection)
                  -> HttpResult<()>;
    /// Notifies the `Session` that the peer has sent a new set of settings. The session itself is
    /// responsible for acknowledging the receipt of the settings.
    fn new_settings(&mut self,
                    settings: Vec<HttpSetting>,
                    conn: &mut HttpConnection)
                    -> HttpResult<()>;

    /// Notifies the `Session` that a PING request has been received. The session itself is
    /// responsible for replying with an ACK.
    fn on_ping(&mut self, ping: &PingFrame, conn: &mut HttpConnection) -> HttpResult<()>;

    /// Notifies the `Session` that a PING acknowledgement has been received.
    fn on_pong(&mut self, ping: &PingFrame, conn: &mut HttpConnection) -> HttpResult<()>;

    /// Notifies the `Session` that the peer has sent a GOAWAY frame, indicating that the
    /// connection is terminated.
    ///
    /// The default implementation simply maps the error into an appropriate
    /// HttpError::PeerConnectionError struct.
    ///
    /// Concrete `Session` implementations can override this in order to, for example, figure out
    /// which streams can be safely retried (based on the last processed stream id).
    fn on_goaway(&mut self,
                 _last_stream_id: StreamId,
                 error_code: ErrorCode,
                 debug_data: Option<&[u8]>,
                 _conn: &mut HttpConnection)
                 -> HttpResult<()> {
        Err(HttpError::PeerConnectionError(ConnectionError {
            error_code: error_code,
            debug_data: debug_data.map(|data| data.to_vec()),
        }))
    }

    /// Notifies the `Session` that the connection's outbound flow control window was updated.
    ///
    /// The default implementation of the method ignores any change.
    ///
    /// Concrete implementations can rely on this to, for example, trigger more writes on a
    /// connection that was previously blocked on flow control (rather than on socket IO).
    fn on_connection_out_window_update(&mut self, _conn: &mut HttpConnection) -> HttpResult<()> {
        Ok(())
    }

    /// Notifies the `Session` that the given stream's outbound flow control window should be
    /// updated. Unlike the `on_connection_out_window_update`, the new size is not provided, but
    /// rather the size of the increment. This is due to the fact that the `HttpConnection` does
    /// not handle individual streams, but expects the session layer to be in charge of that.
    ///
    /// The default implementation of the method ignores any change.
    fn on_stream_out_window_update(&mut self,
                                   _stream_id: StreamId,
                                   _increment: u32,
                                   _conn: &mut HttpConnection)
                                   -> HttpResult<()> {
        Ok(())
    }

    /// Notifies the `Session` that the connection-level inbound flow control window has decreased.
    /// The new value can be obtained from the given `HttpConnection` instance.
    fn on_connection_in_window_decrease(&mut self, _conn: &mut HttpConnection) -> HttpResult<()> {
        Ok(())
    }

    /// Notifies the `Session` that the given stream's inbound flow control window has decreased by
    /// the given number of octets.
    fn on_stream_in_window_decrease(
            &mut self,
            _stream_id: StreamId,
            _size: u32,
            _conn: &mut HttpConnection)
            -> HttpResult<()> {
        Ok(())
    }
}

/// A newtype for an iterator over `Stream`s saved in a `SessionState`.
///
/// Allows `SessionState` implementations to return iterators over its session without being forced
/// to declare them as associated types.
pub struct StreamIter<'a, S: Stream + 'a>(Box<Iterator<Item=(&'a StreamId, &'a mut Entry<S>)> + 'a>);

impl<'a, S> Iterator for StreamIter<'a, S>
    where S: Stream + 'a
{
    type Item = (&'a StreamId, &'a mut Entry<S>);

    #[inline]
    fn next(&mut self) -> Option<(&'a StreamId, &'a mut Entry<S>)> {
        self.0.next()
    }
}

/// A struct representing a single entry in the `SessionState`. The `Entry` represents all relevant
/// information for a single HTTP/2 stream.
pub struct Entry<S> where S: Stream {
    stream: S,
    /// Tracks the size of the outbound flow control window
    out_window: WindowSize,
    /// Tracks the size of the inbound flow control window
    in_window: WindowSize,
}

impl<S> Entry<S> where S: Stream {
    /// Create a new `Entry` with the given `Stream`
    pub fn new(stream: S) -> Entry<S> {
        Entry {
            stream: stream,
            // TODO: Use the current initial window sizes indicated by the connection settings!
            out_window: DEFAULT_MAX_WINDOW_SIZE,
            in_window: DEFAULT_MAX_WINDOW_SIZE,
        }
    }
    /// Consumes the `Entry`, returning the underlying `Stream` instance
    pub fn stream(self) -> S { self.stream }
    /// Returns a reference to the `Stream`
    pub fn stream_ref(&self) -> &S { &self.stream }
    /// Returns a mutable reference to the `Stream`
    pub fn stream_mut(&mut self) -> &mut S { &mut self.stream }

    pub fn outbound_window(&self) -> &WindowSize { &self.out_window }
    pub fn inbound_window(&self) -> &WindowSize { &self.in_window }
    pub fn inbound_window_mut(&mut self) -> &mut WindowSize { &mut self.in_window }
}

/// A trait defining a set of methods for accessing and influencing an HTTP/2 session's state.
///
/// This trait is tightly coupled to a `Stream`-based session layer implementation. Particular
/// implementations are additionally tightly coupled to one particular `Stream` implementation.
///
/// # Note
///
/// Clients built on top of the raw `HttpConnection` + `Session` can still exist without using
/// this trait; however, it is included for convenience, as most session implementations *will*
/// want to keep track of similar things in the session's state.
pub trait SessionState {
    /// The type of the `Stream` that the `SessionState` manages.
    type Stream: Stream;

    /// Inserts the given `Stream` into the session's state, starting to track it.
    /// The `SessionState` should assign it the next available outgoing stream ID.
    fn insert_outgoing(&mut self, stream: Self::Stream) -> StreamId;
    /// Inserts the given `Stream` into the session's state, considering it an incoming
    /// stream.
    /// TODO(mlalic): Allow the exact error to propagate out.
    fn insert_incoming(&mut self, id: StreamId, stream: Self::Stream) -> Result<(), ()>;
    /// Returns a reference to the `Entry` for the stream with the given id.
    fn get_entry_ref(&self, id: StreamId) -> Option<&Entry<Self::Stream>>;
    /// Returns a mutable reference to the `Entry` for the stream with the given id.
    fn get_entry_mut(&mut self, id: StreamId) -> Option<&mut Entry<Self::Stream>>;
    /// Removes the stream with the given `StreamId` from the session. If the stream was found in
    /// the session, it is returned in the result.
    fn remove_stream(&mut self, stream_id: StreamId) -> Option<Entry<Self::Stream>>;

    /// Returns an iterator over the streams currently found in the session.
    fn iter(&mut self) -> StreamIter<Self::Stream>;

    /// The number of streams tracked by this state object
    fn len(&self) -> usize;

    /// Returns a reference to a `Stream` with the given `StreamId`, if it is found in the current
    /// session.
    fn get_stream_ref(&self, stream_id: StreamId) -> Option<&Self::Stream> {
        self.get_entry_ref(stream_id).map(|e| e.stream_ref())
    }

    /// Returns a mutable reference to a `Stream` with the given `StreamId`, if it is found in the
    /// current session.
    fn get_stream_mut(&mut self, stream_id: StreamId) -> Option<&mut Self::Stream> {
        self.get_entry_mut(stream_id).map(|e| e.stream_mut())
    }

    /// Returns all streams that are closed and tracked by the session state.
    ///
    /// The streams are moved out of the session state.
    ///
    /// The default implementations relies on the `iter` implementation to find the closed streams
    /// first and then calls `remove_stream` on all of them.
    fn get_closed(&mut self) -> Vec<Entry<Self::Stream>> {
        let ids: Vec<StreamId> = self.iter()
                                     .filter_map(|(id, e)| {
                                         if e.stream_ref().is_closed() {
                                             Some(*id)
                                         } else {
                                             None
                                         }
                                     }).collect();
        FromIterator::from_iter(ids.into_iter().map(|i| self.remove_stream(i).unwrap()))
    }
}

/// A phantom type for the `DefaultSessionState` struct that indicates that the struct should be
/// geared for a client session.
pub struct Client;
/// A phantom type for the `DefaultSessionState` struct that indicates that the struct should be
/// geared for a server session.
pub struct Server;

/// The simple enum indicates the parity of an integer. Used by the `DefaultSessionState`
/// implementation to make sure that server and client sessions only accept stream IDs with the
/// correct parity (for clients outgoing stream IDs must be odd and incoming even, while for
/// servers it is the other way around).
#[derive(Debug, Clone, Copy, PartialEq)]
enum Parity {
    Even,
    Odd,
}

impl Parity {
    /// Returns the parity of the given `StreamId`.
    fn of(stream_id: StreamId) -> Parity {
        match stream_id % 2 {
            0 => Parity::Even,
            1 => Parity::Odd,
            _ => unreachable!(),
        }
    }
}

/// An implementation of the `SessionState` trait that tracks the active streams in a `HashMap`,
/// mapping the stream ID to the concrete `Stream` instance.
pub struct DefaultSessionState<T, S>
    where S: Stream
{
    /// All streams that the session state is currently aware of.
    streams: HashMap<StreamId, Entry<S>>,
    /// The next available ID for outgoing streams.
    next_stream_id: StreamId,
    /// The parity bit for outgoing connections. Client-initiated connections must always be
    /// odd-numbered, while server-initiated ones should be even. Therefore, the parity bit
    /// is `Odd` for clients' session state and `Even` for servers'.
    /// TODO It'd be better to use an associated constant to type T instead, but
    ///      `associated_consts` is feature gated for now.
    outgoing_parity: Parity,
    /// Indicates whether the session state is maintained for a client or a server session.
    _server_or_client: PhantomData<T>,
}

impl<T, S> DefaultSessionState<T, S>
    where S: Stream
{
    /// A helper function that returns `true` iff the given `StreamId` is a valid ID for an
    /// incoming stream, depending on whether the session is that of a client or a server.
    fn validate_incoming_parity(&self, stream_id: StreamId) -> bool {
        // The parity of incoming connections should be different than the parity of outgoing ones.
        Parity::of(stream_id) != self.outgoing_parity
    }
}

impl<S> DefaultSessionState<Client, S>
    where S: Stream
{
    /// Creates a new `DefaultSessionState` for a client session with no known streams.
    pub fn new() -> DefaultSessionState<Client, S> {
        DefaultSessionState {
            streams: HashMap::new(),
            next_stream_id: 1,
            outgoing_parity: Parity::Odd,
            _server_or_client: PhantomData,
        }
    }
}

impl<S> DefaultSessionState<Server, S>
    where S: Stream
{
    /// Creates a new `DefaultSessionState` for a server session with no known streams.
    pub fn new() -> DefaultSessionState<Server, S> {
        DefaultSessionState {
            streams: HashMap::new(),
            next_stream_id: 2,
            outgoing_parity: Parity::Even,
            _server_or_client: PhantomData,
        }
    }
}

/// Create a new `DefaultSessionState` for a client session.
/// This function is a workaround required due to
/// [rust-lang/rust#29023](https://github.com/rust-lang/rust/issues/29023).
pub fn default_client_state<S: Stream>() -> DefaultSessionState<Client, S> {
    DefaultSessionState::<Client, S>::new()
}
/// Create a new `DefaultSessionState` for a server session.
/// This function is a workaround required due to
/// [rust-lang/rust#29023](https://github.com/rust-lang/rust/issues/29023).
pub fn default_server_state<S: Stream>() -> DefaultSessionState<Server, S> {
    DefaultSessionState::<Server, S>::new()
}

impl<T, S> SessionState for DefaultSessionState<T, S>
    where S: Stream
{
    type Stream = S;

    fn insert_outgoing(&mut self, stream: Self::Stream) -> StreamId {
        let id = self.next_stream_id;
        self.streams.insert(id, Entry::new(stream));
        self.next_stream_id += 2;
        id
    }

    fn insert_incoming(&mut self, stream_id: StreamId, stream: Self::Stream) -> Result<(), ()> {
        if self.validate_incoming_parity(stream_id) {
            // TODO(mlalic): Assert that the stream IDs are monotonically increasing!
            self.streams.insert(stream_id, Entry::new(stream));
            Ok(())
        } else {
            Err(())
        }
    }

    fn get_entry_ref(&self, stream_id: StreamId) -> Option<&Entry<Self::Stream>> {
        self.streams.get(&stream_id)
    }

    fn get_entry_mut(&mut self, stream_id: StreamId) -> Option<&mut Entry<Self::Stream>> {
        self.streams.get_mut(&stream_id)
    }

    #[inline]
    fn remove_stream(&mut self, stream_id: StreamId) -> Option<Entry<Self::Stream>> {
        self.streams.remove(&stream_id)
    }

    #[inline]
    fn iter(&mut self) -> StreamIter<S> {
        StreamIter(Box::new(self.streams.iter_mut()))
    }

    /// Number of currently active streams
    #[inline]
    fn len(&self) -> usize {
        self.streams.len()
    }
}

/// The enum represents all the states that an HTTP/2 stream can be found in.
///
/// Corresponds to [section 5.1.](http://http2.github.io/http2-spec/#rfc.section.5.1) of the spec.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum StreamState {
    Idle,
    ReservedLocal,
    ReservedRemote,
    Open,
    HalfClosedRemote,
    HalfClosedLocal,
    Closed,
}

/// The enum represents errors that can be returned from the `Stream::get_data_chunk` method.
#[derive(Debug)]
pub enum StreamDataError {
    /// Indicates that the stream cannot provide any data, since it is closed for further writes
    /// from the peer's side.
    Closed,
    /// A different error while trying to obtain the data chunk. Wraps a boxed `Error` impl.
    Other(Box<Error + Send + Sync>),
}

impl<E> From<E> for StreamDataError
    where E: Error + Send + Sync + 'static
{
    fn from(err: E) -> StreamDataError {
        StreamDataError::Other(Box::new(err))
    }
}

/// The enum represents the successful completion of the `Stream::get_data_chunk` method.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum StreamDataChunk {
    /// A data chunk of the given size, after which more chunks can follow.
    Chunk(usize),
    /// The chunk was the last one that the stream will ever write.
    Last(usize),
    /// No data currently available, but the stream isn't closed yet
    Unavailable,
}

/// A trait representing a single HTTP/2 stream. An HTTP/2 connection multiplexes a number of
/// streams.
///
/// The trait defines which operations need to be implemented by a type that should
/// be usable as an HTTP/2 stream. By implementing this trait, clients can implement only
/// stream-level logic, such as how the received data should be handled, or which data should be
/// sent to the peer, without having to worry about the lower-level details of session and
/// connection management (e.g. handling raw frames or tracking stream status).
pub trait Stream {
    /// Handle a new data chunk that has arrived for the stream.
    fn new_data_chunk(&mut self, data: &[u8]);

    /// Set headers for a stream. A stream is only allowed to have one set of
    /// headers.
    fn set_headers<'n, 'v>(&mut self, headers: Vec<Header<'n, 'v>>);

    /// Sets the stream state to the newly provided state.
    fn set_state(&mut self, state: StreamState);

    /// Invoked when the session detects that the peer has reset the stream (i.e. sent a RST_STREAM
    /// frame for this stream).
    ///
    /// The default implementation simply closes the stream, discarding the provided error_code.
    /// Concrete `Stream` implementations can override this.
    fn on_rst_stream(&mut self, _error_code: ErrorCode) {
        self.close();
    }

    /// Notifies the `Stream` that a stream error has been detected. This differs from
    /// `on_rst_stream` in that the error was detected by the local peer, rather than the remote.
    ///
    /// The default implementation simply closes the stream.
    fn on_stream_error(&mut self, _error_code: ErrorCode) {
        self.close();
    }

    /// Places the next data chunk that should be written onto the stream into the given buffer.
    ///
    /// # Returns
    ///
    /// The returned variant of the `StreamDataChunk` enum can indicate that the returned chunk is
    /// the last one that the stream can write (the `StreamDataChunk::Last` variant).
    ///
    /// It can also indicate that the stream currently does not have any data that could be
    /// written, but it isn't closed yet, implying that at a later time some data might become
    /// available for writing (the `StreamDataChunk::Unavailable` variant).
    ///
    /// The `StreamDataChunk::Chunk` indicates that the chunk of the given length has been placed
    /// into the buffer and that more data might follow on the stream.
    fn get_data_chunk(&mut self, buf: &mut [u8]) -> Result<StreamDataChunk, StreamDataError>;

    /// Returns the current state of the stream.
    fn state(&self) -> StreamState;

    /// Transitions the stream state to closed. After this, the stream is considered to be closed
    /// for any further reads or writes.
    fn close(&mut self) {
        self.set_state(StreamState::Closed);
    }

    /// Updates the `Stream` status to indicate that it is closed locally.
    ///
    /// If the stream is closed on the remote end, then it is fully closed after this call.
    fn close_local(&mut self) {
        let next = match self.state() {
            StreamState::HalfClosedRemote => StreamState::Closed,
            _ => StreamState::HalfClosedLocal,
        };
        self.set_state(next);
    }

    /// Updates the `Stream` status to indicate that it is closed on the remote peer's side.
    ///
    /// If the stream is also locally closed, then it is fully closed after this call.
    fn close_remote(&mut self) {
        let next = match self.state() {
            StreamState::HalfClosedLocal => StreamState::Closed,
            _ => StreamState::HalfClosedRemote,
        };
        self.set_state(next);
    }

    /// Returns whether the stream is closed.
    ///
    /// A stream is considered to be closed iff its state is set to `Closed`.
    fn is_closed(&self) -> bool {
        self.state() == StreamState::Closed
    }

    /// Returns whether the stream is closed locally.
    fn is_closed_local(&self) -> bool {
        match self.state() {
            StreamState::HalfClosedLocal | StreamState::Closed => true,
            _ => false,
        }
    }

    /// Returns whether the remote peer has closed the stream. This includes a fully closed stream.
    fn is_closed_remote(&self) -> bool {
        match self.state() {
            StreamState::HalfClosedRemote | StreamState::Closed => true,
            _ => false,
        }
    }
}

/// An implementation of the `Stream` trait that saves all headers and data
/// in memory.
///
/// Stores its outgoing data as a `Vec<u8>`.
#[derive(Clone)]
pub struct DefaultStream {
    /// The ID of the stream, if already assigned by the connection.
    pub stream_id: Option<StreamId>,
    /// The headers associated with the stream (i.e. the response headers)
    pub headers: Option<Vec<Header<'static, 'static>>>,
    /// The body of the stream (i.e. the response body)
    pub body: Vec<u8>,
    /// The current stream state.
    pub state: StreamState,
    /// The outgoing data associated to the stream. The `Cursor` points into the `Vec` at the
    /// position where the data has been sent out.
    data: Option<Cursor<Vec<u8>>>,
}

impl DefaultStream {
    /// Create a new `DefaultStream`, where the ID is not yet assigned.
    pub fn new() -> DefaultStream {
        DefaultStream {
            stream_id: None,
            headers: None,
            body: Vec::new(),
            state: StreamState::Open,
            data: None,
        }
    }

    /// Create a new `DefaultStream` with the given ID.
    pub fn with_id(stream_id: StreamId) -> DefaultStream {
        DefaultStream {
            stream_id: Some(stream_id),
            headers: None,
            body: Vec::new(),
            state: StreamState::Open,
            data: None,
        }
    }

    /// Sets the outgoing data of the stream to the given `Vec`.
    ///
    /// Any previously associated (and perhaps unwritten) data is discarded.
    #[inline]
    pub fn set_full_data(&mut self, data: Vec<u8>) {
        self.data = Some(Cursor::new(data));
    }
}

impl Stream for DefaultStream {
    fn new_data_chunk(&mut self, data: &[u8]) {
        self.body.extend(data.to_vec().into_iter());
    }

    fn set_headers<'n, 'v>(&mut self, headers: Vec<Header<'n, 'v>>) {
        let new_headers = headers.into_iter().map(|h| {
            let owned: OwnedHeader = h.into();
            owned.into()
        });

        self.headers = match self.headers.take() {
            Some(mut x) => {
                x.extend(new_headers);
                Some(x)
            }
            None => Some(new_headers.collect()),
        };
    }

    fn set_state(&mut self, state: StreamState) {
        self.state = state;
    }

    fn state(&self) -> StreamState {
        self.state
    }

    fn get_data_chunk(&mut self, buf: &mut [u8]) -> Result<StreamDataChunk, StreamDataError> {
        if self.is_closed_local() {
            return Err(StreamDataError::Closed);
        }
        let chunk = match self.data.as_mut() {
            // No data associated to the stream, but it's open => nothing available for writing
            None => StreamDataChunk::Unavailable,
            Some(d) => {
                let read = try!(d.read(buf));
                if (d.position() as usize) == d.get_ref().len() {
                    StreamDataChunk::Last(read)
                } else {
                    StreamDataChunk::Chunk(read)
                }
            }
        };
        // Transition the stream state to locally closed if we've extracted the final data chunk.
        if let StreamDataChunk::Last(_) = chunk {
            self.close_local()
        }

        Ok(chunk)
    }
}

#[cfg(test)]
mod tests {
    use super::{Stream, DefaultSessionState, DefaultStream, StreamDataChunk, StreamDataError,
                SessionState, Parity, StreamState};
    use super::Client as ClientMarker;
    use super::Server as ServerMarker;
    use http::{ErrorCode, Header};
    use http::tests::common::TestStream;

    /// Checks that the `Parity` struct indeed works as advertised.
    #[test]
    fn test_parity_sanity_check() {
        assert_eq!(Parity::of(1), Parity::Odd);
        assert_eq!(Parity::of(2), Parity::Even);
        assert_eq!(Parity::of(301), Parity::Odd);
        assert_eq!(Parity::of(418), Parity::Even);
    }

    /// Tests that the `DefaultSessionState` when instantiated in client-mode correctly assigns
    /// stream IDs.
    #[test]
    fn test_default_session_state_client() {
        let mut state = DefaultSessionState::<ClientMarker, TestStream>::new();
        // Outgoing streams are odd-numbered...
        assert_eq!(state.insert_outgoing(TestStream::new()), 1);
        assert_eq!(state.insert_outgoing(TestStream::new()), 3);
        // ...while incoming are only allowed to be even-numbered.
        assert!(state.insert_incoming(2, TestStream::new()).is_ok());
        assert!(state.insert_incoming(3, TestStream::new()).is_err());
    }

    /// Tests that the `DefaultSessionState` when instantiated in server-mode correctly assigns
    /// stream IDs.
    #[test]
    fn test_default_session_state_server() {
        let mut state = DefaultSessionState::<ServerMarker, TestStream>::new();
        // Outgoing streams are even-numbered...
        assert_eq!(state.insert_outgoing(TestStream::new()), 2);
        assert_eq!(state.insert_outgoing(TestStream::new()), 4);
        // ...while incoming are only allowed to be odd-numbered.
        assert!(state.insert_incoming(2, TestStream::new()).is_err());
        assert!(state.insert_incoming(3, TestStream::new()).is_ok());
    }

    /// Tests for the `DefaultSessionState` implementation of the `SessionState` trait.
    #[test]
    fn test_default_session_state() {
        fn new_mock_state() -> DefaultSessionState<ClientMarker, TestStream> {
            DefaultSessionState::<ClientMarker, _>::new()
        }

        {
            // Test insert
            let mut state = new_mock_state();
            let assigned_id = state.insert_outgoing(TestStream::new());
            assert_eq!(assigned_id, 1);
        }
        {
            // Test remove: known stream ID
            let mut state = new_mock_state();
            let id = state.insert_outgoing(TestStream::new());

            let _ = state.remove_stream(id).unwrap();
        }
        {
            // Test remove: unknown stream ID
            let mut state = new_mock_state();
            state.insert_outgoing(TestStream::new());

            assert!(state.remove_stream(101).is_none());
        }
        {
            // Test get stream -- unknown ID
            let mut state = new_mock_state();
            state.insert_outgoing(TestStream::new());
            assert!(state.get_stream_ref(3).is_none());
        }
        {
            // Test iterate
            let mut state = new_mock_state();
            state.insert_outgoing(TestStream::new());
            state.insert_outgoing(TestStream::new());
            state.insert_outgoing(TestStream::new());

            let mut stream_ids: Vec<_> = state.iter().map(|(&id, _)| id).collect();
            stream_ids.sort();

            assert_eq!(vec![1, 3, 5], stream_ids);
        }
        {
            // Test iterate on an empty state
            let mut state = new_mock_state();

            assert_eq!(state.iter().collect::<Vec<_>>().len(), 0);
        }
        {
            // Test `get_closed`
            let mut state = new_mock_state();
            state.insert_outgoing(TestStream::new());
            state.insert_outgoing(TestStream::new());
            state.insert_outgoing(TestStream::new());
            // Close some streams now
            state.get_stream_mut(1).unwrap().close();
            state.get_stream_mut(5).unwrap().close();

            let closed = state.get_closed();

            // Only one stream left
            assert_eq!(state.streams.len(), 1);
            // Both of the closed streams extracted into the `closed` Vec.
            assert_eq!(closed.len(), 2);
        }
    }

    /// Tests that the `DefaultStream` provides the correct data when its `get_data_chunk` method
    /// is called.
    #[test]
    fn test_default_stream_get_data() {
        // The buffer that will be used in upcoming tests
        let mut buf = Vec::with_capacity(2);
        unsafe {
            buf.set_len(2);
        }

        {
            // A newly open stream has no available data.
            let mut stream = DefaultStream::new();
            let res = stream.get_data_chunk(&mut buf).ok().unwrap();
            assert_eq!(res, StreamDataChunk::Unavailable);
        }
        {
            // A closed stream returns an error
            let mut stream = DefaultStream::new();
            stream.close();
            let res = stream.get_data_chunk(&mut buf).err().unwrap();
            assert!(match res {
                StreamDataError::Closed => true,
                _ => false,
            });
        }
        {
            // A locally closed stream returns an error
            let mut stream = DefaultStream::new();
            stream.close_local();
            let res = stream.get_data_chunk(&mut buf).err().unwrap();
            assert!(match res {
                StreamDataError::Closed => true,
                _ => false,
            });
        }
        {
            let mut stream = DefaultStream::new();
            stream.set_full_data(vec![1, 2, 3, 4]);

            // A stream with data returns the first full chunk
            let res = stream.get_data_chunk(&mut buf).ok().unwrap();
            assert_eq!(res, StreamDataChunk::Chunk(2));
            assert_eq!(buf, vec![1, 2]);

            // Now it returns the last chunk with the correct indicator
            let res = stream.get_data_chunk(&mut buf).ok().unwrap();
            assert_eq!(res, StreamDataChunk::Last(2));
            assert_eq!(buf, vec![3, 4]);

            // Further calls indicate that the stream is now closed locally
            let res = stream.get_data_chunk(&mut buf).err().unwrap();
            assert!(match res {
                StreamDataError::Closed => true,
                _ => false,
            });
        }
        {
            let mut stream = DefaultStream::new();
            stream.set_full_data(vec![1, 2, 3, 4, 5]);

            let res = stream.get_data_chunk(&mut buf).ok().unwrap();
            assert_eq!(res, StreamDataChunk::Chunk(2));
            assert_eq!(buf, vec![1, 2]);

            let res = stream.get_data_chunk(&mut buf).ok().unwrap();
            assert_eq!(res, StreamDataChunk::Chunk(2));
            assert_eq!(buf, vec![3, 4]);

            let res = stream.get_data_chunk(&mut buf).ok().unwrap();
            assert_eq!(res, StreamDataChunk::Last(1));
            assert_eq!(&buf[..1], &vec![5][..]);
        }
        {
            // Empty data
            let mut stream = DefaultStream::new();
            stream.set_full_data(vec![]);

            let res = stream.get_data_chunk(&mut buf).ok().unwrap();
            assert_eq!(res, StreamDataChunk::Last(0));
        }
    }

    #[test]
    fn test_default_stream_get_data_after_rst() {
        let mut buf = vec![0; 2];
        let mut stream = DefaultStream::new();
        stream.set_full_data(vec![1, 2, 3, 4, 5]);

        let res = stream.get_data_chunk(&mut buf).ok().unwrap();
        assert_eq!(res, StreamDataChunk::Chunk(2));
        assert_eq!(buf, vec![1, 2]);

        // Now signal the stream that it's been reset.
        stream.on_rst_stream(ErrorCode::Cancel);
        // The stream no longer provides data, as there's no point in sending any once it is fully
        // closed on both ends for whatever reason.
        assert!(match stream.get_data_chunk(&mut buf) {
            Err(StreamDataError::Closed) => true,
            _ => false,
        });
    }

    /// Tests that when the `DefaultStream` receives an error, it closes the stream.
    #[test]
    fn test_default_stream_on_error() {
        let mut stream = DefaultStream::new();
        stream.on_stream_error(ErrorCode::FlowControlError);
        assert_eq!(stream.state(), StreamState::Closed);
    }

    #[test]
    /// test_second_header_call will ensure that if headers are called twice in one stream (such as
    /// to set trailers) both results will be added to the stream's headers.
    fn test_second_header_call() {
        let mut stream = DefaultStream::new();

        let headers1 = vec![Header::new(b"Foo", b"Bar")];
        let headers2 = vec![Header::new(b"Baz", b"Bop")];

        stream.set_headers(headers1);
        stream.set_headers(headers2);

        assert!(stream.headers.is_some());
        let headers = stream.headers.unwrap();

        assert_eq!(headers.len(), 2);
        // These assert checks are ugly, but they make the borrow checker happy.
        assert_eq!(headers[0].clone().name.into_owned(), b"Foo");
        assert_eq!(headers[1].clone().name.into_owned(), b"Baz");

        assert_eq!(headers[0].clone().value.into_owned(), b"Bar");
        assert_eq!(headers[1].clone().value.into_owned(), b"Bop");
    }
}
