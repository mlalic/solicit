//! Defines the interface for the session-level management of HTTP/2
//! communication. This is effectively an API that allows hooking into an
//! HTTP/2 connection in order to handle events arising on the connection.
use super::{StreamId, Header};

/// A trait that defines methods that need to be defined in order to track the
/// status of a `ClientConnection`.
///
/// These methods are effectively callbacks that the `ClientConnection` invokes
/// on particular events in the HTTP/2 frame stream.
///
/// TODO Allow the session to influence the `ClientConnection` state and raise
///      errors (i.e. make the return type -> HttpResult<()>.
pub trait Session {
    /// Notifies the `Session` that a new data chunk has arrived on the
    /// connection for a particular stream. Only the raw data is passed
    /// to the callback (all padding is already discarded by the connection).
    fn new_data_chunk(&mut self, stream_id: StreamId, data: &[u8]);
    /// Notifies the `Session` that headers have arrived for a particular
    /// stream. The given list of headers is already decoded by the connection.
    fn new_headers(&mut self, stream_id: StreamId, headers: Vec<Header>);
    /// Notifies the `Session` that a particular stream got closed by the peer.
    fn end_of_stream(&mut self, stream_id: StreamId);
}

/// A trait representing a single HTTP/2 client stream. An HTTP/2 connection
/// multiplexes a number of streams.
///
/// The trait defines which operations need to be defined by a type that should
/// be useable as an HTTP/2 stream. By implementing this trait, clients can only
/// implement stream-level logic, such as how the received data should be handled,
/// instead of tracking which streams exist and what their states are.
pub trait Stream {
    /// Create a new stream with the given ID
    fn new(stream_id: StreamId) -> Self;
    /// Handle a new data chunk that has arrived for the stream.
    fn new_data_chunk(&mut self, data: &[u8]);
    /// Set headers for a stream. A stream is only allowed to have one set of
    /// headers.
    fn set_headers(&mut self, headers: Vec<Header>);
    /// Close the stream.
    fn close(&mut self);

    /// Returns the ID of the stream.
    fn id(&self) -> StreamId;
    /// Returns whether the stream is closed.
    fn is_closed(&self) -> bool;
}
