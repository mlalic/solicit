//! Defines the interface for the session-level management of HTTP/2
//! communication. This is effectively an API that allows hooking into an
//! HTTP/2 connection in order to handle events arising on the connection.
use std::collections::HashMap;
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

/// An implementation of the `Stream` trait that saves all headers and data
/// in memory.
pub struct DefaultStream {
    /// The ID of the stream
    pub stream_id: StreamId,
    /// The headers associated with the stream (i.e. the response headers)
    pub headers: Option<Vec<Header>>,
    /// The body of the stream (i.e. the response body)
    pub body: Vec<u8>,
    /// Whether the stream is already closed
    pub closed: bool,
}

impl DefaultStream {
    /// Create a new `DefaultStream` with the given ID.
    pub fn new(stream_id: StreamId) -> DefaultStream {
        DefaultStream {
            stream_id: stream_id,
            headers: None,
            body: Vec::new(),
            closed: false,
        }
    }
}

impl Stream for DefaultStream {
    fn new(stream_id: StreamId) -> DefaultStream {
        DefaultStream::new(stream_id)
    }

    fn new_data_chunk(&mut self, data: &[u8]) {
        self.body.push_all(data);
    }

    fn set_headers(&mut self, headers: Vec<Header>) {
        self.headers = Some(headers);
    }

    fn close(&mut self) {
        self.closed = true;
    }

    fn id(&self) -> StreamId {
        self.stream_id
    }

    fn is_closed(&self) -> bool {
        self.closed
    }
}

/// A simple implementation of the `Session` trait.
///
/// Keeps track of which streams are currently active by holding a `HashMap`
/// of stream IDs to `Stream` instances. Callbacks delegate to the corresponding
/// stream instance, after validating the received stream ID.
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
pub struct DefaultSession<S=DefaultStream> where S: Stream {
    streams: HashMap<StreamId, S>,
}

impl<S> DefaultSession<S> where S: Stream {
    /// Returns a new `DefaultSession` with no active streams.
    pub fn new() -> DefaultSession<S> {
        DefaultSession {
            streams: HashMap::new(),
        }
    }

    /// Returns a reference to a stream with the given ID, if such a stream is
    /// found in the `DefaultSession`.
    pub fn get_stream(&self, stream_id: StreamId) -> Option<&S> {
        self.streams.get(&stream_id)
    }

    /// Creates a new stream with the given ID in the session.
    pub fn new_stream(&mut self, stream_id: StreamId) {
        self.streams.insert(stream_id, Stream::new(stream_id));
    }
}

impl<S> Session for DefaultSession<S> where S: Stream {
    fn new_data_chunk(&mut self, stream_id: StreamId, data: &[u8]) {
        debug!("Data chunk for stream {}", stream_id);
        let mut stream = match self.streams.get_mut(&stream_id) {
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
        let mut stream = match self.streams.get_mut(&stream_id) {
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
        let mut stream = match self.streams.get_mut(&stream_id) {
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
        Session, DefaultSession,
        Stream, DefaultStream,
    };

    /// Tests that a `DefaultSession` notifies the correct stream when the
    /// appropriate callback is invoked.
    ///
    /// A better unit test would give a mock Stream to the `DefaultSession`,
    /// instead of testing both the `DefaultSession` and the `DefaultStream`
    /// in the same time...
    #[test]
    fn test_default_session_notifies_stream() {
        let mut session: DefaultSession = DefaultSession::new();
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
    }
}
