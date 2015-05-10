//! Defines the interface for the session-level management of HTTP/2
//! communication. This is effectively an API that allows hooking into an
//! HTTP/2 connection in order to handle events arising on the connection.
//!
//! It also provides a default implementation of this interface, the
//! `DefaultSession`. This implementation is based on keeping a mapping of
//! valid stream IDs to instances of `Stream` objects. When the session
//! receives a callback for a particular stream ID, it first validates that
//! it represents a valid stream ID and then delegates to the appropriate
//! action of a `Stream`. This allows clients to easily vary the stream-level
//! logic, without worrying about handling the book-keeping tasks of which
//! streams are active.
use std::collections::HashMap;
use std::iter::FromIterator;
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

/// A newtype for an iterator over `Stream`s saved in a `SessionState`.
///
/// Allows `SessionState` implementations to return iterators over its session without being forced
/// to declare them as associated types.
pub struct StreamIter<'a, S: Stream>(Box<Iterator<Item=&'a mut S> + 'a>);

impl<'a, S> Iterator for StreamIter<'a, S> where S: Stream {
    type Item = &'a mut S;

    #[inline]
    fn next(&mut self) -> Option<&'a mut S> { self.0.next() }
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
    fn insert_stream(&mut self, stream: Self::Stream);
    /// Returns a reference to a `Stream` with the given `StreamId`, if it is found in the current
    /// session.
    fn get_stream_ref(&self, stream_id: StreamId) -> Option<&Self::Stream>;
    /// Returns a mutable reference to a `Stream` with the given `StreamId`, if it is found in the
    /// current session.
    fn get_stream_mut(&mut self, stream_id: StreamId) -> Option<&mut Self::Stream>;
    /// Removes the stream with the given `StreamId` from the session. If the stream was found in
    /// the session, it is returned in the result.
    fn remove_stream(&mut self, stream_id: StreamId) -> Option<Self::Stream>;

    /// Returns an iterator over the streams currently found in the session.
    fn iter(&mut self) -> StreamIter<Self::Stream>;

    /// Returns all streams that are closed and tracked by the session state.
    ///
    /// The streams are moved out of the session state.
    ///
    /// The default implementations relies on the `iter` implementation to find the closed streams
    /// first and then calls `remove_stream` on all of them.
    fn get_closed(&mut self) -> Vec<Self::Stream> {
        let ids: Vec<_> = self.iter()
                              .filter_map(|s| {
                                  if s.is_closed() { Some(s.id()) } else { None }
                              })
                              .collect();
        FromIterator::from_iter(ids.into_iter().map(|i| self.remove_stream(i).unwrap()))
    }
}

/// An implementation of the `SessionState` trait that tracks the active streams in a `HashMap`,
/// mapping the stream ID to the concrete `Stream` instance.
pub struct DefaultSessionState<S> where S: Stream {
    /// All streams that the session state is currently aware of.
    streams: HashMap<StreamId, S>,
}

impl<S> DefaultSessionState<S> where S: Stream {
    /// Creates a new `DefaultSessionState` with no known streams.
    pub fn new() -> DefaultSessionState<S> {
        DefaultSessionState {
            streams: HashMap::new(),
        }
    }
}

impl<S> SessionState for DefaultSessionState<S> where S: Stream {
    type Stream = S;

    #[inline]
    fn insert_stream(&mut self, stream: Self::Stream) {
        self.streams.insert(stream.id(), stream);
    }

    #[inline]
    fn get_stream_ref(&self, stream_id: StreamId) -> Option<&Self::Stream> {
        self.streams.get(&stream_id)
    }
    #[inline]
    fn get_stream_mut(&mut self, stream_id: StreamId) -> Option<&mut Self::Stream> {
        self.streams.get_mut(&stream_id)
    }

    #[inline]
    fn remove_stream(&mut self, stream_id: StreamId) -> Option<Self::Stream> {
        self.streams.remove(&stream_id)
    }

    #[inline]
    fn iter(&mut self) -> StreamIter<S> {
        StreamIter(Box::new(self.streams.iter_mut().map(|(_, s)| s)))
    }
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
#[derive(Clone)]
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
        self.body.extend(data.to_vec().into_iter());
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

    /// Returns all streams that are closed and tracked by the session.
    ///
    /// The streams are moved out of the session.
    pub fn get_closed(&mut self) -> Vec<S> {
        let ids: Vec<_> = self.streams.iter()
                              .filter_map(|(i, s)| {
                                  if s.is_closed() { Some(*i) } else { None }
                              })
                              .collect();
        FromIterator::from_iter(ids.into_iter().map(|i| self.streams.remove(&i).unwrap()))
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
        Stream,
        DefaultSessionState,
        SessionState,
    };
    use http::tests::common::TestStream;

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
        // Sanity check: both streams still found in the session
        assert_eq!(session.streams.len(), 2);
        // The closed stream is returned...
        let closed = session.get_closed();
        assert_eq!(closed.len(), 1);
        assert_eq!(closed[0].id(), 1);
        // ...and is also removed from the session!
        assert_eq!(session.streams.len(), 1);
    }

    /// Tests for the `DefaultSessionState` implementation of the `SessionState` trait.
    #[test]
    fn test_default_session_state() {
        fn new_mock_state() -> DefaultSessionState<TestStream> { DefaultSessionState::new() }

        {
            // Test insert
            let mut state = new_mock_state();
            state.insert_stream(Stream::new(1));
            assert_eq!(state.get_stream_ref(1).unwrap().id(), 1);
        }
        {
            // Test remove
            let mut state = new_mock_state();
            state.insert_stream(Stream::new(101));

            let stream = state.remove_stream(101).unwrap();

            assert_eq!(101, stream.id());
        }
        {
            // Test get stream -- unknown ID
            let mut state = new_mock_state();
            state.insert_stream(Stream::new(1));
            assert!(state.get_stream_ref(3).is_none());
        }
        {
            // Test iterate
            let mut state = new_mock_state();
            state.insert_stream(Stream::new(1));
            state.insert_stream(Stream::new(7));
            state.insert_stream(Stream::new(3));

            let mut streams: Vec<_> = state.iter().collect();
            streams.sort_by(|s1, s2| s1.id().cmp(&s2.id()));

            assert_eq!(vec![1, 3, 7], streams.into_iter().map(|s| s.id()).collect::<Vec<_>>());
        }
        {
            // Test iterate on an empty state
            let mut state = new_mock_state();

            assert_eq!(state.iter().collect::<Vec<_>>().len(), 0);
        }
        {
            // Test `get_closed`
            let mut state = new_mock_state();
            state.insert_stream(Stream::new(1));
            state.insert_stream(Stream::new(7));
            state.insert_stream(Stream::new(3));
            // Close some streams now
            state.get_stream_mut(1).unwrap().close();
            state.get_stream_mut(7).unwrap().close();

            let mut closed = state.get_closed();

            // Only one stream left
            assert_eq!(state.streams.len(), 1);
            // Both of the closed streams extracted into the `closed` Vec.
            assert_eq!(closed.len(), 2);
            closed.sort_by(|s1, s2| s1.id().cmp(&s2.id()));
            assert_eq!(vec![1, 7], closed.into_iter().map(|s| s.id()).collect::<Vec<_>>());
        }
    }
}
