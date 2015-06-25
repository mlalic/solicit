//! Defines the interface for the session-level management of HTTP/2
//! communication. This is effectively an API that allows hooking into an
//! HTTP/2 connection in order to handle events arising on the connection.
//!
//! The module also provides a default implementation for some of the traits.
use std::collections::HashMap;
use std::error::Error;
use std::io::Read;
use std::io::Cursor;
use std::iter::FromIterator;
use http::{StreamId, Header};

/// A trait that defines the interface between an `HttpConnection` and the higher-levels that use
/// it. Essentially, it allows the `HttpConnection` to pass information onto those higher levels
/// through a well-defined interface.
///
/// These methods are effectively a set of callbacks that the `HttpConnection` invokes when the
/// corresponding events arise on the HTTP/2 connection (i.e. frame stream).
///
/// TODO Allow the session to influence the `HttpConnection` state and raise
///      errors (i.e. make the return type -> HttpResult<()>).
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

impl<E> From<E> for StreamDataError where E: Error + Send + Sync + 'static {
    fn from(err: E) -> StreamDataError { StreamDataError::Other(Box::new(err)) }
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
    /// Create a new stream with the given ID
    fn new(stream_id: StreamId) -> Self;
    /// Handle a new data chunk that has arrived for the stream.
    fn new_data_chunk(&mut self, data: &[u8]);
    /// Set headers for a stream. A stream is only allowed to have one set of
    /// headers.
    fn set_headers(&mut self, headers: Vec<Header>);
    /// Sets the stream state to the newly provided state.
    fn set_state(&mut self, state: StreamState);

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

    /// Returns the ID of the stream.
    fn id(&self) -> StreamId;
    /// Returns the current state of the stream.
    fn state(&self) -> StreamState;

    /// Transitions the stream state to closed. After this, the stream is considered to be closed
    /// for any further reads or writes.
    fn close(&mut self) { self.set_state(StreamState::Closed); }
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
    fn is_closed(&self) -> bool { self.state() == StreamState::Closed }
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
    /// The ID of the stream
    pub stream_id: StreamId,
    /// The headers associated with the stream (i.e. the response headers)
    pub headers: Option<Vec<Header>>,
    /// The body of the stream (i.e. the response body)
    pub body: Vec<u8>,
    /// The current stream state.
    pub state: StreamState,
    /// The outgoing data associated to the stream. The `Cursor` points into the `Vec` at the
    /// position where the data has been sent out.
    data: Option<Cursor<Vec<u8>>>,
}

impl DefaultStream {
    /// Create a new `DefaultStream` with the given ID.
    pub fn new(stream_id: StreamId) -> DefaultStream {
        DefaultStream {
            stream_id: stream_id,
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
    fn new(stream_id: StreamId) -> DefaultStream {
        DefaultStream::new(stream_id)
    }

    fn new_data_chunk(&mut self, data: &[u8]) {
        self.body.extend(data.to_vec().into_iter());
    }

    fn set_headers(&mut self, headers: Vec<Header>) {
        self.headers = Some(headers);
    }
    fn set_state(&mut self, state: StreamState) { self.state = state; }

    fn id(&self) -> StreamId {
        self.stream_id
    }
    fn state(&self) -> StreamState { self.state }

    fn get_data_chunk(&mut self, buf: &mut [u8]) -> Result<StreamDataChunk, StreamDataError> {
        if self.is_closed_local() {
            return Err(StreamDataError::Closed);
        }
        let chunk = match self.data.as_mut() {
            // No data associated to the stream, but it's open => nothing available for writing
            None => StreamDataChunk::Unavailable,
            Some(d) =>  {
                // For the `Vec`-backed reader, this should never fail, so unwrapping is
                // fine.
                let read = d.read(buf).unwrap();
                if (d.position() as usize) == d.get_ref().len() {
                    StreamDataChunk::Last(read)
                } else {
                    StreamDataChunk::Chunk(read)
                }
            }
        };
        // Transition the stream state to locally closed if we've extracted the final data chunk.
        match chunk {
            StreamDataChunk::Last(_) => self.close_local(),
            _ => {},
        };

        Ok(chunk)
    }
}

#[cfg(test)]
mod tests {
    use super::{
        Stream,
        DefaultSessionState,
        DefaultStream,
        StreamDataChunk, StreamDataError,
        SessionState,
    };
    use http::tests::common::TestStream;

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

    /// Tests that the `DefaultStream` provides the correct data when its `get_data_chunk` method
    /// is called.
    #[test]
    fn test_default_stream_get_data() {
        // The buffer that will be used in upcoming tests
        let mut buf = Vec::with_capacity(2);
        unsafe { buf.set_len(2); }

        {
            // A newly open stream has no available data.
            let mut stream = DefaultStream::new(1);
            let res = stream.get_data_chunk(&mut buf).ok().unwrap();
            assert_eq!(res, StreamDataChunk::Unavailable);
        }
        {
            // A closed stream returns an error
            let mut stream = DefaultStream::new(1);
            stream.close();
            let res = stream.get_data_chunk(&mut buf).err().unwrap();
            assert!(match res {
                StreamDataError::Closed => true,
                _ => false,
            });
        }
        {
            // A locally closed stream returns an error
            let mut stream = DefaultStream::new(1);
            stream.close_local();
            let res = stream.get_data_chunk(&mut buf).err().unwrap();
            assert!(match res {
                StreamDataError::Closed => true,
                _ => false,
            });
        }
        {
            let mut stream = DefaultStream::new(1);
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
            let mut stream = DefaultStream::new(1);
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
            let mut stream = DefaultStream::new(1);
            stream.set_full_data(vec![]);

            let res = stream.get_data_chunk(&mut buf).ok().unwrap();
            assert_eq!(res, StreamDataChunk::Last(0));
        }
    }
}
