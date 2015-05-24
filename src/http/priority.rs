//! The module exposes an API for defining data prioritization strategies.
//!
//! Types that implement the `DataPrioritizer` trait can be used to provide new data for an
//! `HttpConnection` to send to its peer. Neither the `HttpConnection` nor the `DataPrioritizer`
//! have control over exactly *when* the data is sent. This is left up to the particular client
//! implementations to trigger.

use http::{HttpResult, HttpError};
use http::connection::{
    DataChunk,
    EndStream,
};
use http::session::{
    SessionState,
    StreamDataChunk, StreamDataError,
    Stream,
};

/// A trait that types that want to provide data to an HTTP/2 connection need to implement.
pub trait DataPrioritizer {
    /// Returns the next `DataChunk` that should be sent on the HTTP/2 connection. `None` indicates
    /// that currently there was no data that could be sent at that point.
    fn get_next_chunk(&mut self) -> HttpResult<Option<DataChunk>>;
}

/// An implementation of the `DataPrioritizer` trait that is based on finding the first stream from
/// the given `SessionState` instance that can send data and returning this chunk.
///
/// For all means and purposes, the order of data chunks that the prioritizer returns is undefined
/// and should not be relied on.
pub struct SimplePrioritizer<'a, 'b, State> where State: SessionState + 'a {
    /// The session state from which the streams' data will be taken
    state: &'a mut State,
    /// The buffer into which the prioritizer can place the stream data chunk
    buf: &'b mut [u8],
}

impl<'a, 'b, State> SimplePrioritizer<'a, 'b, State> where State: SessionState +'a {
    /// Creates a new `SimplePrioritizer` that will use the given state to find stream data that
    /// should be sent and use the given buffer to hold the data of the returned chunk.
    pub fn new(state: &'a mut State, buf: &'b mut [u8]) -> SimplePrioritizer<'a, 'b, State> {
        SimplePrioritizer {
            state: state,
            buf: buf,
        }
    }
}

impl<'a, 'b, State> DataPrioritizer for SimplePrioritizer<'a, 'b, State>
        where State: SessionState +'a {
    fn get_next_chunk(&mut self) -> HttpResult<Option<DataChunk>> {
        // Returns the data of the first stream that has data to be written.
        for stream in self.state.iter().filter(|s| !s.is_closed_local()) {
            let res = stream.get_data_chunk(self.buf);
            match res {
                Ok(StreamDataChunk::Last(total)) => {
                    return Ok(Some(DataChunk::new_borrowed(
                                &self.buf[..total], stream.id(), EndStream::Yes)));
                },
                Ok(StreamDataChunk::Chunk(total)) => {
                    return Ok(Some(DataChunk::new_borrowed(
                                &self.buf[..total], stream.id(), EndStream::No)));
                },
                Ok(StreamDataChunk::Unavailable) => {
                    // Stream is still open, but currently has no data that could be sent.
                    // Pass...
                },
                Err(StreamDataError::Closed) => {
                    // Transition the stream state to be locally closed, so we don't attempt to
                    // write any more data on this stream.
                    stream.close_local();
                    // Find a stream with data to actually write to...
                },
                Err(StreamDataError::Other(e)) => {
                    // Any other error is fatal!
                    return Err(HttpError::Other(e));
                },
            };
        }
        // Nothing can be sent if we reach here -- no streams have data that can be sent.
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::{DataPrioritizer, SimplePrioritizer};
    use http::session::{DefaultSessionState, SessionState, Stream};

    use http::tests::common::TestStream;

    #[test]
    fn test_simple_prioritizer() {
        fn prepare_state() -> DefaultSessionState<TestStream> {
            DefaultSessionState::new()
        }

        {
            // No streams in the session
            let mut buf = [0; 5];
            let mut state = prepare_state();
            let mut prioritizer = SimplePrioritizer::new(&mut state, &mut buf);

            let chunk = prioritizer.get_next_chunk().unwrap();

            assert!(chunk.is_none());
        }
        {
            // One stream, one chunk
            let mut buf = [0; 5];
            let mut state = prepare_state();
            let mut stream = TestStream::new(1);
            stream.set_outgoing(vec![1, 2, 3]);
            state.insert_stream(stream);
            let mut prioritizer = SimplePrioritizer::new(&mut state, &mut buf);

            {
                let chunk = prioritizer.get_next_chunk().unwrap().unwrap();
                assert_eq!(chunk.data, vec![1, 2, 3]);
            }

            // Now we have no more data?
            assert!(prioritizer.get_next_chunk().unwrap().is_none());
        }
        {
            // One stream, two chunks
            let mut buf = [0; 2];
            let mut state = prepare_state();
            let mut stream = TestStream::new(1);
            stream.set_outgoing(vec![1, 2, 3]);
            state.insert_stream(stream);
            let mut prioritizer = SimplePrioritizer::new(&mut state, &mut buf);

            {
                let chunk = prioritizer.get_next_chunk().unwrap().unwrap();
                assert_eq!(chunk.data, vec![1, 2]);
            }
            {
                let chunk = prioritizer.get_next_chunk().unwrap().unwrap();
                assert_eq!(chunk.data, vec![3]);
            }

            // Now we have no more data?
            assert!(prioritizer.get_next_chunk().unwrap().is_none());
        }
        {
            // Multiple streams
            let mut buf = [0; 10];
            let mut state = prepare_state();
            for id in 0..3 {
                let mut stream = TestStream::new(id);
                stream.set_outgoing(vec![1, 2, 3]);
                state.insert_stream(stream);
            }

            // In total, we get 3 frames; we don't know anything about the order of the streams,
            // though.
            for _ in 0..3 {
                {
                    let mut prioritizer = SimplePrioritizer::new(&mut state, &mut buf);
                    let chunk = prioritizer.get_next_chunk().unwrap().unwrap();
                    assert_eq!(chunk.data, vec![1, 2, 3]);
                }
                // Zero out the buffer to make sure we don't get false results due to the previous
                // data being the same
                for b in buf.iter_mut() { *b = 0; }
            }

            // Now we have no more data?
            let mut prioritizer = SimplePrioritizer::new(&mut state, &mut buf);
            assert!(prioritizer.get_next_chunk().unwrap().is_none());
        }
    }
}
