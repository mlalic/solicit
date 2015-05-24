//! The module contains a number of reusable components for implementing the server side of an
//! HTTP/2 connection.

use http::{
    StreamId,
    Header,
    HttpResult,
    HttpScheme,
};
use http::frame::SettingsFrame;
use http::connection::{
    SendFrame, ReceiveFrame,
    HttpConnection, EndStream,
    SendStatus,
};
use http::session::{
    Session,
    SessionState,
    Stream,
    DefaultStream,
    DefaultSessionState,
};
use http::priority::SimplePrioritizer;

/// An implementation of the `Session` trait for a server-side HTTP/2 connection.
pub struct ServerSession<'a, State> where State: SessionState + 'a {
    state: &'a mut State,
}

impl<'a, State> ServerSession<'a, State> where State: SessionState + 'a {
    #[inline]
    pub fn new(state: &'a mut State) -> ServerSession<State> {
        ServerSession {
            state: state,
        }
    }
}

impl<'a, State> Session for ServerSession<'a, State> where State: SessionState + 'a {
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
        match self.state.get_stream_mut(stream_id) {
            Some(stream) => {
                // This'd correspond to having received trailers...
                stream.set_headers(headers);
                return;
            },
            None => {},
        };
        // New stream initiated by the client
        let mut stream: State::Stream = Stream::new(stream_id);
        stream.set_headers(headers);
        self.state.insert_stream(stream);
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
        stream.close_remote()
    }
}

/// The struct provides a more convenient API for server-related functionality of an HTTP/2
/// connection, such as sending a response back to the client.
pub struct ServerConnection<S, R, State=DefaultSessionState<DefaultStream>>
        where S: SendFrame, R: ReceiveFrame, State: SessionState {
    /// The underlying `HttpConnection` that will be used for any HTTP/2
    /// communication.
    conn: HttpConnection<S, R>,
    /// The state of the session associated to this client connection. Maintains the status of the
    /// connection streams.
    pub state: State,
}

impl<S, R, State> ServerConnection<S, R, State>
        where S: SendFrame, R: ReceiveFrame, State: SessionState {
    /// Creates a new `ServerConnection` that will use the given `HttpConnection` for its
    /// underlying HTTP/2 communication.
    pub fn with_connection(conn: HttpConnection<S, R>, state: State)
            -> ServerConnection<S, R, State> {
        ServerConnection {
            conn: conn,
            state: state,
        }
    }

    /// Returns the scheme of the underlying `HttpConnection`.
    #[inline]
    pub fn scheme(&self) -> HttpScheme {
        self.conn.scheme
    }

    /// Initializes the `ServerConnection` by sending the server's settings and processing the
    /// client's.
    /// If the client does not provide a settings frame, returns an error.
    ///
    /// TODO This method should eventually be split into two.
    pub fn init(&mut self) -> HttpResult<()> {
        // TODO: `HttpConnection` should provide a better API for sending settings.
        try!(self.conn.sender.send_frame(SettingsFrame::new()));
        try!(self.read_preface());
        Ok(())
    }

    /// Reads and handles the settings frame of the client preface. If the settings frame is not
    /// the next frame received on the underlying connection, returns an error.
    fn read_preface(&mut self) -> HttpResult<()> {
        let mut session = ServerSession::new(&mut self.state);
        self.conn.expect_settings(&mut session)
    }

    /// Fully handles the next incoming frame. Events are passed on to the internal `session`
    /// instance.
    #[inline]
    pub fn handle_next_frame(&mut self) -> HttpResult<()> {
        let mut session = ServerSession::new(&mut self.state);
        self.conn.handle_next_frame(&mut session)
    }

    /// Starts a response on the stream with the given ID by sending the given headers.
    ///
    /// The body of the response is assumed to be provided by the `Stream` instance stored within
    /// the connection's state. (The body does not have to be ready when this method is called, as
    /// long as the `Stream` instance knows how to provide it to the connection later on.)
    #[inline]
    pub fn start_response(&mut self,
                          headers: Vec<Header>,
                          stream_id: StreamId,
                          end_stream: EndStream) -> HttpResult<()> {
        self.conn.send_headers(headers, stream_id, end_stream)
    }

    /// Queues a new DATA frame onto the underlying `SendFrame`.
    ///
    /// Currently, no prioritization of streams is taken into account and which stream's data is
    /// queued cannot be relied on.
    pub fn send_next_data(&mut self) -> HttpResult<SendStatus> {
        debug!("Sending next data...");
        // A default "maximum" chunk size of 8 KiB is set on all data frames.
        const MAX_CHUNK_SIZE: usize = 8 * 1024;
        let mut buf = [0; MAX_CHUNK_SIZE];

        // TODO: Additionally account for the flow control windows.
        let mut prioritizer = SimplePrioritizer::new(&mut self.state, &mut buf);

        self.conn.send_next_data(&mut prioritizer)
    }
}

#[cfg(test)]
mod tests {
    use super::ServerSession;

    use http::tests::common::TestStream;

    use http::session::{DefaultSessionState, SessionState, Stream, Session};

    /// Tests that the `ServerSession` correctly manages the stream state.
    #[test]
    fn test_server_session() {
        let mut state = DefaultSessionState::<TestStream>::new();

        // Receiving new headers results in a new stream being created
        let headers = vec![(b":method".to_vec(), b"GET".to_vec())];
        {
            let mut session = ServerSession::new(&mut state);
            session.new_headers(1, headers.clone());
        }
        assert!(state.get_stream_ref(1).is_some());
        assert_eq!(state.get_stream_ref(1).unwrap().headers.clone().unwrap(),
                   headers);
        // Now some data arrives on the stream...
        {
            let mut session = ServerSession::new(&mut state);
            session.new_data_chunk(1, &[1, 2, 3]);
        }
        // ...works.
        assert_eq!(state.get_stream_ref(1).unwrap().body, vec![1, 2, 3]);
        // Some more data...
        {
            let mut session = ServerSession::new(&mut state);
            session.new_data_chunk(1, &[4]);
        }
        // ...all good.
        assert_eq!(state.get_stream_ref(1).unwrap().body, vec![1, 2, 3, 4]);
        // Add another stream in the mix
        {
            let mut session = ServerSession::new(&mut state);
            session.new_headers(3, headers.clone());
            session.new_data_chunk(3, &[100]);
        }
        assert!(state.get_stream_ref(3).is_some());
        assert_eq!(state.get_stream_ref(3).unwrap().headers.clone().unwrap(),
                   headers);
        assert_eq!(state.get_stream_ref(3).unwrap().body, vec![100]);
        {
            // Finally, the stream 1 ends...
            let mut session = ServerSession::new(&mut state);
            session.end_of_stream(1);
        }
        // ...and gets closed.
        assert!(state.get_stream_ref(1).unwrap().is_closed_remote());
        // but not the other one.
        assert!(!state.get_stream_ref(3).unwrap().is_closed_remote());
    }
}
