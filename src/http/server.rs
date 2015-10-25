//! The module contains a number of reusable components for implementing the server side of an
//! HTTP/2 connection.

use http::{
    StreamId,
    Header,
    HttpResult,
    HttpScheme,
    ErrorCode,
};
use http::frame::{HttpSetting};
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
    Server as ServerMarker,
};
use http::priority::SimplePrioritizer;

/// The `ServerSession` requires an instance of a type that implements this trait in order to
/// create a new `Stream` instance once it detects that a client has initiated a new stream. The
/// factory should take care to provide an appropriate `Stream` implementation that will be able to
/// handle reading the request and generating the response, according to the needs of the
/// underlying application.
pub trait StreamFactory {
    type Stream: Stream;
    /// Create a new `Stream` with the given ID.
    fn create(&mut self, id: StreamId) -> Self::Stream;
}

/// An implementation of the `Session` trait for a server-side HTTP/2 connection.
pub struct ServerSession<'a, State, F, S>
        where State: SessionState + 'a,
              S: SendFrame + 'a,
              F: StreamFactory<Stream=State::Stream> + 'a {
    state: &'a mut State,
    factory: &'a mut F,
    sender: &'a mut S,
}

impl<'a, State, F, S> ServerSession<'a, State, F, S>
        where State: SessionState + 'a,
              S: SendFrame + 'a,
              F: StreamFactory<Stream=State::Stream> + 'a {
    #[inline]
    pub fn new(state: &'a mut State, factory: &'a mut F, sender: &'a mut S)
            -> ServerSession<'a, State, F, S> {
        ServerSession {
            state: state,
            factory: factory,
            sender: sender,
        }
    }
}

impl<'a, State, F, S> Session for ServerSession<'a, State, F, S>
        where State: SessionState + 'a,
              S: SendFrame + 'a,
              F: StreamFactory<Stream=State::Stream> + 'a {
    fn new_data_chunk(&mut self, stream_id: StreamId, data: &[u8], _: &mut HttpConnection)
            -> HttpResult<()> {
        debug!("Data chunk for stream {}", stream_id);
        let mut stream = match self.state.get_stream_mut(stream_id) {
            None => {
                debug!("Received a frame for an unknown stream!");
                return Ok(());
            },
            Some(stream) => stream,
        };
        // Now let the stream handle the data chunk
        stream.new_data_chunk(data);
        Ok(())
    }

    fn new_headers<'n, 'v>(
            &mut self,
            stream_id: StreamId,
            headers: Vec<Header<'n, 'v>>,
            _conn: &mut HttpConnection)
            -> HttpResult<()> {
        debug!("Headers for stream {}", stream_id);
        match self.state.get_stream_mut(stream_id) {
            Some(stream) => {
                // This'd correspond to having received trailers...
                stream.set_headers(headers);
                return Ok(());
            },
            None => {},
        };
        // New stream initiated by the client
        let mut stream = self.factory.create(stream_id);
        stream.set_headers(headers);
        // TODO(mlalic): Once the `Session` trait is able to signal connection failure, handle
        //               the error case here and return the corresponding protocol error.
        let _ = self.state.insert_incoming(stream_id, stream);
        Ok(())
    }

    fn end_of_stream(&mut self, stream_id: StreamId, _: &mut HttpConnection)
            -> HttpResult<()> {
        debug!("End of stream {}", stream_id);
        let mut stream = match self.state.get_stream_mut(stream_id) {
            None => {
                debug!("Received a frame for an unknown stream!");
                return Ok(());
            },
            Some(stream) => stream,
        };
        stream.close_remote();
        Ok(())
    }

    fn rst_stream(&mut self, stream_id: StreamId, error_code: ErrorCode, _: &mut HttpConnection)
            -> HttpResult<()> {
        Ok(())
    }

    fn new_settings(&mut self, _settings: Vec<HttpSetting>, conn: &mut HttpConnection)
            -> HttpResult<()> {
        debug!("Sending a SETTINGS ack");
        conn.sender(self.sender).send_settings_ack()
    }
}

/// The struct provides a more convenient API for server-related functionality of an HTTP/2
/// connection, such as sending a response back to the client.
pub struct ServerConnection<F, State=DefaultSessionState<ServerMarker, DefaultStream>>
        where State: SessionState,
              F: StreamFactory<Stream=State::Stream> {
    /// The underlying `HttpConnection` that will be used for any HTTP/2
    /// communication.
    conn: HttpConnection,
    /// The state of the session associated to this client connection. Maintains the status of the
    /// connection streams.
    pub state: State,
    /// Creates `Stream` instances for client-initiated streams. This allows the client of the
    /// `ServerConnection` to implement custom handling of a newly initiated stream.
    factory: F,
}

impl<F, State> ServerConnection<F, State>
        where State: SessionState, F: StreamFactory<Stream=State::Stream> {
    /// Creates a new `ServerConnection` that will use the given `HttpConnection` for its
    /// underlying HTTP/2 communication. The `state` and `factory` represent, respectively, the
    /// initial state of the connection and an instance of the `StreamFactory` type (allowing the
    /// client to handle newly created streams).
    pub fn with_connection(conn: HttpConnection, state: State, factory: F)
            -> ServerConnection<F, State> {
        ServerConnection {
            conn: conn,
            state: state,
            factory: factory,
        }
    }

    /// Returns the scheme of the underlying `HttpConnection`.
    #[inline]
    pub fn scheme(&self) -> HttpScheme {
        self.conn.scheme
    }

    /// Send the current settings associated to the `ServerConnection` to the client.
    pub fn send_settings<S: SendFrame>(&mut self, sender: &mut S) -> HttpResult<()> {
        // TODO: `HttpConnection` should provide a better API for sending settings.
        self.conn.sender(sender).send_settings_ack()
    }

    /// Handles the next frame on the given `ReceiveFrame` instance and expects it to be a
    /// (non-ACK) SETTINGS frame. Returns an error if not.
    pub fn expect_settings<Recv: ReceiveFrame, Sender: SendFrame>(
            &mut self,
            rx: &mut Recv,
            tx: &mut Sender)
            -> HttpResult<()> {
        let mut session = ServerSession::new(&mut self.state, &mut self.factory, tx);
        self.conn.expect_settings(rx, &mut session)
    }

    /// Fully handles the next frame provided by the given `ReceiveFrame` instance.
    /// Handling the frame can cause the session state of the `ServerConnection` to update.
    #[inline]
    pub fn handle_next_frame<Recv: ReceiveFrame, Sender: SendFrame>(
            &mut self,
            rx: &mut Recv,
            tx: &mut Sender)
            -> HttpResult<()> {
        let mut session = ServerSession::new(&mut self.state, &mut self.factory, tx);
        self.conn.handle_next_frame(rx, &mut session)
    }

    /// Starts a response on the stream with the given ID by sending the given headers.
    ///
    /// The body of the response is assumed to be provided by the `Stream` instance stored within
    /// the connection's state. (The body does not have to be ready when this method is called, as
    /// long as the `Stream` instance knows how to provide it to the connection later on.)
    #[inline]
    pub fn start_response<'n, 'v, S: SendFrame>(
            &mut self,
            headers: Vec<Header<'n, 'v>>,
            stream_id: StreamId,
            end_stream: EndStream,
            sender: &mut S)
            -> HttpResult<()> {
        self.conn.sender(sender).send_headers(
            headers,
            stream_id,
            end_stream)
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

        // TODO: Additionally account for the flow control windows.
        let mut prioritizer = SimplePrioritizer::new(&mut self.state, &mut buf);

        self.conn.sender(sender).send_next_data(&mut prioritizer)
    }
}

#[cfg(test)]
mod tests {
    use super::ServerSession;

    use http::tests::common::{TestStream, TestStreamFactory, build_mock_http_conn, MockSendFrame};

    use http::Header;
    use http::session::{
        DefaultSessionState,
        SessionState,
        Stream,
        Session,
        Server as ServerMarker,
    };

    /// Tests that the `ServerSession` correctly manages the stream state.
    #[test]
    fn test_server_session() {
        let mut state = DefaultSessionState::<ServerMarker, TestStream>::new();
        let mut conn = build_mock_http_conn();
        let mut sender = MockSendFrame::new();

        // Receiving new headers results in a new stream being created
        let headers = vec![
            Header::new(b":method".to_vec(), b"GET".to_vec())
        ];
        {
            let mut factory = TestStreamFactory;
            let mut session = ServerSession::new(&mut state, &mut factory, &mut sender);
            session.new_headers(1, headers.clone(), &mut conn).unwrap();
        }
        assert!(state.get_stream_ref(1).is_some());
        assert_eq!(state.get_stream_ref(1).unwrap().headers.clone().unwrap(),
                   headers);
        // Now some data arrives on the stream...
        {
            let mut factory = TestStreamFactory;
            let mut session = ServerSession::new(&mut state, &mut factory, &mut sender);
            session.new_data_chunk(1, &[1, 2, 3], &mut conn).unwrap();
        }
        // ...works.
        assert_eq!(state.get_stream_ref(1).unwrap().body, vec![1, 2, 3]);
        // Some more data...
        {
            let mut factory = TestStreamFactory;
            let mut session = ServerSession::new(&mut state, &mut factory, &mut sender);
            session.new_data_chunk(1, &[4], &mut conn).unwrap();
        }
        // ...all good.
        assert_eq!(state.get_stream_ref(1).unwrap().body, vec![1, 2, 3, 4]);
        // Add another stream in the mix
        {
            let mut factory = TestStreamFactory;
            let mut session = ServerSession::new(&mut state, &mut factory, &mut sender);
            session.new_headers(3, headers.clone(), &mut conn).unwrap();
            session.new_data_chunk(3, &[100], &mut conn).unwrap();
        }
        assert!(state.get_stream_ref(3).is_some());
        assert_eq!(state.get_stream_ref(3).unwrap().headers.clone().unwrap(),
                   headers);
        assert_eq!(state.get_stream_ref(3).unwrap().body, vec![100]);
        {
            // Finally, the stream 1 ends...
            let mut factory = TestStreamFactory;
            let mut session = ServerSession::new(&mut state, &mut factory, &mut sender);
            session.end_of_stream(1, &mut conn).unwrap();
        }
        // ...and gets closed.
        assert!(state.get_stream_ref(1).unwrap().is_closed_remote());
        // but not the other one.
        assert!(!state.get_stream_ref(3).unwrap().is_closed_remote());
    }
}
