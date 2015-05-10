//! The module contains a number of reusable components for implementing the client side of an
//! HTTP/2 connection.

use http::{HttpScheme, HttpResult, Request};
use http::connection::{
    SendFrame, ReceiveFrame,
    HttpConnection,
};
use http::session::Session;

/// The struct extends the `HttpConnection` API with client-specific methods (such as
/// `send_request`) and wires the `HttpConnection` to the client `Session` callbacks.
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
    ///
    /// The given `session` instance will receive all events that arise from reading frames from
    /// the underlying HTTP/2 connection.
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
    use super::ClientConnection;

    use http::Request;
    use http::tests::common::{
        TestSession,
        build_mock_http_conn,
    };
    use http::frame::{
        SettingsFrame,
        DataFrame,
    };
    use http::connection::{
        HttpFrame,
    };

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
}
