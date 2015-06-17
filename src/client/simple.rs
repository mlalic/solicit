//! The module contains an implementation of a simple HTTP/2 client.

use http::{StreamId, HttpResult, HttpError, Response, Header};
use http::transport::TransportStream;
use http::connection::{HttpConnection, SendStatus};
use http::session::{SessionState, DefaultSessionState, DefaultStream, Stream};
use http::client::{ClientConnection, HttpConnect, RequestStream};

/// A struct implementing a simple HTTP/2 client.
///
/// This client works as an HTTP/1.1 client with a Keep-Alive connection and
/// pipelining might work.
///
/// Multiple requests can be queued up (and sent to the server) by calling
/// `request` multiple times, before any `get_response`.
///
/// Once a `get_response` is issued, the client blocks until it receives the
/// response for the particular request that was referenced in the `get_response`
/// call.
///
/// Therefore, by doing `request` -> `get_response` we can use the HTTP/2
/// connection as a `Keep-Alive` HTTP/1.1 connection and a pipelined flow by
/// queuing up a sequence of requests and then "joining" over them by calling
/// `get_response` for each of them.
///
/// The responses that are returned by the client are very raw representations
/// of the response.
///
/// # Examples
///
/// Issue a simple GET request using the helper `get` method. Premade connection
/// passed to the client.
///
/// ```no_run
/// use std::net::TcpStream;
/// use solicit::http::HttpScheme;
/// use solicit::http::connection::HttpConnection;
/// use solicit::http::client::write_preface;
/// use solicit::client::SimpleClient;
/// use std::str;
///
/// // Prepare a stream manually... We must write the preface ourselves in this case.
/// // This is a more advanced way to use the client and the `HttpConnect` implementations
/// // should usually be preferred for their convenience.
/// let mut stream = TcpStream::connect(&("http2bin.org", 80)).unwrap();
/// write_preface(&mut stream);
/// // Connect to an HTTP/2 aware server
/// let conn = HttpConnection::<TcpStream, TcpStream>::with_stream(
///                                stream,
///                                HttpScheme::Http);
/// let mut client = SimpleClient::with_connection(conn, "http2bin.org".into()).unwrap();
/// let response = client.get(b"/", &[]).unwrap();
/// assert_eq!(response.stream_id, 1);
/// assert_eq!(response.status_code().unwrap(), 200);
/// // Dump the headers and the response body to stdout.
/// // They are returned as raw bytes for the user to do as they please.
/// // (Note: in general directly decoding assuming a utf8 encoding might not
/// // always work -- this is meant as a simple example that shows that the
/// // response is well formed.)
/// for header in response.headers.iter() {
///     println!("{}: {}",
///         str::from_utf8(&header.0).unwrap(),
///         str::from_utf8(&header.1).unwrap());
/// }
/// println!("{}", str::from_utf8(&response.body).unwrap());
/// ```
///
/// Issue a simple GET request using the helper `get` method. Pass a connector
/// to establish a new connection.
///
/// ```no_run
/// use solicit::http::client::CleartextConnector;
/// use solicit::client::SimpleClient;
/// use std::str;
///
/// // Connect to an HTTP/2 aware server
/// let connector = CleartextConnector::new("http2bin.org");
/// let mut client = SimpleClient::with_connector(connector).unwrap();
/// let response = client.get(b"/", &[]).unwrap();
/// assert_eq!(response.stream_id, 1);
/// assert_eq!(response.status_code().unwrap(), 200);
/// // Dump the headers and the response body to stdout.
/// // They are returned as raw bytes for the user to do as they please.
/// // (Note: in general directly decoding assuming a utf8 encoding might not
/// // always work -- this is meant as a simple example that shows that the
/// // response is well formed.)
/// for header in response.headers.iter() {
///     println!("{}: {}",
///         str::from_utf8(&header.0).unwrap(),
///         str::from_utf8(&header.1).unwrap());
/// }
/// println!("{}", str::from_utf8(&response.body).unwrap());
/// ```
pub struct SimpleClient<S> where S: TransportStream {
    /// The underlying `ClientConnection` that the client uses
    conn: ClientConnection<S, S>,
    /// Holds the ID that can be assigned to the next stream to be opened by the
    /// client.
    next_stream_id: u32,
    /// The name of the host to which the client is connected to.
    host: Vec<u8>,
}

impl<S> SimpleClient<S> where S: TransportStream {
    /// Create a new `SimpleClient` instance that will use the given `HttpConnection`
    /// to communicate to the server.
    ///
    /// It assumes that the connection stream is initialized and will *not* automatically write the
    /// client preface.
    pub fn with_connection(conn: HttpConnection<S, S>, host: String)
            -> HttpResult<SimpleClient<S>> {
        let mut client = SimpleClient {
            conn: ClientConnection::with_connection(conn, DefaultSessionState::new()),
            next_stream_id: 1,
            host: host.as_bytes().to_vec(),
        };

        try!(client.init());

        Ok(client)
    }

    /// A convenience constructor that first tries to establish an HTTP/2
    /// connection by using the given connector instance (an implementation of
    /// the `HttpConnect` trait).
    ///
    /// # Panics
    ///
    /// Currently, it panics if the connector returns an error.
    pub fn with_connector<C>(connector: C) -> HttpResult<SimpleClient<S>>
            where C: HttpConnect<Stream=S> {
        let stream = try!(connector.connect());
        let conn = HttpConnection::<S, S>::with_stream(stream.0, stream.1);
        SimpleClient::with_connection(conn, stream.2)
    }

    /// Internal helper method that performs the initialization of the client's
    /// connection.
    #[inline]
    fn init(&mut self) -> HttpResult<()> {
        self.conn.init()
    }

    /// Send a request to the server. Blocks until the entire request has been
    /// sent.
    ///
    /// The request is described by the method, the path on which it should be
    /// invoked and the "real" headers that should be included. Clients should
    /// never put pseudo-headers in the `headers` parameter, as those are
    /// automatically included based on metadata.
    ///
    /// # Returns
    ///
    /// If the full request is successfully sent, returns the ID of the stream
    /// on which the request was sent. Clients can use this ID to refer to the
    /// response.
    ///
    /// Any IO errors are propagated.
    pub fn request(&mut self, method: &[u8], path: &[u8], extras: &[Header], body: Option<Vec<u8>>)
            -> HttpResult<StreamId> {
        // Prepares the request stream
        let stream = self.new_stream(method, path, extras, body);
        // Remember the stream's ID before passing on the ownership to the connection
        let stream_id = stream.stream.id();
        // Starts the request (i.e. sends out the headers)
        try!(self.conn.start_request(stream));

        // And now makes sure the data is sent out...
        // Note: Since for now there is no flow control, sending data will always continue
        //       progressing, but it might violate flow control windows, causing the peer to shut
        //       down the connection.
        debug!("Trying to send the body");
        while let SendStatus::Sent = try!(self.conn.send_next_data()) {
            // We iterate until the data is sent, as the contract of this call is that it blocks
            // until such a time.
        }

        Ok(stream_id)
    }

    /// Gets the response for the stream with the given ID. If a valid stream ID
    /// is given, it blocks until a response is received.
    ///
    /// # Returns
    ///
    /// A `Response` if the response can be successfully read.
    ///
    /// Any underlying IO errors are propagated. Errors in the HTTP/2 protocol
    /// also stop processing and are returned to the client.
    pub fn get_response(&mut self, stream_id: StreamId) -> HttpResult<Response> {
        match self.conn.state.get_stream_ref(stream_id) {
            None => return Err(HttpError::UnknownStreamId),
            Some(_) => {},
        };
        loop {
            if let Some(stream) = self.conn.state.get_stream_ref(stream_id) {
                if stream.is_closed() {
                    return Ok(Response {
                        stream_id: stream.id(),
                        headers: stream.headers.clone().unwrap(),
                        body: stream.body.clone(),
                    });
                }
            }
            try!(self.handle_next_frame());
        }
    }

    /// Performs a GET request on the given path. This is a shortcut method for
    /// calling `request` followed by `get_response` for the returned stream ID.
    pub fn get(&mut self, path: &[u8], extra_headers: &[Header])
            -> HttpResult<Response> {
        let stream_id = try!(self.request(b"GET", path, extra_headers, None));
        self.get_response(stream_id)
    }

    /// Performs a POST request on the given path.
    pub fn post(&mut self, path: &[u8], extra_headers: &[Header], body: Vec<u8>)
            -> HttpResult<Response> {
        let stream_id = try!(self.request(b"POST", path, extra_headers, Some(body)));
        self.get_response(stream_id)
    }

    /// Internal helper method that prepares a new `RequestStream` instance based on the given
    /// request parameters.
    ///
    /// The `RequestStream` is then ready to be passed on to the connection instance in order to
    /// start the request.
    fn new_stream(&mut self, method: &[u8], path: &[u8], extras: &[Header], body: Option<Vec<u8>>)
            -> RequestStream<DefaultStream> {
        let stream_id = self.get_next_stream_id();
        let mut stream = DefaultStream::new(stream_id);
        match body {
            Some(body) => stream.set_full_data(body),
            None => stream.close_local(),
        };

        let mut headers: Vec<Header> = vec![
            (b":method".to_vec(), method.to_vec()),
            (b":path".to_vec(), path.to_vec()),
            (b":authority".to_vec(), self.host.clone()),
            (b":scheme".to_vec(), self.conn.scheme().as_bytes().to_vec()),
        ];
        headers.extend(extras.to_vec().into_iter());

        RequestStream {
            headers: headers,
            stream: stream,
        }
    }

    /// Internal helper method that gets the next valid stream ID number.
    fn get_next_stream_id(&mut self) -> StreamId {
        let ret = self.next_stream_id;
        self.next_stream_id += 2;

        ret
    }

    /// Internal helper method that triggers the client to handle the next
    /// frame off the HTTP/2 connection.
    #[inline]
    fn handle_next_frame(&mut self) -> HttpResult<()> {
        self.conn.handle_next_frame()
    }
}
