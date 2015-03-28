//! The module contains an implementation of a simple HTTP/2 client.

use std::net::TcpStream;

use super::super::http::connection::ClientConnection;
use super::super::http::session::{DefaultSession, Stream};
use super::super::http::{StreamId, HttpResult, HttpError, Response, Header, Request};


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
/// # Notes
///
/// - For now (temporarily) no requests with bodies are supported.
/// - For now, only HTTP/2 over a cleartext TCP connection is supported.
/// - A direct HTTP/2 connection is used (not an upgrade of an HTTP/1.1
///   connection)
///
/// # Examples
///
/// Issue a simple GET request using the helper `get` method.
///
/// ```no_run
/// use solicit::client::SimpleClient;
/// use std::str;
///
/// // Connect to an HTTP/2 aware server
/// let mut client = SimpleClient::connect("nghttp2.org", 80).ok().unwrap();
/// let response = client.get(b"/", &[]).ok().unwrap();
/// assert_eq!(response.stream_id, 1);
/// assert_eq!(response.status_code().ok().unwrap(), 200);
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
#[unstable = "This is unstable"]
pub struct SimpleClient {
    /// The underlying `ClientConnection` that the client uses
    conn: ClientConnection<TcpStream, DefaultSession>,
    /// Holds the ID that can be assigned to the next stream to be opened by the
    /// client.
    next_stream_id: u32,
    /// Holds the domain name of the host to which the client is connected to.
    host: Vec<u8>,
}

impl SimpleClient {
    /// Establishes an HTTP/2 connection to a server, given its host name and
    /// port number. If it is not possible to establish the connection, an error
    /// is returned.
    pub fn connect(host: &str, port: u16) -> HttpResult<SimpleClient> {
        let mut client = SimpleClient {
            conn: ClientConnection::new(
                TcpStream::connect(&(host, port)).unwrap(),
                DefaultSession::new()),
            next_stream_id: 1,
            host: host.as_bytes().to_vec(),
        };

        try!(client.init());

        Ok(client)
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
    pub fn request(&mut self, method: &[u8], path: &[u8], extras: &[Header])
            -> HttpResult<StreamId> {
        let stream_id = self.new_stream();
        // Only http supported for now...
        let scheme = b"http".to_vec();
        let host = self.host.clone();
        let mut headers: Vec<Header> = vec![
            (b":method".to_vec(), method.to_vec()),
            (b":path".to_vec(), path.to_vec()),
            (b":authority".to_vec(), host),
            (b":scheme".to_vec(), scheme),
        ];
        headers.extend(extras.to_vec().into_iter());

        try!(self.conn.send_request(Request {
            stream_id: stream_id,
            headers: headers,
            body: Vec::new(),
        }));

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
        match self.conn.session.get_stream(stream_id) {
            None => return Err(HttpError::UnknownStreamId),
            Some(_) => {},
        };
        loop {
            if let Some(stream) = self.conn.session.get_stream(stream_id) {
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
        let stream_id = try!(self.request(b"GET", path, extra_headers));
        self.get_response(stream_id)
    }

    /// Internal helper method that initializes a new stream and returns its
    /// ID once done.
    fn new_stream(&mut self) -> StreamId {
        let stream_id = self.get_next_stream_id();
        self.conn.session.new_stream(stream_id);

        stream_id
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
