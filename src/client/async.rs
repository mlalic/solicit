//! Contains an implementation of an asynchronous client.
//!
//! It allows users to make requests to the same underlying connection from
//! different threads concurrently, as well as to receive the response
//! asynchronously.
use std::net::TcpStream;
use std::collections::HashMap;

use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;
use std::thread;
use std::io;

use http::connection::{SendFrame};
use http::HttpResult;
use http::frame::RawFrame;
use super::super::http::{StreamId, HttpError, HttpScheme, Response, Request, Header};
use super::super::http::connection::{HttpConnection, ClientConnection, write_preface};
use super::super::http::session::{DefaultSession, DefaultStream};

/// A struct representing an asynchronously dispatched request. It is used
/// internally be the `ClientService` and `Client` structs.
struct AsyncRequest {
    /// The method of the request
    pub method: Vec<u8>,
    /// The path being requested
    pub path: Vec<u8>,
    /// Extra headers that should be included in the request. Does *not*
    /// include meta-headers.
    pub headers: Vec<Header>,
    /// The sender side of a channel where the response to this request should
    /// be delivered.
    tx: Sender<Response>,
}

/// A struct that buffers `RawFrame`s in an internal `mpsc` channel and sends them using the
/// wrapped `SendFrame` instance when the `send_next` method is called.
///
/// Additionally, it provides a `ChannelFrameSenderHandle` instance that implements the `SendFrame`
/// trait and as such can be passed to the `HttpConnection`. This handler simply queues the frame
/// into the internal channel, without ever blocking.
///
/// As such, this is a convenience struct that makes it possible to provide non-blocking writes
/// from within `HttpConnection`s, while handling the actual writes using a `SendFrame`
/// implementation that will block until the frame is sent on a separate thread.
struct ChannelFrameSender<S> where S: SendFrame {
    /// The receiving end of the channel. Buffers the frames that are to be sent.
    rx: Receiver<RawFrame>,
    /// The `SendFrame` instance that will perform the actual writes from within the `send_next`
    /// method.
    inner: S,
}

impl<S> ChannelFrameSender<S> where S: SendFrame {
    /// Creates a new `ChannelFrameSender` that will use the provided `SendFrame` instance within
    /// the `send_next` method in order to perform the final send to the remote peer.
    /// The `ChannelFrameSenderHandle` that is returned can be used to queue frames for sending
    /// from within `HttpConnection`s, as it implements the `SendFrame` trait.
    fn new(inner: S) -> (ChannelFrameSender<S>, ChannelFrameSenderHandle) {
        let (send, recv) = mpsc::channel();

        let handle = ChannelFrameSenderHandle { tx: send };
        let sender = ChannelFrameSender {
            rx: recv,
            inner: inner,
        };
        (sender, handle)
    }

    /// Performs the send of the next frame that is buffered in the internal channel of the struct.
    ///
    /// If there is no frame in the channel, it will block until there is one there.
    ///
    /// If the channel becomes disconnected from all senders, indicating that all handles to the
    /// sender have been dropped, the mehod will return an error.
    fn send_next(&mut self) -> HttpResult<()> {
        let frame = try!(
            self.rx.recv()
                   .map_err(|_| {
                       io::Error::new(io::ErrorKind::Other, "Unable to send frame")
                   })
        );
        debug!("Performing the actual send frame IO");
        self.inner.send_raw_frame(frame)
    }
}

/// A handle to the `ChannelFrameSender` and an implementation of the `SendFrame` trait. It simply
/// queues the given frames into the send queue of the `ChannelFrameSender` without ever blocking.
/// (Except possibly to allocate some memory, as per the `mpsc::channel` specification.)
struct ChannelFrameSenderHandle {
    /// The sender side of the channel that buffers the frames to be written. Allows the handle to
    /// queue the frame for future writing without blocking on the IO.
    tx: Sender<RawFrame>,
}

impl SendFrame for ChannelFrameSenderHandle {
    fn send_raw_frame(&mut self, frame: RawFrame) -> HttpResult<()> {
        try!(self.tx.send(frame)
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::Other, "Unable to send frame")
                    }));
        debug!("Queued the frame for sending...");
        Ok(())
    }
}

/// An enum that represents errors that can be raised by the operation of a
/// `ClientService`.
enum ClientServiceErr {
    /// Corresponds to the case where the service has finished its operation.
    Done,
    /// Corresponds to the case where the service is unable to continue due to
    /// an error that occurred on the underlying HTTP/2 connection.
    Http(HttpError),
}

/// An internal struct encapsulating a service that lets multiple clients
/// issue concurrent requests to the same HTTP/2 connection.
///
/// The service handles issuing requests that it receives on a channel (the
/// receiving end of it is `rx`) to the server and relaying the requests to
/// the corresponding channel (the one given in the `AsyncRequest` instance
/// that was read off the requests channel).
///
/// The service does not automatically start running in a background thread.
/// The user needs to start that explicitly and decide how they want to handle
/// running the `run_once` method.
struct ClientService {
    /// The ID that will be assigned to the next client-initiated stream.
    next_stream_id: StreamId,
    /// The number of requests that have been sent, but are yet unanswered.
    outstanding_reqs: u32,
    /// The limit to the number of requests that can be pending (unanswered,
    /// but sent).
    limit: u32,
    /// The connection that is used for underlying HTTP/2 communication.
    conn: ClientConnection<TcpStream, TcpStream, DefaultSession>,
    /// A mapping of stream IDs to the sender side of a channel that is
    /// expecting a response to the request that is to arrive on that stream.
    chans: HashMap<StreamId, Sender<Response>>,
    /// The receiver end of a channel to which requests that clients wish to
    /// issue are queued.
    rx: Receiver<AsyncRequest>,
}

impl ClientService {
    /// Creates a new `ClientService` that will communicate over a new HTTP/2
    /// connection to the server found at the given host and port combination.
    ///
    /// # Returns
    ///
    /// Returns the newly created `ClientService` and the sender side of the
    /// channel on which the new service instance expects requests to arrive.
    ///
    /// If no HTTP/2 connection can be established to the given host on the
    /// given port, returns `None`.
    pub fn new(host: &str, port: u16) -> Option<(ClientService, Sender<AsyncRequest>)> {
        let (tx, rx): (Sender<AsyncRequest>, Receiver<AsyncRequest>) =
                mpsc::channel();
        let mut stream = TcpStream::connect(&(host, port)).unwrap();
        // The async client doesn't use the `HttpConnect` API for establishing the
        // connection, so it has to write the preface manually.
        // (It also just unwraps everything with no real error checking, as it's
        // mostly a demo/proof-of-concept of an async client implementation.)
        write_preface(&mut stream).unwrap();
        let mut conn = ClientConnection::with_connection(
                HttpConnection::<TcpStream, TcpStream>::with_stream(
                    stream,
                    HttpScheme::Http,
                    host.into()),
                DefaultSession::<DefaultStream>::new());
        match conn.init() {
            Ok(_) => {},
            Err(_) => return None,
        };

        let service = ClientService {
            next_stream_id: 1,
            outstanding_reqs: 0,
            limit: 3,
            conn: conn,
            chans: HashMap::new(),
            rx: rx,
        };

        Some((service, tx))
    }

    /// Performs one iteration of the service.
    ///
    /// If there are no currently oustanding requests (sent, but yet no full
    /// response received), the function blocks until a new request is received.
    /// Once there is a new request, it will be sent to the server in its
    /// entirety.
    ///
    /// If there is an outstanding request, the function tries to handle the
    /// response-related payload incoming on the HTTP/2 connection. This could
    /// be more than one HTTP/2 frame since `SETTINGS` or other frames might be
    /// interleaved with `DATA` and `HEADERS` frames representing the responses.
    ///
    /// Any received responses after handling the first payload are sent to the
    /// corresponding channel that is expecting the particular response.
    ///
    /// Finally, an additional request is sent (in its entirety) if the limit
    /// to the number of concurrent requests was not reached and there are
    /// queued requests from clients.
    ///
    /// # Returns
    ///
    /// On a successful pass, the function returns an `Ok(())`.
    ///
    /// The `Err` response is returned when there are no more responses to be
    /// received and there are no more clients connected to the service (and
    /// thus no more requests could ever be issued by the instance). This
    /// corresponds to the `ClientServiceErr::Done` variant.
    ///
    /// Any HTTP/2 error is propagated (wrapped into a ClientServiceErr::Http
    /// variant).
    pub fn run_once(&mut self) -> Result<(), ClientServiceErr> {
        // If there are no responses that we should read, block until there's
        // a new request. This precludes handling server pushes, pings, or
        // settings changes that may happen in the mean time until there's a
        // new request, since nothing is reading from the connection until then.
        if self.outstanding_reqs == 0 {
            debug!("Service thread blocking until there's a new request...");
            let async_req = match self.rx.recv() {
                Ok(req) => req,
                // The receive operation can only fail if the sender has
                // disconnected implying no further receives are possible.
                // At that point, we make sure to gracefully stop the service.
                Err(_) => return Err(ClientServiceErr::Done),
            };
            self.send_request(async_req);
        }

        // Handles the next frame...
        debug!("Handling next frame");
        match self.conn.handle_next_frame() {
            Ok(_) => {},
            Err(e) => return Err(ClientServiceErr::Http(e)),
        };
        // ...and then any connections that may have been closed in the meantime
        // are converted to responses and notifications sent to appropriate
        // channels.
        self.handle_closed();
        // At this point we try to queue another outstanding request (if the
        // limit has not been reached).
        self.queue_next_request();

        Ok(())
    }

    /// Internal helper method. Sends a request to the server based on the
    /// parameters given in the `AsyncRequest`. It blocks until the request is
    /// fully transmitted to the server.
    fn send_request(&mut self, async_req: AsyncRequest) {
        let req = self.create_request(
                                 async_req.method,
                                 async_req.path,
                                 async_req.headers);

        debug!("Sending new request... id = {}", req.stream_id);

        self.conn.session.new_stream(req.stream_id);
        self.chans.insert(req.stream_id, async_req.tx);
        self.conn.send_request(req).ok().unwrap();
        self.outstanding_reqs += 1;
    }

    /// Internal helper method. Creates a new `Request` instance based on the
    /// given parameters. Such a `Request` instance is ready to be passed to
    /// the connection for transmission to the server.
    fn create_request(&mut self,
                      method: Vec<u8>,
                      path: Vec<u8>,
                      extra_headers: Vec<Header>) -> Request {
        let mut headers: Vec<Header> = Vec::new();
        headers.extend(vec![
            (b":method".to_vec(), method),
            (b":path".to_vec(), path),
            (b":authority".to_vec(), self.conn.host().as_bytes().to_vec()),
            (b":scheme".to_vec(), self.conn.scheme().as_bytes().to_vec()),
        ].into_iter());
        headers.extend(extra_headers.into_iter());

        let req = Request {
            stream_id: self.next_stream_id,
            headers: headers,
            body: Vec::new(),
        };
        self.next_stream_id += 2;

        req
    }

    /// Internal helper method. Sends a response assembled from the given
    /// stream to the corresponding channel that is waiting for the response.
    ///
    /// The given `stream` instance is consumed by this method.
    fn send_response(&mut self, stream: DefaultStream) {
        match self.chans.remove(&stream.stream_id) {
            None => {
                // This should never happen, it means the session gave us
                // a response that we didn't request.
                panic!("Received a response for an unknown request!");
            },
            Some(tx) => {
                let _ = tx.send(Response {
                    stream_id: stream.stream_id,
                    headers: stream.headers.unwrap(),
                    body: stream.body,
                });
            }
        };
    }

    /// Internal helper method. Handles all closed streams by sending appropriate
    /// notifications to waiting channels.
    ///
    /// For now, the channels are all given a `Response`, even though the
    /// stream might end up being closed by the server with an error.
    fn handle_closed(&mut self) {
        let done = self.conn.session.get_closed();
        for stream in done {
            self.send_response(stream);
            self.outstanding_reqs -= 1;
        }
    }

    /// Internal helper method. If there are yet unsent requests queued by a
    /// client to the service and the service has not exceeded the limit of
    /// concurrent requests that it is allowed to issue, it sends a single
    /// new request to the server. Blocks until this request is sent.
    fn queue_next_request(&mut self) {
        if self.outstanding_reqs < self.limit {
            // Try to queue another request since we haven't gone over
            // the (arbitrary) limit.
            debug!("Not over the limit yet. Checking for more requests...");
            if let Ok(async_req) = self.rx.try_recv() {
                self.send_request(async_req);
            }
        }
    }
}

/// A struct representing an HTTP/2 client that receives responses to its
/// requests asynchronously. Additionally, this client can be cloned and all
/// clones can issue (concurrently) requests to the server, using the same
/// underlying HTTP/2 connection.
///
/// # Example
///
/// ```no_run
/// use solicit::client::Client;
/// use std::thread;
/// use std::str;
///
/// // Connect to a server that supports HTTP/2
/// let client = Client::new("nghttp2.org", 80).unwrap();
///
/// // Issue 5 requests from 5 different threads concurrently and wait for all
/// // threads to receive their response.
/// let threads: Vec<_> = (0..5).map(|i| {
///     let this = client.clone();
///     thread::spawn(move || {
///         let resp = this.get(b"/", &[]).unwrap();
///         let response = resp.recv().unwrap();
///         println!("Thread {} got response ... {}", i, response.status_code().ok().unwrap());
///         println!("The response contains the following headers:");
///         for header in response.headers.iter() {
///             println!("  {}: {}",
///                   str::from_utf8(&header.0).unwrap(),
///                   str::from_utf8(&header.1).unwrap());
///         }
///     })
/// }).collect();
///
/// let _: Vec<_> = threads.into_iter().map(|thread| thread.join()).collect();
/// ```
#[derive(Clone)]
pub struct Client {
    /// The sender side of a channel on which a running `ClientService` expects
    /// to receive new requests, which are to be sent to the server.
    sender: Sender<AsyncRequest>,
}

impl Client {
    /// Creates a brand new HTTP/2 client. This means that a new HTTP/2
    /// connection will be established behind the scenes. A thread is spawned
    /// to handle the connection in the background, so that the thread that
    /// creates the client can use it asynchronously.
    ///
    /// # Returns
    ///
    /// A `Client` instance that allows access to the underlying HTTP/2
    /// connection on the application level. Only full requests and responses
    /// are exposed to users.
    ///
    /// The returned `Client` can be cloned and all clones will use the same
    /// underlying HTTP/2 connection. Once all cloned instances (as well as the
    /// original one) are dropped, the thread that was spawned will also exit
    /// gracefully. Any error on the underlying HTTP/2 connection also causes
    /// the thread to exit.
    ///
    /// If the HTTP/2 connection cannot be initialized returns `None`.
    pub fn new(host: &str, port: u16) -> Option<Client> {
        let (mut service, rx) = match ClientService::new(host, port) {
            Some((service, rx)) => (service, rx),
            None => return None,
        };

        thread::spawn(move || {
            while let Ok(_) = service.run_once() {}
            debug!("Service thread halting");
        });

        Some(Client {
            sender: rx,
        })
    }

    /// Issues a new request to the server.
    ///
    /// The request's method, path, and extra headers are provided as parameters.
    /// The headers should *never* include any meta-headers (such as `:method`).
    ///
    /// # Returns
    ///
    /// The method itself returns immediately upon queuing the request. It does
    /// not wait for the request to be transmitted nor for the response to
    /// arrive. Once the caller is interested in the final response, they can
    /// block on the returned `Receiver` end of a channel which will receive
    /// the response once generated.
    ///
    /// The `Response` instance that the channel receives will contain the full
    /// response body and is available only once the full response body has
    /// been received.
    ///
    /// If the method is unable to queue the request, it must mean that the
    /// underlying HTTP/2 connection to which this client is associated has
    /// failed and it returns `None`.
    pub fn request(&self, method: &[u8], path: &[u8], headers: &[Header])
            -> Option<Receiver<Response>> {
        let (resp_tx, resp_rx): (Sender<Response>, Receiver<Response>) =
                mpsc::channel();
        // A send can only fail if the receiver is disconnected. If the send
        // fails here, it means that the service hit an error on the underlying
        // HTTP/2 connection and will never come alive again.
        let res = self.sender.send(AsyncRequest {
            method: method.to_vec(),
            path: path.to_vec(),
            headers: headers.to_vec(),
            tx: resp_tx,
        });

        match res {
            Ok(_) => Some(resp_rx),
            Err(_) => None,
        }
    }

    /// Issues a GET request to the server.
    ///
    /// A convenience wrapper around the `request` method that sets the correct
    /// method.
    pub fn get(&self, path: &[u8], headers: &[Header]) -> Option<Receiver<Response>> {
        self.request(b"GET", path, headers)
    }
}
