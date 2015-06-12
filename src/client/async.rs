//! Contains an implementation of an asynchronous client.
//!
//! It allows users to make requests to the same underlying connection from
//! different threads concurrently, as well as to receive the response
//! asynchronously.
use std::collections::HashMap;

use std::sync::mpsc::{Sender, Receiver};
use std::sync::mpsc;
use std::thread;
use std::io;

use http::{StreamId, HttpError, Response, Header, HttpResult};
use http::frame::RawFrame;
use http::transport::TransportStream;
use http::connection::{SendFrame, ReceiveFrame, HttpFrame, HttpConnection};
use http::session::{SessionState, DefaultSessionState, DefaultStream, Stream};
use http::client::{ClientConnection, HttpConnect, ClientStream, RequestStream};

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
    /// The body of the request, if any.
    pub body: Option<Vec<u8>>,
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

/// A struct that buffers `HttpFrame`s read by the wrapped `ReceiveFrame` instance in an internal
/// `mpsc` channel. The reads from the wrapped `ReceiveFrame` instance are triggered by calls to
/// the `read_next` method.
///
/// Additionally, it provides a `ChannelFrameReceiverHandle` instance that implements the
/// `ReceiveFrame` trait, such that it pops the next available frame from the internal channel.
/// If there are no available frames, it will block, so care must be taken to trigger the
/// connection's frame handling only when there are buffered frames, if it is not to block.
///
/// As such, this is a convenience struct that makes it possible to provide non-blocking reads
/// from within `HttpConnection`s, while handling the actual reads using a `ReceiveFrame`
/// implementation that can block. (Predicated on triggering a single frame handle operation on
/// the connection for each successfully executed `read_next`.)
struct ChannelFrameReceiver<R> where R: ReceiveFrame {
    /// The sender side of the channel. Buffers the frames read by the wrapped `ReceiveFrame`
    /// instance for future consumation by the associated `ChannelFrameReceiverHandle`.
    tx: Sender<HttpFrame>,
    /// The `ReceiveFrame` instance that performs the actual reading of the frame, used from within
    /// the `read_next` method.
    inner: R,
}

impl<R> ChannelFrameReceiver<R> where R: ReceiveFrame {
    /// Creates a new `ChannelFrameReceiver`, as well as the associated
    /// `ChannelFrameReceiverHandle`.
    fn new(inner: R) -> (ChannelFrameReceiver<R>, ChannelFrameReceiverHandle) {
        let (send, recv) = mpsc::channel();

        let handle = ChannelFrameReceiverHandle { rx: recv };
        let receiver = ChannelFrameReceiver {
            tx: send,
            inner: inner,
        };
        (receiver, handle)
    }

    /// Performs a `recv_frame` operation on the wrapped `ReceiveFrame` instance, possibly blocking
    /// the thread in the process, depending on the implementation of the trait. Once a frame is
    /// returned, it will buffer it within the internal channel.
    fn read_next(&mut self) -> HttpResult<()> {
        let frame = try!(self.inner.recv_frame());
        try!(self.tx.send(frame)
                    .map_err(|_| {
                        io::Error::new(io::ErrorKind::Other, "Unable to read frame")
                    }));
        Ok(())
    }
}

/// A handle to the `ChannelFrameReceiver` and an implementation of the `ReceiveFrame` trait.
/// It simply pops the next frame from the internal channel that buffers the frames read by the
/// `ReceiveFrame` instance wrapped by the associated `ChannelFrameReceiver`. If there are no
/// frames currently buffered, it blocks until there is one. Therefore, the `handle_next_frame`
/// method of the `HttpConnection` that relies on the IO provided by this `ReceiveFrame`
/// implementation should be triggered only when sure that there are buffered frames, if blocking
/// handles are to be avoided.
struct ChannelFrameReceiverHandle {
    /// The receiver end of the channel that buffers the received frames.
    rx: Receiver<HttpFrame>,
}

impl ReceiveFrame for ChannelFrameReceiverHandle {
    fn recv_frame(&mut self) -> HttpResult<HttpFrame> {
        self.rx.recv()
            .map_err(|_| {
                HttpError::from(io::Error::new(io::ErrorKind::Other, "Unable to read frame"))
            })
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

impl From<HttpError> for ClientServiceErr {
    fn from(err: HttpError) -> ClientServiceErr { ClientServiceErr::Http(err) }
}

/// An enum representing the types of work that the `ClientService` can perform from within its
/// `run_once` method.
enum WorkItem {
    /// Queue a new request to the HTTP/2 connection.
    Request(AsyncRequest),
    /// Trigger a new `handle_next_frame`. The work item should be queued only when there is a
    /// frame to be handled to avoid blocking the `run_once` call.
    HandleFrame,
    /// Trigger a new `send_next_data` operation.
    SendData,
    /// Signals to the service that a new client is connected. Helps it keep track of whether there
    /// are clients that would expect a response.
    NewClient,
    /// Signals to the service that a client has disconnected. Helps it keep track of whether there
    /// are clients that would expect a response.
    ClientLeft,
}

/// An internal struct encapsulating a service that lets multiple clients
/// issue concurrent requests to the same HTTP/2 connection.
///
/// The service maintains an internal queue of `WorkItem`s that indicate what the operations that
/// it should perform. The next operation from the queue is performed on each `run_once` method
/// call.
///
/// It handles issuing new requests (corresponding to `WorkItem::Request` work item), handling the
/// next received frame (when indicated by the `WorkItem::HandleFrame`), and tracks the number of
/// connected clients (`run_once` returns an error once there are no more clients connected to the
/// service).
///
/// If there is no work in the queue, the `run_once` method blocks.
///
/// Essentially, this represents a simplified event loop that handles events queued on the work
/// queue (blocking to wait for new work when none is available; does not spin). Therefore, the
/// user of the `ClientService` needs to provide a dedicated thread in which to run the `run_once`
/// event loop handler.
///
/// Additionally, the client needs to make sure to perform the actual socket IO (which is fully
/// blocking, without even timeout support currently in Rust) in threads dedicated for that, by
/// calling the `send_next` or `read_next` methods of the `ChannelFrameSender` or
/// `ChannelFrameReceiver`, which are returned from the `ClientService` constructor.
///
/// TODO: Technically, the `run_once` method could take a `WorkItem`, so a single event loop could
///       dispatch work items to a corresponding service, removing the need for the
///       thread-per-service requirement. However, at that point we're nearing a reimplementation
///       of a real event loop, which is slightly out of scope of the `solicit` library, as
///       imagined; the async client is (for now) supposed to be a proof-of-concept
///       implementation of a high-level async/concurrent HTTP/2 client.
struct ClientService {
    /// The ID that will be assigned to the next client-initiated stream.
    next_stream_id: StreamId,
    /// The number of requests that have been sent, but are yet unanswered.
    outstanding_reqs: u32,
    /// The limit to the number of requests that can be pending (unanswered,
    /// but sent).
    limit: u32,
    /// The connection that is used for underlying HTTP/2 communication.
    conn: ClientConnection<ChannelFrameSenderHandle, ChannelFrameReceiverHandle>,
    /// A mapping of stream IDs to the sender side of a channel that is
    /// expecting a response to the request that is to arrive on that stream.
    chans: HashMap<StreamId, Sender<Response>>,
    /// The receiver end of a channel to which work items for the service are
    /// queued. Work items include the variants of the `WorkItem` enum.
    work_queue: Receiver<WorkItem>,
    /// The queue of `AsyncRequest`s that haven't yet been sent to the server.
    request_queue: Vec<AsyncRequest>,
    /// Tracks the number of currently connected clients -- once it reaches 0, the `run_once`
    /// method returns an error.
    client_count: i32,
    /// The name of the host the connection is established to.
    host: Vec<u8>,
    /// Whether the connection has already been initialized.
    initialized: bool,
}

/// A helper wrapper around the components of the `ClientService` that are returned from its
/// constructor.
struct Service<S>(
    ClientService,
    Sender<WorkItem>,
    ChannelFrameReceiver<S>,
    ChannelFrameSender<S>) where S: TransportStream;

impl ClientService {
    /// Creates a new `ClientService` that will use the provided `ClientStream` for its underlying
    /// network communication. A handle is returned for both the read, as well as the write end of
    /// the socket that allows the client that creates the `ClientService` to perform the blocking
    /// IO without influencing the `ClientService` (i.e. without having its `run_once` method
    /// block).
    ///
    /// # Returns
    ///
    /// Returns all the relevant components of the newly created `ClientService`:
    ///
    /// - The `ClientService` itself -- processes events (`WorkItem`s) on each `run_once` call.
    /// - The sender-side of the work queue -- allows `WorkItem`s to be queued into the
    ///   `ClientService`'s simplified event loop.
    /// - The `ChannelFrameReceiver` -- the instance that wraps the actual socket that performs
    ///   the blocking read IO. Allows the caller to block on the IO in a customized manner (e.g.
    ///   in a separate dedicated thread).
    /// - The `ChannelFrameSender` -- the instance that wraps the actual socket that performs the
    ///   blocking write IO. Allows the caller to block on the IO in a customized manner (e.g. in
    ///   a separate thread).
    ///
    /// If no HTTP/2 connection can be established to the given host on the
    /// given port, returns `None`.
    pub fn new<S>(client_stream: ClientStream<S>) -> Option<Service<S>>
            where S: TransportStream {
        let (tx, rx): (Sender<WorkItem>, Receiver<WorkItem>) =
                mpsc::channel();
        let ClientStream(stream, scheme, host) = client_stream;

        // Manually split the stream into the write/read ends, so that we can...
        let sender = stream.try_split().unwrap();
        let receiver = stream;
        // ...wrap them into the adapters...
        let (recv_frame, recv_handle) = ChannelFrameReceiver::new(receiver);
        let (send_frame, send_handle) = ChannelFrameSender::new(sender);

        // ...and pass the non-blocking/buffering ends into the `HttpConnect` instead of the
        // blocking socket itself.
        let conn = ClientConnection::with_connection(
                HttpConnection::new(
                    send_handle,
                    recv_handle,
                    scheme),
                DefaultSessionState::new());

        let service = ClientService {
            next_stream_id: 1,
            outstanding_reqs: 0,
            limit: 3,
            conn: conn,
            chans: HashMap::new(),
            work_queue: rx,
            request_queue: Vec::new(),
            client_count: 0,
            host: host.as_bytes().to_vec(),
            initialized: false,
        };

        // Returns the handles to the channel sender/receiver, so that the client can use them to
        // perform the real IO somewhere.
        Some(Service(service, tx, recv_frame, send_frame))
    }

    /// Performs one iteration of the service.
    ///
    /// One iteration corresponds to running the next `WorkItem` that the service
    /// has queued in its `work_queue`. Essentially, this is a poor-man's event
    /// loop implementation. If there is no work queued for the service, it will
    /// *block*, until there is. As such, embedding calls to this method into a
    /// real event loop should not be done.
    ///
    /// For `WorkItem::Request` work items, the service will queue the received
    /// `AsyncRequest` for sending. It will also attempt to queue it for
    /// transmission to the server, unless the concurrent requests limit has been
    /// exceeded, in which case the request is kept in an internal FIFO queue and
    /// will be sent when its time comes.
    ///
    /// For `WorkItem::HandleFrame` work items, the service will perform a single
    /// `handle_next_frame` call on its underlying `ClientConnection` instance.
    /// Since the item is queued only when the connection actually has frames to
    /// process, this call will never block. If a response got finalized by the
    /// handling of the frame, it is shipped to the channel that expects it and
    /// a new request from the request queue sent.
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
        let work_item = match self.work_queue.recv() {
            Ok(item) => item,
            // The receive operation can only fail if the sender has
            // disconnected implying no further receives are possible.
            // At that point, we make sure to gracefully stop the service.
            Err(_) => return Err(ClientServiceErr::Done),
        };

        // Dispatch the work to the corresponding method...
        match work_item {
            WorkItem::Request(async_req) => {
                debug!("Queuing request");
                self.request_queue.push(async_req);
                self.queue_next_request();
                Ok(())
            },
            WorkItem::HandleFrame => {
                if !self.initialized {
                    try!(self.conn.init());
                    self.initialized = true;
                    Ok(())
                } else {
                    self.handle_frame()
                }
            },
            WorkItem::SendData => {
                debug!("Will queue some request data");
                try!(self.conn.send_next_data());
                Ok(())
            }
            WorkItem::NewClient => {
                self.client_count += 1;
                Ok(())
            },
            WorkItem::ClientLeft => {
                self.client_count -= 1;
                if self.client_count == 0 {
                    Err(ClientServiceErr::Done)
                } else {
                    Ok(())
                }
            }
        }
    }

    /// A private convenience method that performs the handling of the next received frame.
    ///
    /// It calls the underlying connection's `handle_next_frame` method and then inspects the
    /// changes made to the session, notifying clients of completed requests or queueing new ones,
    /// if available.
    fn handle_frame(&mut self) -> Result<(), ClientServiceErr> {
        // Handles the next frame...
        debug!("Handling next frame");
        try!(self.conn.handle_next_frame());
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
        let (req, tx) = self.create_request(async_req);

        debug!("Sending new request... id = {}", req.stream.id());

        self.chans.insert(req.stream.id(), tx);
        self.conn.start_request(req).ok().unwrap();
        self.outstanding_reqs += 1;
    }

    /// Internal helper method. Creates a new `RequestStream` instance based on the
    /// given parameters. Such a `RequestStream` instance is ready to be passed to
    /// the connection for transmission to the server (i.e. `start_request`).
    /// Also returns the sender end of the channel to which the response is to be transmitted,
    /// once received.
    fn create_request(&mut self, async_req: AsyncRequest)
            -> (RequestStream<DefaultStream>, Sender<Response>) {
        let mut headers: Vec<Header> = Vec::new();
        headers.extend(vec![
            (b":method".to_vec(), async_req.method),
            (b":path".to_vec(), async_req.path),
            (b":authority".to_vec(), self.host.clone()),
            (b":scheme".to_vec(), self.conn.scheme().as_bytes().to_vec()),
        ].into_iter());
        headers.extend(async_req.headers.into_iter());

        let mut stream = DefaultStream::new(self.next_stream_id);
        self.next_stream_id += 2;
        match async_req.body {
            Some(body) => stream.set_full_data(body),
            None => stream.close_local(),
        };

        (
            RequestStream {
                stream: stream,
                headers: headers,
            },
            async_req.tx
        )
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
        let done = self.conn.state.get_closed();
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
            if self.request_queue.len() > 0 {
                let async_req = self.request_queue.remove(0);
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
/// use solicit::http::client::CleartextConnector;
/// use std::thread;
/// use std::str;
///
/// // Connect to a server that supports HTTP/2
/// let connector = CleartextConnector::new("http2bin.org");
/// let client = Client::with_connector(connector).unwrap();
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
pub struct Client {
    /// The sender side of a channel on which a running `ClientService` expects
    /// to receive new requests, which are to be sent to the server.
    sender: Sender<WorkItem>,
}

impl Clone for Client {
    fn clone(&self) -> Client {
        self.sender.send(WorkItem::NewClient).unwrap();
        Client {
            sender: self.sender.clone(),
        }
    }
}

impl Drop for Client {
    fn drop(&mut self) {
        let _ = self.sender.send(WorkItem::ClientLeft);
    }
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
    pub fn with_connector<C, S>(connector: C) -> Option<Client>
            where C: HttpConnect<Stream=S>, S: TransportStream + Send + 'static {
        // Use the provided connector to establish a network connection...
        let client_stream = connector.connect().ok().unwrap();
        // Keep a socket handle in order to shut it down once the service stops. This is required
        // because if the service decides to stop (due to all clients disconnecting) while the
        // socket is still open and the read thread waiting, it can happen that the read thread
        // (and as such the socket itself) ends up waiting indefinitely (or well, until the server
        // decides to close it), effectively leaking the socket and thread.
        let mut sck = client_stream.0.try_split().unwrap();

        let service = match ClientService::new(client_stream) {
            Some(service) => service,
            None => return None,
        };
        let Service(mut service, rx, mut recv_frame, mut send_frame) = service;

        if let Err(_) = rx.send(WorkItem::NewClient) {
            return None;
        }

        // Keep a handle to the work queue to notify the service of newly read frames, making it so
        // that it never blocks on waiting for frames to read.
        let read_notify = rx.clone();
        let sender_work_queue = rx.clone();

        thread::spawn(move || {
            while let Ok(_) = service.run_once() {}
            debug!("Service thread halting");
            // This is the one place where it's okay to unwrap, as if the shutdown fails, there's
            // really nothing we can do to recover at this point...
            // This forces the reader thread to stop, as the socket is no longer operational.
            sck.close().unwrap();
        });
        thread::spawn(move || {
            while let Ok(_) = send_frame.send_next() {
                sender_work_queue.send(WorkItem::SendData).unwrap();
            }
            debug!("Sender thread halting");
        });
        thread::spawn(move || {
            while let Ok(_) = recv_frame.read_next() {
                read_notify.send(WorkItem::HandleFrame).unwrap();
            }
            debug!("Reader thread halting");
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
    pub fn request(&self, method: &[u8], path: &[u8], headers: &[Header], body: Option<Vec<u8>>)
            -> Option<Receiver<Response>> {
        let (resp_tx, resp_rx): (Sender<Response>, Receiver<Response>) =
                mpsc::channel();
        // A send can only fail if the receiver is disconnected. If the send
        // fails here, it means that the service hit an error on the underlying
        // HTTP/2 connection and will never come alive again.
        let res = self.sender.send(WorkItem::Request(AsyncRequest {
            method: method.to_vec(),
            path: path.to_vec(),
            headers: headers.to_vec(),
            body: body,
            tx: resp_tx,
        }));

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
        self.request(b"GET", path, headers, None)
    }

    /// Issues a POST request to the server.
    ///
    /// Returns the receiving end of a channel where the `Response` will eventually be pushed.
    pub fn post(&self, path: &[u8], headers: &[Header], body: Vec<u8>)
            -> Option<Receiver<Response>> {
        self.request(b"POST", path, headers, Some(body))
    }
}
