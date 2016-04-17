//! The module contains some common utilities for `solicit::http` tests.

use std::io;
use std::rc::Rc;
use std::cell::{RefCell, Cell};
use std::borrow::Cow;
use std::io::{Cursor, Read, Write};

use http::{HttpResult, HttpScheme, StreamId, Header, OwnedHeader, ErrorCode};
use http::frame::{RawFrame, FrameIR, FrameHeader, pack_header, HttpSetting, PingFrame};
use http::session::{Session, DefaultSessionState, SessionState, Stream, StreamState,
                    StreamDataChunk, StreamDataError};
use http::session::Client as ClientMarker;
use http::priority::DataPrioritizer;
use http::transport::TransportStream;
use http::connection::{SendFrame, ReceiveFrame, HttpFrame, HttpConnection, EndStream, DataChunk};
use http::client::ClientConnection;
use http::server::StreamFactory;

/// Creates a new `RawFrame` from two separate parts: the header and the payload.
/// Useful for tests that need to create frames, since they can easily specify the header and the
/// payload separately and use this function to stitch them together into a `RawFrame`.
pub fn raw_frame_from_parts<'a>(header: FrameHeader, payload: Vec<u8>) -> RawFrame<'a> {
    let mut buf = Vec::new();
    assert_eq!(9, buf.write(&pack_header(&header)[..]).unwrap());
    assert_eq!(payload.len(), buf.write(&payload).unwrap());
    buf.into()
}

/// Serializes the given frame into a newly allocated vector (without consuming the frame).
pub fn serialize_frame<F: FrameIR + Clone>(frame: &F) -> Vec<u8> {
    let mut buf = io::Cursor::new(Vec::new());
    frame.clone().serialize_into(&mut buf).ok().expect("Expected the serialization to succeed");
    buf.into_inner()
}

/// A mock `SendFrame` implementation that simply saves all frames that it is to send to a `Vec`.
pub struct MockSendFrame {
    pub sent: Vec<RawFrame<'static>>,
}

impl MockSendFrame {
    pub fn new() -> MockSendFrame {
        MockSendFrame { sent: Vec::new() }
    }
}

impl SendFrame for MockSendFrame {
    fn send_frame<F: FrameIR>(&mut self, frame: F) -> HttpResult<()> {
        let mut buf = io::Cursor::new(Vec::new());
        frame.serialize_into(&mut buf).unwrap();
        let raw = buf.into_inner().into();
        self.sent.push(raw);
        Ok(())
    }
}

/// A mock `ReceiveFrame` implementation that simply serves the frames from a `Vec`.
pub struct MockReceiveFrame<'a> {
    pub recv_list: Vec<HttpFrame<'a>>,
}

impl<'a> MockReceiveFrame<'a> {
    pub fn new(recv_list: Vec<HttpFrame<'a>>) -> MockReceiveFrame<'a> {
        MockReceiveFrame { recv_list: recv_list }
    }
}

impl<'a> ReceiveFrame for MockReceiveFrame<'a> {
    fn recv_frame(&mut self) -> HttpResult<HttpFrame> {
        if self.recv_list.len() != 0 {
            Ok(self.recv_list.remove(0))
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "End of Frame List").into())
        }
    }
}

pub type MockHttpConnection = HttpConnection;

/// A helper function that creates an `HttpConnection` with the `MockSendFrame` and the
/// `MockReceiveFrame` as its underlying frame handlers.
pub fn build_mock_http_conn() -> MockHttpConnection {
    HttpConnection::new(HttpScheme::Http)
}

/// A helper stub implementation of a `TransportStream`.
///
/// When read from this stream, it spits out bytes from a predefined `Vec`
/// in the original given order. Once those are exhausted, it returns an EOF.
///
/// When writng to the stream, the bytes are aggregated to internal buffer.
/// The contents of the buffer can be accessed using the `get_writted`
/// method.
///
/// It is possible to "close" the stream (both ends at once) so that
/// aftwerwards any read or write attempt returns an `io::Error`;
#[derive(Clone)]
pub struct StubTransportStream {
    reader: Rc<RefCell<Cursor<Vec<u8>>>>,
    writer: Rc<RefCell<Cursor<Vec<u8>>>>,
    closed: Rc<Cell<bool>>,
}

impl StubTransportStream {
    /// Initializes the stream with the given byte vector representing
    /// the bytes that will be read from the stream.
    pub fn with_stub_content(stub: &[u8]) -> StubTransportStream {
        StubTransportStream {
            reader: Rc::new(RefCell::new(Cursor::new(stub.to_vec()))),
            writer: Rc::new(RefCell::new(Cursor::new(Vec::new()))),
            closed: Rc::new(Cell::new(false)),
        }
    }

    /// Returns a slice representing the bytes already written to the
    /// stream.
    pub fn get_written(&self) -> Vec<u8> {
        self.writer.borrow().get_ref().to_vec()
    }
}

impl io::Read for StubTransportStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.closed.get() {
            Err(io::Error::new(io::ErrorKind::Other, "Closed"))
        } else {
            self.reader.borrow_mut().read(buf)
        }
    }
}

impl io::Write for StubTransportStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.closed.get() {
            Err(io::Error::new(io::ErrorKind::Other, "Closed"))
        } else {
            self.writer.borrow_mut().write(buf)
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.borrow_mut().flush()
    }
}

impl TransportStream for StubTransportStream {
    fn try_split(&self) -> Result<StubTransportStream, io::Error> {
        Ok(self.clone())
    }

    /// Closes the stream, making any read or write operation return an
    /// `io::Error` from there on out.
    fn close(&mut self) -> io::Result<()> {
        self.closed.set(true);
        Ok(())
    }
}

/// A helper function that builds a buffer of bytes from the given `Vec` of
/// `HttpFrame`s, by serializing them in the given order.
pub fn build_stub_from_frames(frames: &Vec<HttpFrame>) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    for frame in frames.iter() {
        let serialized = match *frame {
            HttpFrame::DataFrame(ref frame) => serialize_frame(frame),
            HttpFrame::HeadersFrame(ref frame) => serialize_frame(frame),
            HttpFrame::RstStreamFrame(ref frame) => serialize_frame(frame),
            HttpFrame::SettingsFrame(ref frame) => serialize_frame(frame),
            HttpFrame::PingFrame(ref frame) => serialize_frame(frame),
            HttpFrame::GoawayFrame(ref frame) => serialize_frame(frame),
            HttpFrame::WindowUpdateFrame(ref frame) => serialize_frame(frame),
            HttpFrame::UnknownFrame(ref frame) => serialize_frame(frame),
        };
        buf.extend(serialized.into_iter());
    }

    buf
}

/// A test that makes sure that the `StubTransportStream` exhibits
/// properties that a "real" `TransportStream` would too.
#[test]
fn sanity_check_stub_stream() {
    // `read` returns 0 at the "end of file"?
    {
        let mut stream = StubTransportStream::with_stub_content(&vec![]);
        let mut buf = [0u8; 5];
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
        assert_eq!(stream.read(&mut buf).unwrap(), 0);
    }
    // A closed stream always returns an io::Error
    {
        let mut stream = StubTransportStream::with_stub_content(&vec![]);
        stream.close().unwrap();
        assert!(stream.write(&[1]).is_err());
        assert!(stream.read(&mut [0; 5]).is_err());
    }
    // A stream can be split
    {
        let mut stream = StubTransportStream::with_stub_content(&vec![3, 4]);
        let mut other = stream.try_split().unwrap();
        // Write something using both of them
        stream.write(&[1]).unwrap();
        other.write(&[2]).unwrap();
        assert_eq!(&[1, 2], &stream.get_written()[..]);
        assert_eq!(&[1, 2], &other.get_written()[..]);
        // Try reading independently...
        let mut buf = [0];
        stream.read(&mut buf).unwrap();
        assert_eq!(&[3], &buf);
        other.read(&mut buf).unwrap();
        assert_eq!(&[4], &buf);
    }
    // Closing one handle of the stream closes all handles
    {
        let mut stream = StubTransportStream::with_stub_content(&vec![3, 4]);
        let mut other = stream.try_split().unwrap();
        other.close().unwrap();
        assert!(stream.write(&[1]).is_err());
        assert!(stream.read(&mut [0; 5]).is_err());
    }
}

/// A helper struct implementing the `Session` trait, intended for testing
/// purposes.
///
/// It is basically a poor man's mock, providing us the ability to check
/// how many times the particular callbacks were called (although not the
/// order in which they were called).
///
/// Additionally, when created with `new_verify` it is possible to provide
/// a list of headers and data chunks and make the session verify that it
/// them from the connection in the exactly given order (i.e. relative
/// order of chunks and headers; there is no way to check the order between
/// chunks and headers for now).
pub struct TestSession {
    pub silent: bool,
    /// List of expected headers -- in the order that they are expected
    pub headers: Vec<Vec<OwnedHeader>>,
    /// List of expected data chunks -- in the order that they are expected
    pub chunks: Vec<Vec<u8>>,
    /// The current number of header calls.
    pub curr_header: usize,
    /// The current number of data chunk calls.
    pub curr_chunk: usize,
    /// The current number of `rst_stream` calls.
    pub rst_streams: Vec<StreamId>,
    /// All the goaway error codes received.
    pub goaways: Vec<ErrorCode>,
    /// All the ping data received
    pub pings: Vec<u64>,
    /// All the ping ack data received
    pub pongs: Vec<u64>,
}

impl TestSession {
    /// Returns a new `TestSession` that only counts how many times the
    /// callback methods were invoked.
    pub fn new() -> TestSession {
        TestSession {
            silent: true,
            headers: Vec::new(),
            chunks: Vec::new(),
            curr_header: 0,
            curr_chunk: 0,
            rst_streams: Vec::new(),
            goaways: Vec::new(),
            pings: Vec::new(),
            pongs: Vec::new(),
        }
    }

    /// Returns a new `TestSession` that veriies that the headers received
    /// in the callbacks are equal to those in the given headers `Vec` and
    /// that they come in exactly the given order. Does the same for chunks.
    pub fn new_verify(headers: Vec<Vec<OwnedHeader>>, chunks: Vec<Vec<u8>>) -> TestSession {
        TestSession {
            silent: false,
            headers: headers,
            chunks: chunks,
            curr_header: 0,
            curr_chunk: 0,
            rst_streams: Vec::new(),
            goaways: Vec::new(),
            pings: Vec::new(),
            pongs: Vec::new(),
        }
    }
}

impl Session for TestSession {
    fn new_data_chunk(&mut self,
                      _: StreamId,
                      data: &[u8],
                      _: &mut HttpConnection)
                      -> HttpResult<()> {
        if !self.silent {
            assert_eq!(&self.chunks[self.curr_chunk], &data);
        }
        self.curr_chunk += 1;
        Ok(())
    }

    fn new_headers<'n, 'v>(&mut self,
                           _: StreamId,
                           headers: Vec<Header<'n, 'v>>,
                           _: &mut HttpConnection)
                           -> HttpResult<()> {
        if !self.silent {
            assert_eq!(self.headers[self.curr_header], headers);
        }
        self.curr_header += 1;
        Ok(())
    }

    fn end_of_stream(&mut self, _: StreamId, _: &mut HttpConnection) -> HttpResult<()> {
        Ok(())
    }

    fn rst_stream(&mut self,
                  stream_id: StreamId,
                  _: ErrorCode,
                  _: &mut HttpConnection)
                  -> HttpResult<()> {
        self.rst_streams.push(stream_id);
        Ok(())
    }

    fn new_settings(&mut self,
                    _settings: Vec<HttpSetting>,
                    _conn: &mut HttpConnection)
                    -> HttpResult<()> {
        Ok(())
    }

    fn on_goaway(&mut self,
                 _: StreamId,
                 error_code: ErrorCode,
                 _: Option<&[u8]>,
                 _: &mut HttpConnection)
                 -> HttpResult<()> {
        self.goaways.push(error_code);
        Ok(())
    }

    fn on_ping(&mut self, ping: &PingFrame, _conn: &mut HttpConnection) -> HttpResult<()> {
        self.pings.push(ping.opaque_data());
        Ok(())
    }

    fn on_pong(&mut self, ping: &PingFrame, _conn: &mut HttpConnection) -> HttpResult<()> {
        self.pongs.push(ping.opaque_data());
        Ok(())
    }
}

/// A stream that can be used for testing purposes.
pub struct TestStream {
    pub body: Vec<u8>,
    pub headers: Option<Vec<OwnedHeader>>,
    pub state: StreamState,
    pub outgoing: Option<Cursor<Vec<u8>>>,
    pub errors: Vec<ErrorCode>,
}

impl TestStream {
    pub fn new() -> TestStream {
        TestStream {
            body: Vec::new(),
            headers: None,
            state: StreamState::Open,
            outgoing: None,
            errors: Vec::new(),
        }
    }

    #[inline]
    pub fn set_outgoing(&mut self, outgoing: Vec<u8>) {
        self.outgoing = Some(Cursor::new(outgoing));
    }
}

impl Stream for TestStream {
    fn new_data_chunk(&mut self, data: &[u8]) {
        self.body.extend(data.to_vec());
    }
    fn set_headers<'n, 'v>(&mut self, headers: Vec<Header<'n, 'v>>) {
        self.headers = Some(headers.into_iter()
                                   .map(|h| {
                                       let owned: OwnedHeader = h.into();
                                       owned.into()
                                   })
                                   .collect());
    }
    fn set_state(&mut self, state: StreamState) {
        self.state = state;
    }

    fn on_rst_stream(&mut self, error: ErrorCode) {
        self.errors.push(error);
        self.close();
    }
    fn get_data_chunk(&mut self, buf: &mut [u8]) -> Result<StreamDataChunk, StreamDataError> {
        if self.is_closed_local() {
            return Err(StreamDataError::Closed);
        }
        let chunk = match self.outgoing.as_mut() {
            // No data associated to the stream, but it's open => nothing available for writing
            None => StreamDataChunk::Unavailable,
            Some(d) => {
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
            _ => {}
        };

        Ok(chunk)
    }

    fn state(&self) -> StreamState {
        self.state
    }
}

pub struct TestStreamFactory;
impl StreamFactory for TestStreamFactory {
    type Stream = TestStream;
    fn create(&mut self, _id: StreamId) -> TestStream {
        TestStream::new()
    }
}

/// A `DataPrioritizer` implementation that returns data chunks from a predefined buffer given to
/// it at construct time (always on stream ID 1).
pub struct StubDataPrioritizer {
    pub chunks: Vec<Vec<u8>>,
}

impl StubDataPrioritizer {
    pub fn new(chunks: Vec<Vec<u8>>) -> StubDataPrioritizer {
        StubDataPrioritizer { chunks: chunks }
    }
}

impl DataPrioritizer for StubDataPrioritizer {
    fn get_next_chunk(&mut self) -> HttpResult<Option<DataChunk>> {
        if self.chunks.len() == 0 {
            return Ok(None);
        }
        let chunk = self.chunks.remove(0);
        Ok(Some(DataChunk {
            stream_id: 1,
            data: Cow::Owned(chunk),
            end_stream: EndStream::No,
        }))
    }
}

/// A type alias for a `ClientConnection` with mock replacements for its dependent types.
pub type MockClientConnection = ClientConnection<DefaultSessionState<ClientMarker, TestStream>>;

/// Returns a `ClientConnection` suitable for use in tests.
#[inline]
pub fn build_mock_client_conn() -> MockClientConnection {
    ClientConnection::with_connection(build_mock_http_conn(),
                                      DefaultSessionState::<ClientMarker, TestStream>::new())
}
