//! The module contains some common utilities for `solicit::http` tests.

use std::io;
use std::rc::Rc;
use std::cell::{RefCell, Cell};
use std::borrow::Cow;
use std::io::{Cursor, Read, Write};

use http::{
    HttpResult,
    HttpScheme,
    StreamId,
    Header,
};
use http::frame::{RawFrame, Frame};
use http::session::{
    Session,
    DefaultSessionState,
    SessionState,
    Stream,
    StreamState,
    StreamDataChunk, StreamDataError,
};
use http::priority::DataPrioritizer;
use http::transport::TransportStream;
use http::connection::{
    SendFrame,
    ReceiveFrame,
    HttpFrame,
    HttpConnection,
    EndStream,
    DataChunk,
};
use http::client::ClientConnection;

/// A mock `SendFrame` implementation that simply saves all frames that it is to send to a `Vec`.
pub struct MockSendFrame {
    pub sent: Vec<HttpFrame>,
}

impl MockSendFrame {
    pub fn new() -> MockSendFrame {
        MockSendFrame { sent: Vec::new() }
    }
}

impl SendFrame for MockSendFrame {
    fn send_raw_frame(&mut self, frame: RawFrame) -> HttpResult<()> {
        self.sent.push(HttpFrame::from_raw(frame).unwrap());
        Ok(())
    }
}

/// A mock `ReceiveFrame` implementation that simply serves the frames from a `Vec`.
pub struct MockReceiveFrame {
    pub recv_list: Vec<HttpFrame>,
}

impl MockReceiveFrame {
    pub fn new(recv_list: Vec<HttpFrame>) -> MockReceiveFrame {
        MockReceiveFrame {
            recv_list: recv_list,
        }
    }
}

impl ReceiveFrame for MockReceiveFrame {
    fn recv_frame(&mut self) -> HttpResult<HttpFrame> {
        if self.recv_list.len() != 0 {
            Ok(self.recv_list.remove(0))
        } else {
            Err(io::Error::new(io::ErrorKind::Other, "End of Frame List").into())
        }
    }
}

pub type MockHttpConnection = HttpConnection<MockSendFrame, MockReceiveFrame>;

/// A helper function that creates an `HttpConnection` with the `MockSendFrame` and the
/// `MockReceiveFrame` as its underlying frame handlers.
pub fn build_mock_http_conn(stub_frames: Vec<HttpFrame>) -> MockHttpConnection {
    HttpConnection::new(
        MockSendFrame::new(), MockReceiveFrame::new(stub_frames), HttpScheme::Http)
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
        let serialized = match frame {
            &HttpFrame::DataFrame(ref frame) => frame.serialize(),
            &HttpFrame::HeadersFrame(ref frame) => frame.serialize(),
            &HttpFrame::SettingsFrame(ref frame) => frame.serialize(),
            &HttpFrame::UnknownFrame(ref frame) => frame.serialize(),
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
    pub headers: Vec<Vec<Header>>,
    /// List of expected data chunks -- in the order that they are expected
    pub chunks: Vec<Vec<u8>>,
    /// The current number of header calls.
    pub curr_header: usize,
    /// The current number of data chunk calls.
    pub curr_chunk: usize,
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
        }
    }

    /// Returns a new `TestSession` that veriies that the headers received
    /// in the callbacks are equal to those in the given headers `Vec` and
    /// that they come in exactly the given order. Does the same for chunks.
    pub fn new_verify(headers: Vec<Vec<Header>>, chunks: Vec<Vec<u8>>)
        -> TestSession {
            TestSession {
                silent: false,
                headers: headers,
                chunks: chunks,
                curr_header: 0,
                curr_chunk: 0,
            }
        }
}

impl Session for TestSession {
    fn new_data_chunk(&mut self, _: StreamId, data: &[u8]) {
        if !self.silent {
            assert_eq!(&self.chunks[self.curr_chunk], &data);
        }
        self.curr_chunk += 1;
    }

    fn new_headers(&mut self, _: StreamId, headers: Vec<Header>) {
        if !self.silent {
            assert_eq!(self.headers[self.curr_header], headers);
        }
        self.curr_header += 1;
    }

    fn end_of_stream(&mut self, _: StreamId) {}
}

/// A stream that can be used for testing purposes.
pub struct TestStream {
    pub id: StreamId,
    pub body: Vec<u8>,
    pub headers: Option<Vec<Header>>,
    pub state: StreamState,
    pub outgoing: Option<Cursor<Vec<u8>>>,
}

impl TestStream {
    #[inline]
    pub fn set_outgoing(&mut self, outgoing: Vec<u8>) {
        self.outgoing = Some(Cursor::new(outgoing));
    }
}

impl Stream for TestStream {
    fn new(stream_id: StreamId) -> TestStream {
        TestStream {
            id: stream_id,
            body: Vec::new(),
            headers: None,
            state: StreamState::Open,
            outgoing: None,
        }
    }
    fn new_data_chunk(&mut self, data: &[u8]) { self.body.extend(data.to_vec()); }
    fn set_headers(&mut self, headers: Vec<Header>) { self.headers = Some(headers); }
    fn set_state(&mut self, state: StreamState) { self.state = state; }

    fn get_data_chunk(&mut self, buf: &mut [u8]) -> Result<StreamDataChunk, StreamDataError> {
        if self.is_closed_local() {
            return Err(StreamDataError::Closed);
        }
        let chunk = match self.outgoing.as_mut() {
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

    fn id(&self) -> StreamId { self.id }
    fn state(&self) -> StreamState { self.state }
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
pub type MockClientConnection = ClientConnection<MockSendFrame,
                                                 MockReceiveFrame,
                                                 DefaultSessionState<TestStream>>;

/// Returns a `ClientConnection` suitable for use in tests.
#[inline]
pub fn build_mock_client_conn(frames: Vec<HttpFrame>) -> MockClientConnection {
    ClientConnection::with_connection(
        build_mock_http_conn(frames),
        DefaultSessionState::<TestStream>::new())
}
