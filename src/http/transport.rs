//! The module contains implementations of the transport layer functionality
//! that HTTP/2 requires. It exposes APIs that allow the HTTP/2 connection to
//! use the transport layer without requiring it to know which exact
//! implementation they are using (e.g. a clear-text TCP connection, a TLS
//! protected connection, or even a mock implementation).
//!
//! The types provided here are purely for convenience in being able to easily
//! plug in the native Rust socket IO primitives into the HTTP/2 connection API
//! without having to write too much boilerplate around them.

use std::io;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::net::Shutdown;

use http::HttpResult;
use http::frame::{FrameIR, RawFrame, unpack_header};
use http::connection::{SendFrame, ReceiveFrame, HttpFrame};

/// A trait that any struct that wants to provide the transport layer for
/// HTTP/2 needs to implement.
///
/// It provides default implementations for some convenience methods, backed
/// by the `Read` and `Write` implementations.
pub trait TransportStream: Read + Write + Sized {
    /// A convenience method that performs as many `read` calls on the
    /// underlying `Read` implementation as it takes to fill the given buffer.
    ///
    /// The implementation simply calls the `read` in a loop until the
    /// buffer is filled or an aparent end of file is reached, upon which
    /// an error is returned.
    ///
    /// However, no particular care is taken to limit the number of loop
    /// iterations and it could theoretically be possible to end up reading
    /// a single byte at a time into a large buffer, taking a long time to
    /// return.
    ///
    /// Any errors raised by the underlying `Read` implementations are
    /// propagated.
    ///
    /// When an error is raised, the given buffer is only partially filled,
    /// but there is no way to know how many bytes were actually written to
    /// the underlying buffer, which means that, effectively, all read bytes
    /// are lost on any error.
    fn read_exact(&mut self, buf: &mut [u8]) -> io::Result<()> {
        let mut total = 0;
        while total < buf.len() {
            let read = try!(self.read(&mut buf[total..]));
            if read == 0 {
                // We consider this an unexpected end of file and return an
                // error since we were unable to read the minimum amount of
                // bytes.
                return Err(io::Error::new(io::ErrorKind::Other,
                                          "Not enough bytes"));
            }
            total += read;
        }

        Ok(())
    }

    /// Attempts to split the `TransportStream` instance into a new independently
    /// owned handle to the same underlying stream.
    fn try_split(&self) -> Result<Self, io::Error>;

    /// Attempts to shutdown both ends of the transport stream.
    ///
    /// If successful, all handles to the stream created by the `try_split` operation will start
    /// receiving an error for any IO operations.
    fn close(&mut self) -> Result<(), io::Error>;
}

impl TransportStream for TcpStream {
    fn try_split(&self) -> Result<TcpStream, io::Error> {
        self.try_clone()
    }

    fn close(&mut self) -> Result<(), io::Error> {
        self.shutdown(Shutdown::Both)
    }
}

impl<T> SendFrame for T where T: TransportStream {
    fn send_frame<F: FrameIR>(&mut self, frame: F) -> HttpResult<()> {
        let mut buf = io::Cursor::new(Vec::with_capacity(1024));
        try!(frame.serialize_into(&mut buf));
        try!(self.write_all(buf.get_ref()));
        Ok(())
    }
}

/// The struct is a an implementation of the `ReceiveFrame` trait that wraps an existing
/// `TransportStream` and uses it to provide HTTP/2 frames, when asked for one, by reading from the
/// stream.
/// The implementation always allocates a new buffer on the heap for every incoming frame.
pub struct TransportReceiveFrame<'a, TS> where TS: TransportStream + 'a {
    ts: &'a mut TS,
    raw_frame: Option<RawFrame<'a>>,
}

impl<'a, TS> TransportReceiveFrame<'a, TS> where TS: TransportStream {
    /// Create a new `TransportReceiveFrame` that will use the given `TransportStream` for reading
    /// the frame.
    pub fn new(ts: &'a mut TS) -> TransportReceiveFrame<'a, TS> {
        TransportReceiveFrame {
            ts: ts,
            raw_frame: None,
        }
    }
}

impl<'a, TS> ReceiveFrame for TransportReceiveFrame<'a, TS> where TS: TransportStream {
    fn recv_frame(&mut self) -> HttpResult<HttpFrame> {
        let raw_header = {
            let mut buf = [0; 9];
            try!(TransportStream::read_exact(self.ts, &mut buf));
            buf
        };
        let header = unpack_header(&raw_header);
        trace!("Received frame header {:?}", header);

        let total_len = 9 + header.0 as usize;
        // Now prepare the buffer that will hold the entire frame.
        let mut full_frame = Vec::with_capacity(total_len);
        // First copy the header into the buffer...
        try!(io::copy(&mut &raw_header[..], &mut full_frame));
        // Now expand it to its full size...
        unsafe { full_frame.set_len(total_len); }
        // ...and have the stream read into the payload section the exact number of bytes that the
        // header indicated.
        try!(TransportStream::read_exact(self.ts, &mut full_frame[9..]));

        self.raw_frame = Some(RawFrame::from(full_frame));
        // TODO: The reason behind being unable to decode the frame should be
        //       extracted to allow an appropriate connection-level action to be
        //       taken (e.g. responding with a PROTOCOL_ERROR).
        HttpFrame::from_raw(self.raw_frame.as_ref().unwrap())
    }
}

#[cfg(feature="tls")]
use openssl::ssl::SslStream;
#[cfg(feature="tls")]
impl TransportStream for SslStream<TcpStream> {
    fn try_split(&self) -> Result<SslStream<TcpStream>, io::Error> {
        self.try_clone()
    }

    fn close(&mut self) -> Result<(), io::Error> {
        self.get_ref().shutdown(Shutdown::Both)
    }
}

#[cfg(test)]
mod tests {
    use super::{TransportStream, TransportReceiveFrame};

    use http::tests::common::{
        serialize_frame,
        build_stub_from_frames,
        StubTransportStream,
    };
    use http::HttpError;
    use http::connection::{HttpFrame, SendFrame, ReceiveFrame};
    use http::frame::{
        RawFrame,
        DataFrame,
        HeadersFrame,
        pack_header,
    };

    /// A helper function that sends the given frame using the provided `sender` and also returns
    /// the raw serialization of the frame.
    fn send_frame<S: SendFrame>(sender: &mut S, frame: HttpFrame) -> Vec<u8> {
        match frame {
            HttpFrame::DataFrame(frame) => {
                let ret = serialize_frame(&frame);
                sender.send_frame(frame).unwrap();
                ret
            },
            HttpFrame::HeadersFrame(frame) => {
                let ret = serialize_frame(&frame);
                sender.send_frame(frame).unwrap();
                ret
            },
            HttpFrame::RstStreamFrame(frame) => {
                let ret = serialize_frame(&frame);
                sender.send_frame(frame).unwrap();
                ret
            },
            HttpFrame::SettingsFrame(frame) => {
                let ret = serialize_frame(&frame);
                sender.send_frame(frame).unwrap();
                ret
            },
            HttpFrame::GoawayFrame(frame) => {
                let ret = serialize_frame(&frame);
                sender.send_frame(frame).unwrap();
                ret
            },
            HttpFrame::WindowUpdateFrame(frame) => {
                let ret = serialize_frame(&frame);
                sender.send_frame(frame).unwrap();
                ret
            },
            HttpFrame::UnknownFrame(frame) => {
                let ret = serialize_frame(&frame);
                let raw: RawFrame = frame.into();
                sender.send_frame(raw).unwrap();
                ret
            },
        }
    }

    /// Tests the implementation of the `SendFrame` for `TransportStream`s when
    /// writing individual frames.
    #[test]
    fn test_send_frame_for_transport_stream_individual() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
            HttpFrame::DataFrame(DataFrame::new(1)),
            HttpFrame::DataFrame(DataFrame::new(3)),
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 3)),
            HttpFrame::UnknownFrame(From::from(RawFrame::from(vec![0; 9]))),
        ];
        for frame in frames.into_iter() {
            let mut stream = StubTransportStream::with_stub_content(&[]);
            let frame_serialized = send_frame(&mut stream, frame);
            assert_eq!(stream.get_written(), frame_serialized);
        }
    }

    /// Tests the implementation of the `SendFrame` for `TransportStream`s.
    #[test]
    fn test_send_frame_for_transport_stream() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
            HttpFrame::DataFrame(DataFrame::new(1)),
            HttpFrame::DataFrame(DataFrame::new(3)),
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 3)),
            HttpFrame::UnknownFrame(From::from(RawFrame::from(vec![0; 9]))),
        ];
        let mut stream = StubTransportStream::with_stub_content(&[]);
        let mut previous = 0;
        for frame in frames.into_iter() {
            let frame_serialized = send_frame(&mut stream, frame);
            let written = stream.get_written();
            assert_eq!(&written[previous..], &frame_serialized[..]);
            previous = written.len();
        }
    }

    /// Tests that trying to send a frame on a closed transport stream results in an error.
    /// (i.e. an error returned by the underlying `io::Write` is propagated).
    #[test]
    fn test_send_frame_closed_stream() {
        let mut stream = StubTransportStream::with_stub_content(&vec![]);
        stream.close().unwrap();

        let res = stream.send_frame(HeadersFrame::new(vec![], 1));

        assert!(res.is_err());
    }

    /// Tests that the implementation of `ReceiveFrame` for `TransportReceiveFrame` types
    /// works correctly.
    #[test]
    fn test_recv_frame_for_transport_stream() {
        let unknown_frame = RawFrame::from({
            let mut buf: Vec<u8> = Vec::new();
            // Frame type 10 with a payload of length 1 on stream 1
            let header = (1u32, 10u8, 0u8, 1u32);
            buf.extend(pack_header(&header).to_vec().into_iter());
            buf.push(1);
            buf
        });
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
            HttpFrame::DataFrame(DataFrame::new(1)),
            HttpFrame::DataFrame(DataFrame::new(3)),
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 3)),
            HttpFrame::UnknownFrame(From::from(unknown_frame)),
        ];
        let mut stream = StubTransportStream::with_stub_content(&build_stub_from_frames(&frames));

        // Necessary to coax the borrow-checker to accept a new mutable borrow of stream in every
        // iteration of the loop below...
        fn assert_equal<'a>(orig: HttpFrame<'a>, next: HttpFrame<'a>) {
            assert_eq!(orig, next);
        }
        let mut receiver = TransportReceiveFrame::new(&mut stream);
        for frame in frames.into_iter() {
            assert_equal(frame, receiver.recv_frame().unwrap());
        }
        // Attempting to read after EOF yields an error
        assert!(receiver.recv_frame().is_err());
    }

    /// Tests that the implementation of `ReceiveFrame` for `TransportReceiveFrame` types
    /// works correctly when faced with an incomplete frame.
    #[test]
    fn test_recv_frame_for_transport_stream_incomplete_frame() {
        let frame = DataFrame::with_data(1, vec![1, 2, 3]);
        let serialized: Vec<u8> = serialize_frame(&frame);

        {
            // Incomplete header
            let mut stream = StubTransportStream::with_stub_content(&serialized[..5]);
            let mut receiver = TransportReceiveFrame::new(&mut stream);

            assert!(receiver.recv_frame().is_err());
        }
        {
            // Incomplete data
            let mut stream = StubTransportStream::with_stub_content(&serialized[..10]);
            let mut receiver = TransportReceiveFrame::new(&mut stream);

            assert!(receiver.recv_frame().is_err());
        }
    }

    /// Tests that when an invalid, yet syntactically correct, frame is read from the stream,
    /// a corresponding error is returned.
    #[test]
    fn test_recv_frame_invalid() {
        // A DATA header which is attached to stream 0
        let serialized = serialize_frame(&HeadersFrame::new(vec![], 0));
        let mut stream = StubTransportStream::with_stub_content(&serialized);
        let mut receiver = TransportReceiveFrame::new(&mut stream);

        assert_eq!(receiver.recv_frame().err().unwrap(), HttpError::InvalidFrame);
    }

}
