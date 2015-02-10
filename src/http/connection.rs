//! The module contains the implementation of an HTTP/2 connection.
//!
//! This provides an API to read and write raw HTTP/2 frames.

use std::old_io::IoError;
use super::HttpError;
use super::transport::TransportStream;
use super::frame::{
    Frame,
    RawFrame,
    DataFrame,
    HeadersFrame,
    SettingsFrame,
    unpack_header,
};

/// An enum representing all frame variants that can be returned by an
/// `HttpConnection`.
///
/// The variants wrap the appropriate `Frame` implementation.
#[derive(PartialEq)]
#[derive(Debug)]
pub enum HttpFrame {
    DataFrame(DataFrame),
    HeadersFrame(HeadersFrame),
    SettingsFrame(SettingsFrame),
}

/// A helper macro that can be used on `old_io::Result`s to either unwrap the
/// result (the same as the `try!` macro) or else wrap the returned `IoError`
/// to an `HttpError::IoError` variant and do an early return with such an
/// error.
///
/// This is useful so that the operations that the `HttpConnection` invokes on
/// its underlying stream can easily be wrapped into an `HttpError` without a
/// lot of repetitive boilerplate code.
macro_rules! try_io {
    ($e:expr) => (
        match $e {
            Ok(e) => e,
            Err(e@IoError { .. }) => {
                debug!("ignored error: {:?}", e);
                return Err(HttpError::IoError(e));
            }
        }
    )
}

/// The struct implements the HTTP/2 connection level logic.
///
/// It provides an API for writing and reading HTTP/2 frames. It also takes
/// care to validate the received frames.
pub struct HttpConnection<S> where S: TransportStream {
    stream: S,
}

impl<S> HttpConnection<S> where S: TransportStream {
    /// Creates a new `HttpConnection` that will use the given stream as its
    /// underlying transport layer.
    pub fn with_stream(stream: S) -> HttpConnection<S> {
        HttpConnection {
            stream: stream,
        }
    }

    /// Sends the given frame to the peer.
    ///
    /// # Returns
    ///
    /// Any IO errors raised by the underlying transport layer are wrapped in a
    /// `HttpError::IoError` variant and propagated upwards.
    ///
    /// If the frame is successfully written, returns a unit Ok (`Ok(())`).
    pub fn send_frame<F: Frame>(&mut self, frame: F) -> Result<(), HttpError> {
        debug!("Sending frame ... {:?}", frame.get_header());
        try_io!(self.stream.write(&frame.serialize()[]));
        Ok(())
    }

    /// Reads a new frame from the transport layer.
    ///
    /// # Returns
    ///
    /// Any IO errors raised by the underlying transport layer are wrapped in a
    /// `HttpError::IoError` variant and propagated upwards.
    ///
    /// If the frame type is unknown the `HttpError::UnknownFrameType` variant
    /// is returned.
    ///
    /// If the frame type is recognized, but the frame cannot be successfully
    /// decoded, the `HttpError::InvalidFrame` variant is returned. For now,
    /// invalid frames are not further handled by informing the peer (e.g.
    /// sending PROTOCOL_ERROR) nor can the exact reason behind failing to
    /// decode the frame be extracted.
    ///
    /// If a frame is successfully read and parsed, returns the frame wrapped
    /// in the appropriate variant of the `HttpFrame` enum.
    pub fn recv_frame(&mut self) -> Result<HttpFrame, HttpError> {
        let header = unpack_header(&try!(self.read_header_bytes()));
        debug!("Received frame header {:?}", header);

        let payload = try!(self.read_payload(header.0));
        let raw_frame = RawFrame::with_payload(header, payload);

        // TODO: The reason behind being unable to decode the frame should be
        //       extracted and an appropriate connection-level action taken
        //       (e.g. responding with a PROTOCOL_ERROR).
        let frame = match header.1 {
            0x0 => HttpFrame::DataFrame(try!(self.parse_frame(raw_frame))),
            0x1 => HttpFrame::HeadersFrame(try!(self.parse_frame(raw_frame))),
            0x4 => HttpFrame::SettingsFrame(try!(self.parse_frame(raw_frame))),
            _ => return Err(HttpError::UnknownFrameType),
        };

        Ok(frame)
    }

    /// Reads the header bytes of the next frame from the underlying stream.
    ///
    /// # Returns
    ///
    /// Since each frame header is exactly 9 octets long, returns an array of
    /// 9 bytes if the frame header is successfully read.
    ///
    /// Any IO errors raised by the underlying transport layer are wrapped in a
    /// `HttpError::IoError` variant and propagated upwards.
    fn read_header_bytes(&mut self) -> Result<[u8; 9], HttpError> {
        let mut buf = [0; 9];
        try_io!(self.stream.read_at_least(9, &mut buf));

        Ok(buf)
    }

    /// Reads the payload of an HTTP/2 frame with the given length.
    ///
    /// # Returns
    ///
    /// A newly allocated buffer containing the entire payload of the frame.
    ///
    /// Any IO errors raised by the underlying transport layer are wrapped in a
    /// `HttpError::IoError` variant and propagated upwards.
    fn read_payload(&mut self, len: u32) -> Result<Vec<u8>, HttpError> {
        debug!("Trying to read {} bytes of frame payload", len);
        let length = len as usize;
        let mut buf: Vec<u8> = Vec::with_capacity(length);
        // This is completely safe since we *just* allocated the vector with
        // the same capacity.
        unsafe { buf.set_len(length); }
        try_io!(self.stream.read_at_least(length, &mut buf[]));

        Ok(buf)
    }

    /// A helper method that parses the given `RawFrame` into the given `Frame`
    /// implementation.
    ///
    /// # Returns
    ///
    /// Failing to decode the given `Frame` from the `raw_frame`, an
    /// `HttpError::InvalidFrame` error is returned.
    #[inline]
    fn parse_frame<F: Frame>(&self, raw_frame: RawFrame) -> Result<F, HttpError> {
        Frame::from_raw(raw_frame).ok_or(HttpError::InvalidFrame)
    }
}

#[cfg(test)]
mod tests {
    use std::old_io::{IoResult, IoError, MemReader, MemWriter};

    use super::super::frame::{
        Frame, DataFrame, HeadersFrame,
        pack_header
    };
    use super::{HttpConnection, HttpFrame};
    use super::super::transport::TransportStream;
    use super::super::HttpError;

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
    /// aftwerwards any read or write attempt returns an IoError;
    struct StubTransportStream {
        reader: MemReader,
        writer: MemWriter,
        closed: bool,
    }

    impl StubTransportStream {
        /// Initializes the stream with the given byte vector representing
        /// the bytes that will be read from the stream.
        fn with_stub_content(stub: &Vec<u8>) -> StubTransportStream {
            StubTransportStream {
                reader: MemReader::new(stub.clone()),
                writer: MemWriter::new(),
                closed: false,
            }
        }

        /// Returns a slice representing the bytes already written to the
        /// stream.
        fn get_written(&self) -> &[u8] {
            self.writer.get_ref()
        }

        /// Closes the stream, making any read or write operation return an
        /// `IoError` from there on out.
        fn close(&mut self) {
            self.closed = true;
        }
    }

    impl Reader for StubTransportStream {
        fn read(&mut self, buf: &mut [u8]) -> IoResult<usize> {
            if self.closed {
                Err(IoError::from_errno(1, false))
            } else {
                self.reader.read(buf)
            }
        }
    }

    impl Writer for StubTransportStream {
        fn write_all(&mut self, buf: &[u8]) -> IoResult<()> {
            if self.closed {
                Err(IoError::from_errno(1, false))
            } else {
                self.writer.write_all(buf)
            }
        }
    }

    impl TransportStream for StubTransportStream {}

    /// A helper function that creates an `HttpConnection` with a `StubTransportStream`
    /// where the content of the stream is defined by the given `stub_data`
    fn build_http_conn(stub_data: &Vec<u8>) -> HttpConnection<StubTransportStream> {
        HttpConnection {
            stream: StubTransportStream::with_stub_content(stub_data),
        }
    }

    /// A helper function that builds a buffer of bytes from the given `Vec` of
    /// `HttpFrame`s, by serializing them in the given order.
    fn build_stub_from_frames(frames: &Vec<HttpFrame>) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        for frame in frames.iter() {
            let serialized = match frame {
                &HttpFrame::DataFrame(ref frame) => frame.serialize(),
                &HttpFrame::HeadersFrame(ref frame) => frame.serialize(),
                &HttpFrame::SettingsFrame(ref frame) => frame.serialize(),
            };
            buf.push_all(&serialized[]);
        }

        buf
    }

    /// Tests that it is possible to read a single frame from the stream.
    #[test]
    fn test_read_single_frame() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
        ];
        let mut conn = build_http_conn(&build_stub_from_frames(&frames));

        let actual = (0..frames.len()).map(|_| conn.recv_frame().ok().unwrap())
                                      .collect();

        assert_eq!(actual, frames);
    }

    /// Tests that multiple frames are correctly read from the stream.
    #[test]
    fn test_read_multiple_frames() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
            HttpFrame::DataFrame(DataFrame::new(1)),
            HttpFrame::DataFrame(DataFrame::new(3)),
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 3)),
        ];
        let mut conn = build_http_conn(&build_stub_from_frames(&frames));

        let actual = (0..frames.len()).map(|_| conn.recv_frame().ok().unwrap())
                                      .collect();

        assert_eq!(actual, frames);
    }

    /// Tests that when reading from a stream that initially contains no data,
    /// an `IoError` is returned.
    #[test]
    fn test_read_no_data() {
        let mut conn = build_http_conn(&vec![]);

        let res = conn.recv_frame();

        assert!(match res.err().unwrap() {
            HttpError::IoError(_) => true,
            _ => false,
        });
    }

    /// Tests that a read past the end of file (stream) results in an `IoError`.
    #[test]
    fn test_read_past_eof() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
        ];
        let mut conn = build_http_conn(&build_stub_from_frames(&frames));

        let _: Vec<_> = (0..frames.len()).map(|_| conn.recv_frame().ok().unwrap())
                                      .collect();
        let res = conn.recv_frame();

        assert!(match res.err().unwrap() {
            HttpError::IoError(_) => true,
            _ => false,
        });
    }

    /// Tests that when reading off a stream that doesn't have a complete frame
    /// header causes a graceful failure.
    #[test]
    fn test_read_invalid_stream_incomplete_frame() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
        ];
        let mut conn = build_http_conn(&{
            let mut buf: Vec<u8> = Vec::new();
            buf.push_all(&build_stub_from_frames(&frames));
            // We add an extra trailing byte (a start of the header of another
            // frame).
            buf.push(0);
            buf
        });

        let actual = (0..frames.len()).map(|_| conn.recv_frame().ok().unwrap())
                                      .collect();
        // The first frame is correctly read
        assert_eq!(actual, frames);
        // ...but now we get an error
        assert!(match conn.recv_frame().err().unwrap() {
            HttpError::IoError(_) => true,
            _ => false,
        });
    }

    /// Tests that when reading off a stream that doesn't have a frame payload
    /// (when it should) causes a graceful failure.
    #[test]
    fn test_read_invalid_stream_incomplete_payload() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
        ];
        let mut conn = build_http_conn(&{
            let mut buf: Vec<u8> = Vec::new();
            buf.push_all(&build_stub_from_frames(&frames));
            // We add a header indicating that there should be 1 byte of payload
            let header = (1u32, 0u8, 0u8, 1u32);
            buf.push_all(&pack_header(&header));
            // ...but we don't add any payload!
            buf
        });

        let actual = (0..frames.len()).map(|_| conn.recv_frame().ok().unwrap())
                                      .collect();
        // The first frame is correctly read
        assert_eq!(actual, frames);
        // ...but now we get an error
        assert!(match conn.recv_frame().err().unwrap() {
            HttpError::IoError(_) => true,
            _ => false,
        });
    }

    /// Tests that when reading off a stream that contains an invalid frame
    /// returns an appropriate indicator.
    #[test]
    fn test_read_invalid_frame() {
        // A DATA header which is attached to stream 0
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 0)),
        ];
        let mut conn = build_http_conn(&build_stub_from_frames(&frames));

        // An error indicating that the frame is invalid.
        assert!(match conn.recv_frame().err().unwrap() {
            HttpError::InvalidFrame => true,
            _ => false,
        });
    }

    /// Tests that when reading a frame with a header that indicates an
    /// unknown frame type, an appropriate error is returned.
    #[test]
    fn test_read_unknown_frame() {
        let mut conn = build_http_conn(&{
            let mut buf: Vec<u8> = Vec::new();
            // Frame type 10 with a payload of length 1 on stream 1
            let header = (1u32, 10u8, 0u8, 1u32);
            buf.push_all(&pack_header(&header));
            buf.push(1);
            buf
        });

        // Unknown frame error.
        assert!(match conn.recv_frame().err().unwrap() {
            HttpError::UnknownFrameType => true,
            _ => false,
        });
    }

    /// Tests that it is possible to write a single frame to the connection.
    #[test]
    fn test_write_single_frame() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
        ];
        let expected = build_stub_from_frames(&frames);
        let mut conn = build_http_conn(&vec![]);

        for frame in frames.into_iter() {
            match frame {
                HttpFrame::DataFrame(frame) => conn.send_frame(frame),
                HttpFrame::SettingsFrame(frame) => conn.send_frame(frame),
                HttpFrame::HeadersFrame(frame) => conn.send_frame(frame),
            };
        }

        assert_eq!(expected, conn.stream.get_written());
    }


    /// Tests that multiple frames are correctly written to the stream.
    #[test]
    fn test_write_multiple_frames() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
            HttpFrame::DataFrame(DataFrame::new(1)),
            HttpFrame::DataFrame(DataFrame::new(3)),
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 3)),
        ];
        let expected = build_stub_from_frames(&frames);
        let mut conn = build_http_conn(&vec![]);

        for frame in frames.into_iter() {
            match frame {
                HttpFrame::DataFrame(frame) => conn.send_frame(frame),
                HttpFrame::SettingsFrame(frame) => conn.send_frame(frame),
                HttpFrame::HeadersFrame(frame) => conn.send_frame(frame),
            };
        }

        assert_eq!(expected, conn.stream.get_written());
    }

    /// Tests that a write to a closed stream fails with an IoError.
    #[test]
    fn test_write_to_closed_stream() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
        ];
        let expected = build_stub_from_frames(&frames);
        let mut conn = build_http_conn(&vec![]);
        // Close the underlying stream!
        conn.stream.close();

        for frame in frames.into_iter() {
            let res = match frame {
                HttpFrame::DataFrame(frame) => conn.send_frame(frame),
                HttpFrame::SettingsFrame(frame) => conn.send_frame(frame),
                HttpFrame::HeadersFrame(frame) => conn.send_frame(frame),
            };

            assert!(match res {
                Err(HttpError::IoError(_)) => true,
                _ => false,
            });
        }
    }
}
