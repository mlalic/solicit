//! The module contains the implementation of an HTTP/2 connection.
//!
//! This provides an API to read and write raw HTTP/2 frames.

use std::old_io::IoError;
use super::HttpError;
use super::transport::TransportStream;
use super::frame::{
    Frame,
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
