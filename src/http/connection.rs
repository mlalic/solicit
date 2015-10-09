//! The module contains the implementation of an HTTP/2 connection.
//!
//! This provides an API to read and write raw HTTP/2 frames, as well as a way to hook into
//! higher-level events arising on an HTTP/2 connection, such as the receipt of headers on a
//! particular stream or a new data chunk.
//!
//! The `SendFrame` and `ReceiveFrame` traits are the API to sending and receiving frames off of an
//! HTTP/2 connection. The module includes default implementations of those traits for `io::Write`
//! and `solicit::http::transport::TransportStream` types.
//!
//! The `HttpConnection` struct builds on top of these traits and provides an API for sending
//! messages of a higher level to the peer (such as writing data or headers, while automatically
//! handling the framing and header encoding), as well as for handling incoming events of that
//! type. The `Session` trait is the bridge between the connection layer (i.e. the
//! `HttpConnection`) and the higher layers that handle these events and pass them on to the
//! application.

use std::io;
use std::borrow::Cow;
use std::borrow::Borrow;

use http::{
    Header,
    StreamId,
    HttpError,
    HttpResult,
    HttpScheme,
};
use http::priority::DataPrioritizer;
use http::session::Session;
use http::transport::TransportStream;
use http::frame::{
    Frame,
    RawFrame,
    DataFrame,
    DataFlag,
    HeadersFrame,
    HeadersFlag,
    SettingsFrame,
    unpack_header,
};
use hpack;

/// A thin wrapper around an unknown frame that guarantees that the frame's content is owned.
/// This makes it suitable for inclusion in the `HttpFrame` enum which needs to be `Send`
/// (for now).
#[derive(Debug, Clone, PartialEq)]
pub struct UnknownFrame {
    buf: Vec<u8>,
}
impl UnknownFrame {
    pub fn serialize(&self) -> Vec<u8> {
        self.buf.clone()
    }
}
// Conversion traits: from and into a `RawFrame`, as well as an owned and borrowed byte buffer.
impl<'a> From<RawFrame<'a>> for UnknownFrame {
    fn from(raw: RawFrame<'a>) -> UnknownFrame {
        UnknownFrame { buf: raw.into() }
    }
}
impl<'a> Into<RawFrame<'a>> for UnknownFrame {
    fn into(self) -> RawFrame<'a> {
        self.buf.into()
    }
}
impl Into<Vec<u8>> for UnknownFrame {
    fn into(self) -> Vec<u8> { self.buf }
}
impl AsRef<[u8]> for UnknownFrame {
    fn as_ref(&self) -> &[u8] { &self.buf }
}

/// An enum representing all frame variants that can be returned by an `HttpConnection` can handle.
///
/// The variants wrap the appropriate `Frame` implementation, except for the `UnknownFrame`
/// variant, which provides an owned representation of the underlying `RawFrame`
#[derive(PartialEq)]
#[derive(Debug)]
#[derive(Clone)]
pub enum HttpFrame {
    DataFrame(DataFrame),
    HeadersFrame(HeadersFrame),
    SettingsFrame(SettingsFrame),
    UnknownFrame(UnknownFrame),
}

impl HttpFrame {
    pub fn from_raw(raw_frame: RawFrame) -> HttpResult<HttpFrame> {
        let frame = match raw_frame.header().1 {
            0x0 => HttpFrame::DataFrame(try!(HttpFrame::parse_frame(raw_frame))),
            0x1 => HttpFrame::HeadersFrame(try!(HttpFrame::parse_frame(raw_frame))),
            0x4 => HttpFrame::SettingsFrame(try!(HttpFrame::parse_frame(raw_frame))),
            _ => HttpFrame::UnknownFrame(From::from(raw_frame)),
        };

        Ok(frame)
    }

    /// A helper method that parses the given `RawFrame` into the given `Frame`
    /// implementation.
    ///
    /// # Returns
    ///
    /// Failing to decode the given `Frame` from the `raw_frame`, an
    /// `HttpError::InvalidFrame` error is returned.
    #[inline]
    fn parse_frame<F: Frame>(raw_frame: RawFrame) -> HttpResult<F> {
        // TODO: The reason behind being unable to decode the frame should be
        //       extracted to allow an appropriate connection-level action to be
        //       taken (e.g. responding with a PROTOCOL_ERROR).
        Frame::from_raw(raw_frame).ok_or(HttpError::InvalidFrame)
    }
}

/// The enum represents the success status of the operation of sending a next data chunk on an
/// HTTP/2 connection.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum SendStatus {
    /// Indicates that a DATA frame was successfully sent
    Sent,
    /// Indicates that nothing was sent, but that no errors occurred.
    ///
    /// This is the case when none of the streams had any data to write.
    Nothing,
}

/// The struct implements the HTTP/2 connection level logic.
///
/// This means that the struct is a bridge between the low level raw frame reads/writes (i.e. what
/// the `SendFrame` and `ReceiveFrame` traits do) and the higher session-level logic.
///
/// Therefore, it provides an API that exposes higher-level write operations, such as writing
/// headers or data, that take care of all the underlying frame construction that is required.
///
/// Similarly, it provides an API for handling events that arise from receiving frames, without
/// requiring the higher level to directly look at the frames themselves, rather only the semantic
/// content within the frames.
pub struct HttpConnection<S> where S: SendFrame {
    /// The instance handling the writing of frames.
    pub sender: S,
    /// HPACK decoder used to decode incoming headers before passing them on to the session.
    decoder: hpack::Decoder<'static>,
    /// The HPACK encoder used to encode headers before sending them on this connection.
    encoder: hpack::Encoder<'static>,
    /// The scheme of the connection
    pub scheme: HttpScheme,
}

/// A trait that should be implemented by types that can provide the functionality
/// of sending HTTP/2 frames.
pub trait SendFrame {
    /// Sends the given raw frame.
    fn send_raw_frame(&mut self, frame: RawFrame) -> HttpResult<()>;
    /// Sends the given concrete frame.
    ///
    /// A default implementation based on the `send_raw_frame` method is provided.
    fn send_frame<F: Frame>(&mut self, frame: F) -> HttpResult<()> {
        self.send_raw_frame(RawFrame::from(frame.serialize()))
    }
}

/// A blanket implementation of `SendFrame` is possible for any type that is also an
/// `io::Write`.
impl<W> SendFrame for W where W: io::Write {
    #[inline]
    fn send_frame<F: Frame>(&mut self, frame: F) -> HttpResult<()> {
        try!(self.write_all(&frame.serialize()));
        Ok(())
    }

    #[inline]
    fn send_raw_frame(&mut self, frame: RawFrame) -> HttpResult<()> {
        let serialized: Vec<u8> = frame.into();
        try!(self.write_all(&serialized));
        Ok(())
    }
}

/// A trait that should be implemented by types that can provide the functionality
/// of receiving HTTP/2 frames.
pub trait ReceiveFrame {
    /// Return a new `HttpFrame` instance. Unknown frames can be wrapped in the
    /// `HttpFrame::UnknownFrame` variant (i.e. their `RawFrame` representation).
    fn recv_frame(&mut self) -> HttpResult<HttpFrame>;
}

/// A blanket implementation of the trait for `TransportStream`s.
impl<TS> ReceiveFrame for TS where TS: TransportStream {
    fn recv_frame(&mut self) -> HttpResult<HttpFrame> {
        let raw_header = {
            let mut buf = [0; 9];
            try!(TransportStream::read_exact(self, &mut buf));
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
        try!(TransportStream::read_exact(self, &mut full_frame[9..]));

        let raw_frame = RawFrame::from(full_frame);
        // TODO: The reason behind being unable to decode the frame should be
        //       extracted to allow an appropriate connection-level action to be
        //       taken (e.g. responding with a PROTOCOL_ERROR).
        let frame = try!(HttpFrame::from_raw(raw_frame));
        Ok(frame)
    }
}

/// The struct represents a chunk of data that should be sent to the peer on a particular stream.
pub struct DataChunk<'a> {
    /// The data that should be sent.
    pub data: Cow<'a, [u8]>,
    /// The ID of the stream on which the data should be sent.
    pub stream_id: StreamId,
    /// Whether the data chunk will also end the stream.
    pub end_stream: EndStream,
}

impl<'a> DataChunk<'a> {
    /// Creates a new `DataChunk`.
    ///
    /// **Note:** `IntoCow` is unstable and there's no implementation of `Into<Cow<'a, [u8]>>` for
    /// the fundamental types, making this a bit of a clunky API. Once such an `Into` impl is
    /// added, this can be made generic over the trait for some ergonomic improvements.
    pub fn new(data: Cow<'a, [u8]>, stream_id: StreamId, end_stream: EndStream) -> DataChunk<'a> {
        DataChunk {
            data: data,
            stream_id: stream_id,
            end_stream: end_stream,
        }
    }

    /// Creates a new `DataChunk` from a borrowed slice. This method should become obsolete if we
    /// can take an `Into<Cow<_, _>>` without using unstable features.
    pub fn new_borrowed<D: Borrow<&'a [u8]>>(data: D, stream_id: StreamId, end_stream: EndStream)
            -> DataChunk<'a> {
        DataChunk {
            data: Cow::Borrowed(data.borrow()),
            stream_id: stream_id,
            end_stream: end_stream,
        }
    }
}

/// An enum indicating whether the `HttpConnection` send operation should end the stream.
#[derive(Clone, Copy, PartialEq, Debug)]
pub enum EndStream {
    /// The stream should be closed
    Yes,
    /// The stream should still be kept open
    No,
}

impl<S> HttpConnection<S> where S: SendFrame {
    /// Creates a new `HttpConnection` that will use the given sender
    /// for writing frames.
    pub fn new(sender: S, scheme: HttpScheme) -> HttpConnection<S> {
        HttpConnection {
            sender: sender,
            scheme: scheme,
            decoder: hpack::Decoder::new(),
            encoder: hpack::Encoder::new(),
        }
    }

    /// Creates a new `HttpConnection` that will use the given stream as its
    /// underlying transport layer.
    ///
    /// This constructor is provided as a convenience when the underlying IO of the
    /// HTTP/2 connection should be based on the `TransportStream` interface.
    ///
    /// The scheme of the connection is also provided.
    pub fn with_stream<TS>(stream: TS, scheme: HttpScheme) -> HttpConnection<TS>
            where TS: TransportStream {
        HttpConnection::new(stream, scheme)
    }

    /// Sends the given frame to the peer.
    ///
    /// # Returns
    ///
    /// Any IO errors raised by the underlying transport layer are wrapped in a
    /// `HttpError::IoError` variant and propagated upwards.
    ///
    /// If the frame is successfully written, returns a unit Ok (`Ok(())`).
    #[inline]
    fn send_frame<F: Frame>(&mut self, frame: F) -> HttpResult<()> {
        debug!("Sending frame ... {:?}", frame.get_header());
        self.sender.send_frame(frame)
    }

    /// A helper function that inserts the frames required to send the given headers onto the
    /// `SendFrame` stream.
    ///
    /// The `HttpConnection` performs the HPACK encoding of the header block using an internal
    /// encoder.
    ///
    /// # Parameters
    ///
    /// - `headers` - a headers list that should be sent.
    /// - `stream_id` - the ID of the stream on which the headers will be sent. The connection
    ///   performs no checks as to whether the stream is a valid identifier.
    /// - `end_stream` - whether the stream should be closed from the peer's side immediately
    ///   after sending the headers
    pub fn send_headers<H: Into<Vec<Header>>>(&mut self,
                                              headers: H,
                                              stream_id: StreamId,
                                              end_stream: EndStream) -> HttpResult<()> {
        self.send_headers_inner(headers.into(), stream_id, end_stream)
    }

    /// A private helper method: the non-generic implementation of the `send_headers` method.
    fn send_headers_inner(&mut self,
                          headers: Vec<Header>,
                          stream_id: StreamId,
                          end_stream: EndStream) -> HttpResult<()> {
        let headers_fragment = self.encoder.encode(
            headers.iter().map(|h| (&h.0[..], &h.1[..])));
        // For now, sending header fragments larger than 16kB is not supported
        // (i.e. the encoded representation cannot be split into CONTINUATION
        // frames).
        let mut frame = HeadersFrame::new(headers_fragment, stream_id);
        frame.set_flag(HeadersFlag::EndHeaders);

        if end_stream == EndStream::Yes {
            frame.set_flag(HeadersFlag::EndStream);
        }

        self.send_frame(frame)
    }

    /// A helper function that inserts a frame representing the given data into the `SendFrame`
    /// stream.
    ///
    /// The `HttpConnection` itself does not track the flow control window and will happily send
    /// data that exceeds a particular stream's or the connection's flow control window size.
    ///
    /// # Parameters
    ///
    /// - `data` - the data that should be sent on the connection
    /// - `stream_id` - the ID of the stream on which the data will be sent
    /// - `end_stream` - whether the stream should be closed from the peer's side immediately after
    ///   sending the data (i.e. the last data frame closes the stream).
    pub fn send_data<'a>(&mut self,
                         chunk: DataChunk<'a>) -> HttpResult<()> {
        let DataChunk { data, stream_id, end_stream } = chunk;
        self.send_data_inner(data.into_owned(), stream_id, end_stream)
    }

    /// A private helepr method: the non-generic implementation of the `send_data` method.
    fn send_data_inner(&mut self, data: Vec<u8>, stream_id: StreamId, end_stream: EndStream)
            -> HttpResult<()>{
        // TODO Validate that the given data can fit into the maximum frame size allowed by the
        //      current settings.
        let mut frame = DataFrame::new(stream_id);
        frame.data.extend(data);
        if end_stream == EndStream::Yes {
            frame.set_flag(DataFlag::EndStream);
        }

        self.send_frame(frame)
    }

    /// Sends the chunk of data provided by the given `DataPrioritizer`.
    ///
    /// # Returns
    ///
    /// Returns the status of the operation. If the provider does not currently have any data that
    /// could be sent, returns `SendStatus::Nothing`. If any data is sent, returns
    /// `SendStatus::Sent`.
    pub fn send_next_data<P: DataPrioritizer>(&mut self, prioritizer: &mut P)
            -> HttpResult<SendStatus> {
        let chunk = try!(prioritizer.get_next_chunk());
        match chunk {
            None => Ok(SendStatus::Nothing),
            Some(chunk) => {
                try!(self.send_data(chunk));
                Ok(SendStatus::Sent)
            },
        }
    }
    /// The method processes the next frame provided by the given `ReceiveFrame` instance, expecting
    /// it to be a SETTINGS frame.
    /// Additionally, the frame cannot be an ACK settings frame, but rather it should contain the
    /// peer's settings.
    ///
    /// The method can be used when the receipt of the peer's preface needs to be asserted, such as
    /// when the connection is first initiated (the first frame on a fresh HTTP/2 connection that
    /// any peer sends must be a SETTINGS frame).
    ///
    /// If the received frame is not a SETTINGS frame, an `HttpError::UnableToConnect` variant is
    /// returned. (TODO: Change this variant's name, as it is a byproduct of this method's legacy)
    pub fn expect_settings<Recv: ReceiveFrame, Sess: Session>(
            &mut self,
            rx: &mut Recv,
            session: &mut Sess)
            -> HttpResult<()> {
        let frame = rx.recv_frame();
        match frame {
            Ok(HttpFrame::SettingsFrame(ref settings)) if !settings.is_ack() => {
                debug!("Correctly received a SETTINGS frame from the server");
            },
            // Wrong frame received...
            Ok(_) => return Err(HttpError::UnableToConnect),
            // Already an error -- propagate that.
            Err(e) => return Err(e),
        };
        try!(self.handle_frame(frame.unwrap(), session));
        Ok(())
    }

    /// Handles the next frame incoming on the given `ReceiveFrame` instance.
    ///
    /// The `HttpConnection` takes care of parsing the frame and extracting the semantics behind it
    /// and passes this on to the higher level by invoking (possibly multiple) callbacks on the
    /// given `Session` instance. For information on which events can be passed to the session,
    /// check out the `Session` trait.
    ///
    /// If the handling is successful, a unit `Ok` is returned; all HTTP and IO errors are
    /// propagated.
    pub fn handle_next_frame<Recv: ReceiveFrame, Sess: Session>(
            &mut self,
            rx: &mut Recv,
            session: &mut Sess)
            -> HttpResult<()> {
        debug!("Waiting for frame...");
        let frame = match rx.recv_frame() {
            Ok(frame) => frame,
            Err(e) => {
                debug!("Encountered an HTTP/2 error, stopping.");
                return Err(e);
            },
        };

        self.handle_frame(frame, session)
    }

    /// Private helper method that actually handles a received frame.
    fn handle_frame<Sess: Session>(&mut self, frame: HttpFrame, session: &mut Sess)
            -> HttpResult<()> {
        match frame {
            HttpFrame::DataFrame(frame) => {
                debug!("Data frame received");
                self.handle_data_frame(frame, session)
            },
            HttpFrame::HeadersFrame(frame) => {
                debug!("Headers frame received");
                self.handle_headers_frame(frame, session)
            },
            HttpFrame::SettingsFrame(frame) => {
                debug!("Settings frame received");
                self.handle_settings_frame::<Sess>(frame, session)
            },
            HttpFrame::UnknownFrame(frame) => {
                debug!("Unknown frame received; raw = {:?}", frame);
                // We simply drop any unknown frames...
                // TODO Signal this to the session so that a hook is available
                //      for implementing frame-level protocol extensions.
                Ok(())
            },
        }
    }

    /// Private helper method that handles a received `DataFrame`.
    fn handle_data_frame<Sess: Session>(&mut self, frame: DataFrame, session: &mut Sess)
            -> HttpResult<()> {
        try!(session.new_data_chunk(frame.get_stream_id(), &frame.data, self));

        if frame.is_set(DataFlag::EndStream) {
            debug!("End of stream {}", frame.get_stream_id());
            try!(session.end_of_stream(frame.get_stream_id(), self));
        }

        Ok(())
    }

    /// Private helper method that handles a received `HeadersFrame`.
    fn handle_headers_frame<Sess: Session>(&mut self, frame: HeadersFrame, session: &mut Sess)
            -> HttpResult<()> {
        let headers = try!(self.decoder.decode(&frame.header_fragment)
                                       .map_err(|e| HttpError::CompressionError(e)));
        try!(session.new_headers(frame.get_stream_id(), headers, self));

        if frame.is_end_of_stream() {
            debug!("End of stream {}", frame.get_stream_id());
            try!(session.end_of_stream(frame.get_stream_id(), self));
        }

        Ok(())
    }

    /// Private helper method that handles a received `SettingsFrame`.
    fn handle_settings_frame<Sess: Session>(&mut self, frame: SettingsFrame, _session: &mut Sess)
            -> HttpResult<()> {
        if !frame.is_ack() {
            // TODO: Actually handle the settings change before sending out the ACK
            //       sending out the ACK.
            debug!("Sending a SETTINGS ack");
            try!(self.send_frame(SettingsFrame::new_ack()));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;

    use super::{
        HttpConnection,
        HttpFrame,
        SendFrame, ReceiveFrame,
        EndStream,
        DataChunk,
        SendStatus,
    };

    use http::tests::common::{
        build_mock_http_conn,
        build_stub_from_frames,
        StubTransportStream,
        StubDataPrioritizer,
        TestSession,
        MockReceiveFrame,
        MockSendFrame,
    };
    use http::frame::{
        Frame, DataFrame, HeadersFrame,
        SettingsFrame,
        pack_header,
        RawFrame,
    };
    use http::transport::TransportStream;
    use http::{HttpError, HttpResult, HttpScheme};
    use hpack;

    /// A helper function that performs a `send_frame` operation on the given
    /// `HttpConnection` by providing the frame instance wrapped in the given
    /// `HttpFrame`.
    ///
    /// If the `HttpFrame` variant is `HttpFrame::UnknownFrame`, nothing will
    /// be sent and an `Ok(())` is returned.
    fn send_frame<S: SendFrame>(conn: &mut HttpConnection<S>, frame: HttpFrame)
            -> HttpResult<()> {
        match frame {
            HttpFrame::DataFrame(frame) => conn.send_frame(frame),
            HttpFrame::SettingsFrame(frame) => conn.send_frame(frame),
            HttpFrame::HeadersFrame(frame) => conn.send_frame(frame),
            HttpFrame::UnknownFrame(_) => Ok(()),
        }
    }

    /// Tests the implementation of the `SendFrame` for `io::Write` types when
    /// writing individual frames.
    #[test]
    fn test_send_frame_for_io_write_individual() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
            HttpFrame::DataFrame(DataFrame::new(1)),
            HttpFrame::DataFrame(DataFrame::new(3)),
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 3)),
            HttpFrame::UnknownFrame(From::from(RawFrame::from(vec![1, 2, 3, 4]))),
        ];
        for frame in frames.into_iter() {
            let mut writeable = Vec::new();
            let frame_serialized = match frame {
                HttpFrame::DataFrame(frame) => {
                    let ret = frame.serialize();
                    writeable.send_frame(frame).unwrap();
                    ret
                },
                HttpFrame::HeadersFrame(frame) => {
                    let ret = frame.serialize();
                    writeable.send_frame(frame).unwrap();
                    ret
                },
                HttpFrame::SettingsFrame(frame) => {
                    let ret = frame.serialize();
                    writeable.send_frame(frame).unwrap();
                    ret
                },
                HttpFrame::UnknownFrame(frame) => {
                    let ret = frame.serialize();
                    writeable.send_raw_frame(frame.into()).unwrap();
                    ret
                },
            };
            assert_eq!(writeable, frame_serialized);
        }
    }

    /// Tests the implementation of the `SendFrame` for `io::Write` types when multiple
    /// frames are written to the same stream.
    #[test]
    fn test_send_frame_for_io_write_multiple() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
            HttpFrame::DataFrame(DataFrame::new(1)),
            HttpFrame::DataFrame(DataFrame::new(3)),
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 3)),
            HttpFrame::UnknownFrame(From::from(RawFrame::from(vec![1, 2, 3, 4]))),
        ];
        let mut writeable = Vec::new();
        let mut previous = 0;
        for frame in frames.into_iter() {
            let frame_serialized = match frame {
                HttpFrame::DataFrame(frame) => {
                    let ret = frame.serialize();
                    writeable.send_frame(frame).unwrap();
                    ret
                },
                HttpFrame::HeadersFrame(frame) => {
                    let ret = frame.serialize();
                    writeable.send_frame(frame).unwrap();
                    ret
                },
                HttpFrame::SettingsFrame(frame) => {
                    let ret = frame.serialize();
                    writeable.send_frame(frame).unwrap();
                    ret
                },
                HttpFrame::UnknownFrame(frame) => {
                    let ret = frame.serialize();
                    writeable.send_raw_frame(frame.into()).unwrap();
                    ret
                },
            };
            assert_eq!(&writeable[previous..], &frame_serialized[..]);
            previous = writeable.len();
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

    /// Tests that the implementation of `ReceiveFrame` for `TransportStream` types
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

        for frame in frames.into_iter() {
            assert_eq!(frame, stream.recv_frame().unwrap());
        }
        // Attempting to read after EOF yields an error
        assert!(stream.recv_frame().is_err());
    }

    /// Tests that the implementation of `ReceiveFrame` for `TransportStream` types
    /// works correctly when faced with an incomplete frame.
    #[test]
    fn test_recv_frame_for_transport_stream_incomplete_frame() {
        let frame = {
            let mut frame = DataFrame::new(1);
            frame.data = vec![1, 2, 3];
            frame
        };
        let serialized: Vec<u8> = frame.serialize();

        {
            // Incomplete header
            let mut stream = StubTransportStream::with_stub_content(&serialized[..5]);

            assert!(stream.recv_frame().is_err());
        }
        {
            // Incomplete data
            let mut stream = StubTransportStream::with_stub_content(&serialized[..10]);

            assert!(stream.recv_frame().is_err());
        }
    }

    /// Tests that when an invalid, yet syntactically correct, frame is read from the stream,
    /// a corresponding error is returned.
    #[test]
    fn test_recv_frame_invalid() {
        // A DATA header which is attached to stream 0
        let serialized = HeadersFrame::new(vec![], 0).serialize();
        let mut stream = StubTransportStream::with_stub_content(&serialized);

        assert_eq!(stream.recv_frame().err().unwrap(), HttpError::InvalidFrame);
    }

    /// Tests that the `HttpFrame::from_raw` method correctly recognizes the frame
    /// type from the header and returns the corresponding variant.
    #[test]
    fn test_http_frame_from_raw() {
        fn to_raw<'a, F: Frame>(frame: F) -> RawFrame<'a> {
            RawFrame::from(frame.serialize())
        }

        assert!(match HttpFrame::from_raw(to_raw(DataFrame::new(1))) {
            Ok(HttpFrame::DataFrame(_)) => true,
            _ => false,
        });

        assert!(match HttpFrame::from_raw(to_raw(HeadersFrame::new(vec![], 1))) {
            Ok(HttpFrame::HeadersFrame(_)) => true,
            _ => false,
        });

        assert!(match HttpFrame::from_raw(to_raw(SettingsFrame::new())) {
            Ok(HttpFrame::SettingsFrame(_)) => true,
            _ => false,
        });

        let unknown_frame = RawFrame::from({
            let mut buf: Vec<u8> = Vec::new();
            // Frame type 10 with a payload of length 1 on stream 1
            let header = (1u32, 10u8, 0u8, 1u32);
            buf.extend(pack_header(&header).to_vec().into_iter());
            buf.push(1);
            buf
        });
        assert!(match HttpFrame::from_raw(unknown_frame) {
            Ok(HttpFrame::UnknownFrame(_)) => true,
            _ => false,
        });

        // Invalid since it's headers on stream 0
        let invalid_frame = HeadersFrame::new(vec![], 0);
        assert!(HttpFrame::from_raw(to_raw(invalid_frame)).is_err());
    }

    /// Tests that it is possible to write a single frame to the connection.
    #[test]
    fn test_write_single_frame() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
        ];
        let expected = frames.clone();
        let mut conn = build_mock_http_conn();

        for frame in frames.into_iter() {
            send_frame(&mut conn, frame).unwrap();
        }

        assert_eq!(expected, conn.sender.sent);
    }

    #[test]
    fn test_send_next_data() {
        fn expect_chunk(expected: &[u8], frame: &HttpFrame) {
            let frame = match frame {
                &HttpFrame::DataFrame(ref frame) => frame,
                _ => panic!("Expected a data frame"),
            };
            assert_eq!(expected, &frame.data[..]);
        }
        let mut conn = build_mock_http_conn();
        let chunks = vec![
            vec![1, 2, 3, 4],
            vec![5, 6],
            vec![7],
            vec![],
        ];
        let mut prioritizer = StubDataPrioritizer::new(chunks.clone());

        // Send as many chunks as we've given the prioritizer
        for chunk in chunks.iter() {
            assert_eq!(SendStatus::Sent, conn.send_next_data(&mut prioritizer).unwrap());
            expect_chunk(&chunk, conn.sender.sent.last().unwrap());
        }
        // Nothing to send any more
        assert_eq!(SendStatus::Nothing, conn.send_next_data(&mut prioritizer).unwrap());
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
        let expected = frames.clone();
        let mut conn = build_mock_http_conn();

        for frame in frames.into_iter() {
            send_frame(&mut conn, frame).unwrap();
        }

        assert_eq!(expected, conn.sender.sent);
    }

    /// Tests that `HttpConnection::send_headers` correctly sends the given headers when they can
    /// fit into a single frame's payload.
    #[test]
    fn test_send_headers_single_frame() {
        fn assert_correct_headers(headers: &[(Vec<u8>, Vec<u8>)], frame: &HeadersFrame) {
            let buf = &frame.header_fragment;
            let frame_headers = hpack::Decoder::new().decode(buf).unwrap();
            assert_eq!(headers, &frame_headers[..]);
        }
        let headers: Vec<(Vec<u8>, Vec<u8>)> = vec![
            (b":method".to_vec(), b"GET".to_vec()),
            (b":scheme".to_vec(), b"http".to_vec()),
        ];
        {
            let mut conn = build_mock_http_conn();

            // Headers when the stream should be closed
            conn.send_headers(&headers[..], 1, EndStream::Yes).unwrap();

            // Only 1 frame sent?
            assert_eq!(conn.sender.sent.len(), 1);
            // The headers frame?
            let frame = match conn.sender.sent.remove(0) {
                HttpFrame::HeadersFrame(frame) => frame,
                _ => panic!("Headers frame not sent"),
            };
            // We sent a headers frame with end of headers and end of stream flags
            assert!(frame.is_headers_end());
            assert!(frame.is_end_of_stream());
            // And the headers were also correct -- just for good measure.
            assert_correct_headers(&headers, &frame);
        }
        {
            let mut conn = build_mock_http_conn();

            // Headers when the stream should be left open
            conn.send_headers(&headers[..], 1, EndStream::No).unwrap();

            // Only 1 frame sent?
            assert_eq!(conn.sender.sent.len(), 1);
            // The headers frame?
            let frame = match conn.sender.sent.remove(0) {
                HttpFrame::HeadersFrame(frame) => frame,
                _ => panic!("Headers frame not sent"),
            };
            assert!(frame.is_headers_end());
            // ...but it's not the end of the stream
            assert!(!frame.is_end_of_stream());
            assert_correct_headers(&headers, &frame);
        }
        {
            let mut conn = build_mock_http_conn();

            // Make sure it's all peachy when we give a `Vec` instead of a slice
            conn.send_headers(headers.clone(), 1, EndStream::Yes).unwrap();

            // Only 1 frame sent?
            assert_eq!(conn.sender.sent.len(), 1);
            // The headers frame?
            let frame = match conn.sender.sent.remove(0) {
                HttpFrame::HeadersFrame(frame) => frame,
                _ => panic!("Headers frame not sent"),
            };
            // We sent a headers frame with end of headers and end of stream flags
            assert!(frame.is_headers_end());
            assert!(frame.is_end_of_stream());
            // And the headers were also correct -- just for good measure.
            assert_correct_headers(&headers, &frame);
        }
    }

    /// Tests that `HttpConnection::send_data` correctly sends the given data when it can fit into
    /// a single frame's payload.
    #[test]
    fn test_send_data_single_frame() {
        {
            // Data shouldn't end the stream...
            let mut conn = build_mock_http_conn();
            let data: &[u8] = b"1234";

            conn.send_data(DataChunk::new_borrowed(data, 1, EndStream::No)).unwrap();

            // Only 1 frame sent?
            assert_eq!(conn.sender.sent.len(), 1);
            // A data frame?
            let frame = match conn.sender.sent.remove(0) {
                HttpFrame::DataFrame(frame) => frame,
                _ => panic!("Data frame not sent"),
            };
            assert_eq!(&frame.data[..], data);
            assert!(!frame.is_end_of_stream());
        }
        {
            // Data should end the stream...
            let mut conn = build_mock_http_conn();
            let data: &[u8] = b"1234";

            conn.send_data(DataChunk::new_borrowed(data, 1, EndStream::Yes)).unwrap();

            // Only 1 frame sent?
            assert_eq!(conn.sender.sent.len(), 1);
            // A data frame?
            let frame = match conn.sender.sent.remove(0) {
                HttpFrame::DataFrame(frame) => frame,
                _ => panic!("Data frame not sent"),
            };
            assert_eq!(&frame.data[..], data);
            assert!(frame.is_end_of_stream());
        }
        {
            // given a `Vec` we're good too?
            let mut conn = build_mock_http_conn();
            let data: &[u8] = b"1234";
            let chunk = DataChunk {
                data: Cow::Owned(data.to_vec()),
                stream_id: 1,
                end_stream: EndStream::Yes,
            };

            conn.send_data(chunk).unwrap();

            // Only 1 frame sent?
            assert_eq!(conn.sender.sent.len(), 1);
            // A data frame?
            let frame = match conn.sender.sent.remove(0) {
                HttpFrame::DataFrame(frame) => frame,
                _ => panic!("Data frame not sent"),
            };
            assert_eq!(&frame.data[..], data);
            assert!(frame.is_end_of_stream());
        }
    }

    /// Tests that the `HttpConnection` correctly notifies the session on a
    /// new headers frame, with no continuation.
    #[test]
    fn test_http_conn_notifies_session_header() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
        ];
        let mut conn = HttpConnection::new(
            MockSendFrame::new(), HttpScheme::Http);
        let mut session = TestSession::new();
        let mut frame_provider = MockReceiveFrame::new(frames);

        conn.handle_next_frame(&mut frame_provider, &mut session).unwrap();

        // A poor man's mock...
        // The header callback was called
        assert_eq!(session.curr_header, 1);
        // ...no chunks were seen.
        assert_eq!(session.curr_chunk, 0);
    }

    /// Tests that the `HttpConnection` correctly notifies the session on
    /// a new data chunk.
    #[test]
    fn test_http_conn_notifies_session_data() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::DataFrame(DataFrame::new(1)),
        ];
        let mut conn = HttpConnection::new(
            MockSendFrame::new(), HttpScheme::Http);
        let mut session = TestSession::new();
        let mut frame_provider = MockReceiveFrame::new(frames);

        conn.handle_next_frame(&mut frame_provider, &mut session).unwrap();

        // A poor man's mock...
        // The header callback was not called
        assert_eq!(session.curr_header, 0);
        // and exactly one chunk seen.
        assert_eq!(session.curr_chunk, 1);
    }

    /// Tests that the session gets the correct values for the headers and data
    /// from the `HttpConnection` when multiple frames are handled.
    #[test]
    fn test_http_conn_session_gets_headers_data_values() {
        let headers = vec![(b":method".to_vec(), b"GET".to_vec())];
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(
                    hpack::Encoder::new().encode(
                        headers.iter().map(|h| (&h.0[..], &h.1[..]))),
                    1)),
            HttpFrame::DataFrame(DataFrame::new(1)), {
                let mut frame = DataFrame::new(1);
                frame.data = b"1234".to_vec();
                HttpFrame::DataFrame(frame)
            },
        ];
        let mut conn = HttpConnection::new(
            MockSendFrame::new(), HttpScheme::Http);
        let mut session = TestSession::new_verify(
                vec![headers],
                vec![b"".to_vec(), b"1234".to_vec()]);
        let mut frame_provider = MockReceiveFrame::new(frames);

        conn.handle_next_frame(&mut frame_provider, &mut session).unwrap();
        conn.handle_next_frame(&mut frame_provider, &mut session).unwrap();
        conn.handle_next_frame(&mut frame_provider, &mut session).unwrap();

        // Two chunks and one header processed?
        assert_eq!(session.curr_chunk, 2);
        assert_eq!(session.curr_header, 1);
    }

    /// Tests that the `HttpConnection::expect_settings` method works correctly.
    #[test]
    fn test_http_conn_expect_settings() {
        {
            // The next frame is indeed a settings frame.
            let frames = vec![HttpFrame::SettingsFrame(SettingsFrame::new())];
            let mut conn = HttpConnection::new(
                MockSendFrame::new(), HttpScheme::Http);
            let mut frame_provider = MockReceiveFrame::new(frames);
            assert!(conn.expect_settings(&mut frame_provider, &mut TestSession::new()).is_ok());
        }
        {
            // The next frame is a data frame...
            let frames = vec![HttpFrame::DataFrame(DataFrame::new(1))];
            let mut conn = HttpConnection::new(
                MockSendFrame::new(), HttpScheme::Http);
            let mut frame_provider = MockReceiveFrame::new(frames);
            assert!(conn.expect_settings(&mut frame_provider, &mut TestSession::new()).is_err());
        }
        {
            // The next frame is an ACK settings frame
            let frames = vec![HttpFrame::SettingsFrame(SettingsFrame::new_ack())];
            let mut conn = HttpConnection::new(
                MockSendFrame::new(), HttpScheme::Http);
            let mut frame_provider = MockReceiveFrame::new(frames);
            assert!(conn.expect_settings(&mut frame_provider, &mut TestSession::new()).is_err());
        }
    }
}
