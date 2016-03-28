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

use std::borrow::Cow;
use std::borrow::Borrow;

use http::{Header, StreamId, HttpError, HttpResult, HttpScheme, WindowSize,
           ErrorCode, INITIAL_CONNECTION_WINDOW_SIZE};
use http::priority::DataPrioritizer;
use http::session::Session;
use http::frame::{Frame, FrameIR, RawFrame, DataFrame, DataFlag, HeadersFrame, HeadersFlag,
                  SettingsFrame, RstStreamFrame, PingFrame, GoawayFrame, WindowUpdateFrame};
use hpack;

/// An enum representing all frame variants that can be returned by an `HttpConnection` can handle.
///
/// The variants wrap the appropriate `Frame` implementation, except for the `UnknownFrame`
/// variant, which provides an owned representation of the underlying `RawFrame`
#[derive(PartialEq)]
#[derive(Debug)]
#[derive(Clone)]
pub enum HttpFrame<'a> {
    DataFrame(DataFrame<'a>),
    HeadersFrame(HeadersFrame<'a>),
    RstStreamFrame(RstStreamFrame),
    SettingsFrame(SettingsFrame),
    PingFrame(PingFrame),
    GoawayFrame(GoawayFrame<'a>),
    WindowUpdateFrame(WindowUpdateFrame),
    UnknownFrame(RawFrame<'a>),
}

impl<'a> HttpFrame<'a> {
    pub fn from_raw(raw_frame: &'a RawFrame) -> HttpResult<HttpFrame<'a>> {
        let frame = match raw_frame.header().1 {
            0x0 => HttpFrame::DataFrame(try!(HttpFrame::parse_frame(&raw_frame))),
            0x1 => HttpFrame::HeadersFrame(try!(HttpFrame::parse_frame(&raw_frame))),
            0x3 => HttpFrame::RstStreamFrame(try!(HttpFrame::parse_frame(&raw_frame))),
            0x4 => HttpFrame::SettingsFrame(try!(HttpFrame::parse_frame(&raw_frame))),
            0x6 => HttpFrame::PingFrame(try!(HttpFrame::parse_frame(&raw_frame))),
            0x7 => HttpFrame::GoawayFrame(try!(HttpFrame::parse_frame(&raw_frame))),
            0x8 => HttpFrame::WindowUpdateFrame(try!(HttpFrame::parse_frame(&raw_frame))),
            _ => HttpFrame::UnknownFrame(raw_frame.as_ref().into()),
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
    fn parse_frame<F: Frame<'a>>(raw_frame: &'a RawFrame) -> HttpResult<F> {
        // TODO: The reason behind being unable to decode the frame should be
        //       extracted to allow an appropriate connection-level action to be
        //       taken (e.g. responding with a PROTOCOL_ERROR).
        Frame::from_raw(&raw_frame).ok_or(HttpError::InvalidFrame)
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
pub struct HttpConnection {
    /// HPACK decoder used to decode incoming headers before passing them on to the session.
    decoder: hpack::Decoder<'static>,
    /// The HPACK encoder used to encode headers before sending them on this connection.
    encoder: hpack::Encoder<'static>,
    /// Tracks the size of the outbound flow control window
    out_window_size: WindowSize,
    /// Tracks the size of the inbound flow control window
    in_window_size: WindowSize,
    /// The scheme of the connection
    pub scheme: HttpScheme,
}

/// A trait that should be implemented by types that can provide the functionality
/// of sending HTTP/2 frames.
pub trait SendFrame {
    /// Queue the given frame for immediate sending to the peer. It is the responsibility of each
    /// individual `SendFrame` implementation to correctly serialize the given `FrameIR` into an
    /// appropriate buffer and make sure that the frame is subsequently eventually pushed to the
    /// peer.
    fn send_frame<F: FrameIR>(&mut self, frame: F) -> HttpResult<()>;
}

/// A trait that should be implemented by types that can provide the functionality
/// of receiving HTTP/2 frames.
pub trait ReceiveFrame {
    /// Return a new `HttpFrame` instance. Unknown frames can be wrapped in the
    /// `HttpFrame::UnknownFrame` variant (i.e. their `RawFrame` representation).
    fn recv_frame(&mut self) -> HttpResult<HttpFrame>;
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
    pub fn new_borrowed<D: Borrow<&'a [u8]>>(data: D,
                                             stream_id: StreamId,
                                             end_stream: EndStream)
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

/// The struct represents an `HttpConnection` that has been bound to a `SendFrame` reference,
/// allowing it to send frames. It exposes convenience methods for various send operations that can
/// be invoked on the underlying stream. The methods prepare the appropriate frames and queue their
/// sending on the referenced `SendFrame` instance.
///
/// The only way for clients to obtain an `HttpConnectionSender` is to invoke the
/// `HttpConnection::sender` method and provide it a reference to the `SendFrame` that should be
/// used.
pub struct HttpConnectionSender<'a, S>
    where S: SendFrame + 'a
{
    sender: &'a mut S,
    conn: &'a mut HttpConnection,
}

impl<'a, S> HttpConnectionSender<'a, S>
    where S: SendFrame + 'a
{
    /// Sends the given frame to the peer.
    ///
    /// # Returns
    ///
    /// Any IO errors raised by the underlying transport layer are wrapped in a
    /// `HttpError::IoError` variant and propagated upwards.
    ///
    /// If the frame is successfully written, returns a unit Ok (`Ok(())`).
    #[inline]
    fn send_frame<F: FrameIR>(&mut self, frame: F) -> HttpResult<()> {
        self.sender.send_frame(frame)
    }

    /// Send a RST_STREAM frame for the given frame id
    pub fn rst_stream(&mut self, id: StreamId, code: ErrorCode) -> HttpResult<()> {
        self.send_frame(RstStreamFrame::new(id, code))
    }

    /// Sends a SETTINGS acknowledge frame to the peer.
    pub fn send_settings_ack(&mut self) -> HttpResult<()> {
        self.send_frame(SettingsFrame::new_ack())
    }

    /// Sends a PING ack
    pub fn send_ping_ack(&mut self, bytes: u64) -> HttpResult<()> {
        self.send_frame(PingFrame::new_ack(bytes))
    }

    /// Sends a PING request
    pub fn send_ping(&mut self, bytes: u64) -> HttpResult<()> {
        self.send_frame(PingFrame::with_data(bytes))
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
    pub fn send_headers<'n, 'v, H: Into<Vec<Header<'n, 'v>>>>(&mut self,
                                                              headers: H,
                                                              stream_id: StreamId,
                                                              end_stream: EndStream)
                                                              -> HttpResult<()> {
        let headers_fragment = self.conn
                                   .encoder
                                   .encode(headers.into().iter().map(|h| (h.name(), h.value())));
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
    /// stream. In doing so, the connection's outbound flow control window is adjusted
    /// appropriately.
    pub fn send_data(&mut self, chunk: DataChunk) -> HttpResult<()> {
        // Prepare the frame...
        let DataChunk { data, stream_id, end_stream } = chunk;
        let mut frame = DataFrame::with_data(stream_id, data.as_ref());
        if end_stream == EndStream::Yes {
            frame.set_flag(DataFlag::EndStream);
        }
        // Adjust the flow control window...
        try!(self.conn.decrease_out_window(frame.payload_len()));
        trace!("New OUT WINDOW size = {:?}", self.conn.out_window_size());
        // ...and now send it out.
        self.send_frame(frame)
    }

    /// Sends a window update frame for the peer's connection level flow control window.
    pub fn send_connection_window_update(&mut self, increment: u32) -> HttpResult<()> {
        if increment == 0 {
            warn!("Tried to increase window by zero, which would be invalid; frame not sent.");
            return Ok(());
        }
        let frame = WindowUpdateFrame::for_connection(increment);
        self.send_frame(frame)
    }

    /// Sends a window update frame for the given stream's flow control window.
    pub fn send_stream_window_update(&mut self,
                                     stream_id: StreamId,
                                     increment: u32)
                                     -> HttpResult<()> {
        if increment == 0 {
            warn!("Tried to increase window by zero, which would be invalid; frame not sent.");
            return Ok(());
        }
        let frame = WindowUpdateFrame::for_stream(stream_id, increment);
        self.send_frame(frame)
    }

    /// Sends the chunk of data provided by the given `DataPrioritizer`.
    ///
    /// # Returns
    ///
    /// Returns the status of the operation. If the provider does not currently have any data that
    /// could be sent, returns `SendStatus::Nothing`. If any data is sent, returns
    /// `SendStatus::Sent`.
    pub fn send_next_data<P: DataPrioritizer>(&mut self,
                                              prioritizer: &mut P)
                                              -> HttpResult<SendStatus> {
        let chunk = try!(prioritizer.get_next_chunk());
        match chunk {
            None => Ok(SendStatus::Nothing),
            Some(chunk) => {
                try!(self.send_data(chunk));
                Ok(SendStatus::Sent)
            }
        }
    }
}

impl HttpConnection {
    /// Creates a new `HttpConnection` that will use the given sender
    /// for writing frames.
    pub fn new(scheme: HttpScheme) -> HttpConnection {
        HttpConnection {
            scheme: scheme,
            decoder: hpack::Decoder::new(),
            encoder: hpack::Encoder::new(),
            in_window_size: WindowSize::new(INITIAL_CONNECTION_WINDOW_SIZE),
            out_window_size: WindowSize::new(INITIAL_CONNECTION_WINDOW_SIZE),
        }
    }

    /// Creates a new `HttpConnectionSender` instance that will use the given `SendFrame` instance
    /// to send the frames that it prepares. This is a convenience struct so that clients do not
    /// have to pass the same `sender` reference to multiple send methods.
    ///
    /// # Example
    ///
    /// ```rust
    /// use solicit::http::{HttpScheme, HttpResult};
    /// use solicit::http::frame::FrameIR;
    /// use solicit::http::connection::{HttpConnection, SendFrame};
    /// struct FakeSender;
    /// impl SendFrame for FakeSender {
    ///     fn send_frame<F: FrameIR>(&mut self, frame: F) -> HttpResult<()> {
    ///         // Does not actually send anything!
    ///         Ok(())
    ///     }
    /// }
    /// let mut conn = HttpConnection::new(HttpScheme::Http);
    /// {
    ///     let mut frame_sender = FakeSender;
    ///     let mut sender = conn.sender(&mut frame_sender);
    ///     // Now we can use the provided sender to queue multiple HTTP/2 write operations,
    ///     // without passing the same FakeSender reference to every single method.
    ///     sender.send_settings_ack().unwrap();
    ///     // While the `sender` is active, though, the original `conn` cannot be used, as the
    ///     // sender holds on a mutable reference to it...
    /// }
    /// // A sender can be obtained, immediately used, and discarded:
    /// conn.sender(&mut FakeSender).send_settings_ack();
    /// ```
    pub fn sender<'a, S: SendFrame>(&'a mut self, sender: &'a mut S) -> HttpConnectionSender<S> {
        HttpConnectionSender {
            sender: sender,
            conn: self,
        }
    }

    /// Returns the current size of the inbound flow control window (i.e. the number of octets that
    /// the connection will accept and the peer will send at most, unless the window is updated).
    pub fn in_window_size(&self) -> WindowSize {
        self.in_window_size
    }

    /// Returns the current size of the outbound flow control window (i.e. the number of octets
    /// that can be sent on the connection to the peer without violating flow control).
    pub fn out_window_size(&self) -> WindowSize {
        self.out_window_size
    }

    /// Increases the size of the inbound connection flow control window by the given delta.
    ///
    /// If this would cause the window to overflow the maximum value of 2^31 - 1, returns an error.
    /// The method **does not** automatically send any window update frames. It is the caller's
    /// responsibility to make sure that the peer is notified of the window increase.
    pub fn increase_connection_window_size(&mut self, delta: u32) -> HttpResult<()> {
        self.in_window_size.try_increase(delta).map_err(|_| HttpError::WindowSizeOverflow)
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
    pub fn expect_settings<Recv: ReceiveFrame, Sess: Session>(&mut self,
                                                              rx: &mut Recv,
                                                              session: &mut Sess)
                                                              -> HttpResult<()> {
        let frame = rx.recv_frame();
        match frame {
            Ok(HttpFrame::SettingsFrame(settings)) => {
                if settings.is_ack() {
                    Err(HttpError::UnableToConnect)
                } else {
                    debug!("Correctly received a SETTINGS frame from the server");
                    try!(self.handle_frame(HttpFrame::SettingsFrame(settings), session));
                    Ok(())
                }
            }
            // Wrong frame received...
            Ok(_) => Err(HttpError::UnableToConnect),
            // Already an error -- propagate that.
            Err(e) => Err(e),
        }
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
    pub fn handle_next_frame<Recv: ReceiveFrame, Sess: Session>(&mut self,
                                                                rx: &mut Recv,
                                                                session: &mut Sess)
                                                                -> HttpResult<()> {
        debug!("Waiting for frame...");
        let frame = match rx.recv_frame() {
            Ok(frame) => frame,
            Err(e) => {
                debug!("Encountered an HTTP/2 error, stopping.");
                return Err(e);
            }
        };

        self.handle_frame(frame, session)
    }

    /// Private helper method that actually handles a received frame.
    fn handle_frame<Sess: Session>(&mut self,
                                   frame: HttpFrame,
                                   session: &mut Sess)
                                   -> HttpResult<()> {
        match frame {
            HttpFrame::DataFrame(frame) => {
                debug!("Data frame received");
                self.handle_data_frame(frame, session)
            }
            HttpFrame::HeadersFrame(frame) => {
                debug!("Headers frame received");
                self.handle_headers_frame(frame, session)
            }
            HttpFrame::RstStreamFrame(frame) => {
                debug!("RST_STREAM frame received");
                self.handle_rst_stream_frame(frame, session)
            }
            HttpFrame::SettingsFrame(frame) => {
                debug!("Settings frame received");
                self.handle_settings_frame::<Sess>(frame, session)
            },
            HttpFrame::PingFrame(frame) => {
                debug!("PING frame received");
                self.handle_ping_frame(frame, session)
            },
            HttpFrame::GoawayFrame(frame) => {
                debug!("GOAWAY frame received");
                session.on_goaway(frame.last_stream_id(),
                                  frame.error_code(),
                                  frame.debug_data(),
                                  self)
            }
            HttpFrame::WindowUpdateFrame(frame) => {
                debug!("WINDOW_UPDATE frame received");
                self.handle_window_update(frame, session)
            }
            HttpFrame::UnknownFrame(frame) => {
                debug!("Unknown frame received; raw = {:?}", frame);
                // We simply drop any unknown frames...
                // TODO Signal this to the session so that a hook is available
                //      for implementing frame-level protocol extensions.
                Ok(())
            }
        }
    }

    /// Private helper method that handles a received `DataFrame`.
    fn handle_data_frame<Sess: Session>(&mut self,
                                        frame: DataFrame,
                                        session: &mut Sess)
                                        -> HttpResult<()> {
        // Decrease the connection inbound window...
        try!(self.decrease_in_window(frame.payload_len()));
        trace!("New IN WINDOW size = {:?}", self.in_window_size());
        try!(session.on_connection_in_window_decrease(self));

        // ...as well as the stream's...
        try!(session.on_stream_in_window_decrease(
                frame.get_stream_id(),
                frame.payload_len(),
                self));

        // ...before passing off the actual data chunk to the session.
        try!(session.new_data_chunk(frame.get_stream_id(), &frame.data, self));

        if frame.is_set(DataFlag::EndStream) {
            debug!("End of stream {}", frame.get_stream_id());
            try!(session.end_of_stream(frame.get_stream_id(), self));
        }

        Ok(())
    }

    /// Private helper method that handles a received `HeadersFrame`.
    fn handle_headers_frame<Sess: Session>(&mut self,
                                           frame: HeadersFrame,
                                           session: &mut Sess)
                                           -> HttpResult<()> {
        let headers = try!(self.decoder
                               .decode(&frame.header_fragment())
                               .map_err(HttpError::CompressionError));
        let headers = headers.into_iter().map(|h| h.into()).collect();
        try!(session.new_headers(frame.get_stream_id(), headers, self));

        if frame.is_end_of_stream() {
            debug!("End of stream {}", frame.get_stream_id());
            try!(session.end_of_stream(frame.get_stream_id(), self));
        }

        Ok(())
    }

    /// Private helper method that handles a received `RstStreamFrame`
    #[inline]
    fn handle_rst_stream_frame<Sess: Session>(&mut self,
                                              frame: RstStreamFrame,
                                              session: &mut Sess)
                                              -> HttpResult<()> {
        session.rst_stream(frame.get_stream_id(), frame.error_code(), self)
    }

    /// Respond to a ping frame if it's not an ACK
    fn handle_ping_frame<Sess: Session>(&mut self, frame: PingFrame, session: &mut Sess)
            -> HttpResult<()> {
        if frame.is_ack() {
            session.on_pong(&frame, self)
        } else {
            session.on_ping(&frame, self)
        }
    }

    /// Private helper method that handles a received `SettingsFrame`.
    fn handle_settings_frame<Sess: Session>(&mut self,
                                            frame: SettingsFrame,
                                            session: &mut Sess)
                                            -> HttpResult<()> {
        if !frame.is_ack() {
            // TODO: Actually handle the settings change before sending out the ACK
            trace!("New settings frame {:#?}", frame);
            try!(session.new_settings(frame.settings, self));
        }

        Ok(())
    }

    /// Private helper method that handles an incoming `WindowUpdateFrame`.
    fn handle_window_update<Sess: Session>(&mut self,
                                           frame: WindowUpdateFrame,
                                           session: &mut Sess)
                                           -> HttpResult<()> {
        if frame.get_stream_id() == 0 {
            // TODO: If overflow does occur, notify the session so that it can try to send a
            //       GOAWAY before tearing down the connection.
            try!(self.out_window_size.try_increase(frame.increment())
                                     .map_err(|_| HttpError::WindowSizeOverflow));
            try!(session.on_connection_out_window_update(self));
        } else {
            try!(session.on_stream_out_window_update(frame.get_stream_id(),
                                                     frame.increment(),
                                                     self));
        }

        Ok(())
    }

    /// Internal helper method that decreases the outbound flow control window size.
    fn decrease_out_window(&mut self, size: u32) -> HttpResult<()> {
        // The size by which we decrease the window must be at most 2^31 - 1. We should be able to
        // reach here only after sending a DATA frame, whose payload also cannot be larger than
        // that, but we assert it just in case.
        debug_assert!(size < 0x80000000);
        self.out_window_size
            .try_decrease(size as i32)
            .map_err(|_| HttpError::WindowSizeOverflow)
    }

    /// Internal helper method that decreases the inbound flow control window size.
    fn decrease_in_window(&mut self, size: u32) -> HttpResult<()> {
        // The size by which we decrease the window must be at most 2^31 - 1. We should be able to
        // reach here only after receiving a DATA frame, which would have been validated when
        // parsed from the raw frame to have the correct payload size, but we assert it just in
        // case.
        debug_assert!(size < 0x80000000);
        self.in_window_size
            .try_decrease(size as i32)
            .map_err(|_| HttpError::WindowSizeOverflow)
    }
}

/// A helper method for tests that allows the window sizes of the given connection to be modified.
/// Since this touches the internal state that isn't intended to be modified by clients directly,
/// it is intended only as a helper for tests.
#[cfg(test)]
pub fn set_connection_windows(conn: &mut HttpConnection,
                              in_window: WindowSize,
                              out_window: WindowSize) {
    conn.in_window_size = in_window;
    conn.out_window_size = out_window;
}

#[cfg(test)]
mod tests {
    use std::borrow::Cow;
    use std::io;

    use super::{HttpConnection, HttpFrame, SendFrame, EndStream, DataChunk, SendStatus};

    use http::tests::common::{build_mock_http_conn, StubDataPrioritizer, TestSession,
                              MockReceiveFrame, MockSendFrame};
    use http::frame::{Frame, DataFrame, HeadersFrame, RstStreamFrame, GoawayFrame, SettingsFrame,
                      WindowUpdateFrame, PingFrame, pack_header, RawFrame, FrameIR};
    use http::{HttpResult, HttpError, HttpScheme, Header, OwnedHeader, ErrorCode};
    use hpack;

    /// A helper function that performs a `send_frame` operation on the given
    /// `HttpConnection` by providing the frame instance wrapped in the given
    /// `HttpFrame`.
    ///
    /// If the `HttpFrame` variant is `HttpFrame::UnknownFrame`, nothing will
    /// be sent and an `Ok(())` is returned.
    fn send_frame<S: SendFrame>(sender: &mut S,
                                conn: &mut HttpConnection,
                                frame: HttpFrame)
                                -> HttpResult<()> {
        match frame {
            HttpFrame::DataFrame(frame) => conn.sender(sender).send_frame(frame),
            HttpFrame::SettingsFrame(frame) => conn.sender(sender).send_frame(frame),
            HttpFrame::RstStreamFrame(frame) => conn.sender(sender).send_frame(frame),
            HttpFrame::HeadersFrame(frame) => conn.sender(sender).send_frame(frame),
            HttpFrame::PingFrame(frame) => conn.sender(sender).send_frame(frame),
            HttpFrame::GoawayFrame(frame) => conn.sender(sender).send_frame(frame),
            HttpFrame::WindowUpdateFrame(frame) => conn.sender(sender).send_frame(frame),
            HttpFrame::UnknownFrame(_) => Ok(()),
        }
    }

    /// Tests that the `HttpFrame::from_raw` method correctly recognizes the frame
    /// type from the header and returns the corresponding variant.
    #[test]
    fn test_http_frame_from_raw() {
        fn to_raw<'a, F: FrameIR>(frame: F) -> RawFrame<'static> {
            let mut buf = io::Cursor::new(Vec::new());
            frame.serialize_into(&mut buf).unwrap();
            RawFrame::from(buf.into_inner())
        }

        assert!(match HttpFrame::from_raw(&to_raw(DataFrame::new(1))) {
            Ok(HttpFrame::DataFrame(_)) => true,
            _ => false,
        });

        assert!(match HttpFrame::from_raw(&to_raw(HeadersFrame::new(vec![], 1))) {
            Ok(HttpFrame::HeadersFrame(_)) => true,
            _ => false,
        });

        assert!(match HttpFrame::from_raw(&to_raw(SettingsFrame::new())) {
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
        assert!(match HttpFrame::from_raw(&unknown_frame) {
            Ok(HttpFrame::UnknownFrame(_)) => true,
            _ => false,
        });

        // Invalid since it's headers on stream 0
        let invalid_frame = HeadersFrame::new(vec![], 0);
        assert!(HttpFrame::from_raw(&to_raw(invalid_frame)).is_err());
    }

    fn expect_frame_list(expected: Vec<HttpFrame>, sent: Vec<RawFrame>) {
        for (expect, actual) in expected.into_iter().zip(sent.into_iter()) {
            let actual = HttpFrame::from_raw(&actual).unwrap();
            assert_eq!(expect, actual);
        }
    }

    /// Tests that it is possible to write a single frame to the connection.
    #[test]
    fn test_write_single_frame() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
        ];
        let expected = frames.clone();
        let mut conn = build_mock_http_conn();
        let mut sender = MockSendFrame::new();

        for frame in frames.into_iter() {
            send_frame(&mut sender, &mut conn, frame).unwrap();
        }

        expect_frame_list(expected, sender.sent);
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
        let mut sender = MockSendFrame::new();
        let chunks = vec![
            vec![1, 2, 3, 4],
            vec![5, 6],
            vec![7],
            vec![],
        ];
        let mut prioritizer = StubDataPrioritizer::new(chunks.clone());

        let mut expected_window = 65_535;
        assert_eq!(conn.out_window_size(), expected_window);
        // Send as many chunks as we've given the prioritizer
        for chunk in chunks.iter() {
            assert_eq!(SendStatus::Sent,
                       conn.sender(&mut sender).send_next_data(&mut prioritizer).unwrap());
            let last = sender.sent.pop().unwrap();
            expect_chunk(&chunk, &HttpFrame::from_raw(&last).unwrap());
            expected_window -= chunk.len() as i32;
            assert_eq!(conn.out_window_size(), expected_window);
        }
        // Nothing to send any more
        assert_eq!(SendStatus::Nothing,
                   conn.sender(&mut sender).send_next_data(&mut prioritizer).unwrap());
        // No change to the window either, of course.
        assert_eq!(conn.out_window_size(), expected_window);
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
        let mut sender = MockSendFrame::new();

        for frame in frames.into_iter() {
            send_frame(&mut sender, &mut conn, frame).unwrap();
        }

        expect_frame_list(expected, sender.sent);
    }

    /// Tests that `HttpConnection::send_headers` correctly sends the given headers when they can
    /// fit into a single frame's payload.
    #[test]
    fn test_send_headers_single_frame() {
        fn assert_correct_headers(headers: &[Header], frame: &HeadersFrame) {
            let buf = frame.header_fragment();
            let frame_headers = hpack::Decoder::new().decode(buf).unwrap();
            let headers: Vec<OwnedHeader> = headers.iter().map(|h| h.clone().into()).collect();
            assert_eq!(headers, frame_headers);
        }
        let headers: Vec<Header> = vec![
            Header::new(b":method", b"GET"),
            Header::new(b":scheme", b"http"),
        ];
        {
            let mut conn = build_mock_http_conn();
            let mut sender = MockSendFrame::new();

            // Headers when the stream should be closed
            conn.sender(&mut sender).send_headers(&headers[..], 1, EndStream::Yes).unwrap();

            // Only 1 frame sent?
            assert_eq!(sender.sent.len(), 1);
            // The headers frame?
            let frame = match HttpFrame::from_raw(&sender.sent[0]).unwrap() {
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
            let mut sender = MockSendFrame::new();

            // Headers when the stream should be left open
            conn.sender(&mut sender).send_headers(&headers[..], 1, EndStream::No).unwrap();

            // Only 1 frame sent?
            assert_eq!(sender.sent.len(), 1);
            // The headers frame?
            let frame = match HttpFrame::from_raw(&sender.sent[0]).unwrap() {
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
            let mut sender = MockSendFrame::new();

            // Make sure it's all peachy when we give a `Vec` instead of a slice
            conn.sender(&mut sender).send_headers(headers.clone(), 1, EndStream::Yes).unwrap();

            // Only 1 frame sent?
            assert_eq!(sender.sent.len(), 1);
            // The headers frame?
            let frame = match HttpFrame::from_raw(&sender.sent[0]).unwrap() {
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
            let mut sender = MockSendFrame::new();
            let data: &[u8] = b"1234";

            conn.sender(&mut sender)
                .send_data(DataChunk::new_borrowed(data, 1, EndStream::No))
                .unwrap();

            // Only 1 frame sent?
            assert_eq!(sender.sent.len(), 1);
            // A data frame?
            let raw = sender.sent.remove(0);
            let parsed_frame = HttpFrame::from_raw(&raw);
            let frame = match parsed_frame {
                Ok(HttpFrame::DataFrame(frame)) => frame,
                _ => panic!("Data frame not sent"),
            };
            assert_eq!(&frame.data[..], data);
            assert!(!frame.is_end_of_stream());
            assert_eq!(conn.out_window_size(), 65_535 - data.len() as i32);
        }
        {
            // Data should end the stream...
            let mut conn = build_mock_http_conn();
            let mut sender = MockSendFrame::new();
            let data: &[u8] = b"1234";

            conn.sender(&mut sender)
                .send_data(DataChunk::new_borrowed(data, 1, EndStream::Yes))
                .unwrap();

            // Only 1 frame sent?
            assert_eq!(sender.sent.len(), 1);
            // A data frame?
            let raw = sender.sent.remove(0);
            let parsed_frame = HttpFrame::from_raw(&raw).unwrap();
            let frame = match parsed_frame {
                HttpFrame::DataFrame(frame) => frame,
                _ => panic!("Data frame not sent"),
            };
            assert_eq!(&frame.data[..], data);
            assert!(frame.is_end_of_stream());
            assert_eq!(conn.out_window_size(), 65_535 - data.len() as i32);
        }
        {
            // given a `Vec` we're good too?
            let mut conn = build_mock_http_conn();
            let mut sender = MockSendFrame::new();
            let data: &[u8] = b"1234";
            let chunk = DataChunk {
                data: Cow::Owned(data.to_vec()),
                stream_id: 1,
                end_stream: EndStream::Yes,
            };

            conn.sender(&mut sender).send_data(chunk).unwrap();

            // Only 1 frame sent?
            assert_eq!(sender.sent.len(), 1);
            // A data frame?
            let raw = sender.sent.remove(0);
            let parsed_frame = HttpFrame::from_raw(&raw).unwrap();
            let frame = match parsed_frame {
                HttpFrame::DataFrame(frame) => frame,
                _ => panic!("Data frame not sent"),
            };
            assert_eq!(&frame.data[..], data);
            assert!(frame.is_end_of_stream());
            assert_eq!(conn.out_window_size(), 65_535 - data.len() as i32);
        }
    }

    #[test]
    fn test_send_rst_stream() {
        let expected = vec![
            HttpFrame::RstStreamFrame(RstStreamFrame::new(1, ErrorCode::InternalError)),
        ];

        let mut conn = build_mock_http_conn();
        let mut sender = MockSendFrame::new();
        conn.sender(&mut sender).rst_stream(1, ErrorCode::InternalError).unwrap();

        expect_frame_list(expected, sender.sent);
    }

    #[test]
    fn test_send_connection_window_update_non_zero() {
        let increment = 100;
        let expected = vec![
            HttpFrame::WindowUpdateFrame(WindowUpdateFrame::for_connection(increment)),
        ];

        let mut conn = build_mock_http_conn();
        let mut sender = MockSendFrame::new();
        conn.sender(&mut sender).send_connection_window_update(increment).unwrap();

        expect_frame_list(expected, sender.sent);
    }

    #[test]
    fn test_send_connection_window_update_is_zero() {
        let increment = 0;

        let mut conn = build_mock_http_conn();
        let mut sender = MockSendFrame::new();
        conn.sender(&mut sender).send_connection_window_update(increment).unwrap();

        expect_frame_list(vec![], sender.sent);
    }

    #[test]
    fn test_send_stream_window_update_non_zero() {
        let increment = 100;
        let expected = vec![
            HttpFrame::WindowUpdateFrame(WindowUpdateFrame::for_stream(1, increment)),
        ];

        let mut conn = build_mock_http_conn();
        let mut sender = MockSendFrame::new();
        conn.sender(&mut sender).send_stream_window_update(1, increment).unwrap();

        expect_frame_list(expected, sender.sent);
    }

    #[test]
    fn test_send_stream_window_update_is_zero() {
        let increment = 0;

        let mut conn = build_mock_http_conn();
        let mut sender = MockSendFrame::new();
        conn.sender(&mut sender).send_stream_window_update(1, increment).unwrap();

        expect_frame_list(vec![], sender.sent);
    }

    #[test]
    fn test_increase_connection_window() {
        let mut conn = build_mock_http_conn();
        assert_eq!(conn.in_window_size(), 0xffff);
        conn.increase_connection_window_size(500).unwrap();
        assert_eq!(conn.in_window_size(), 0xffff + 500);
        conn.increase_connection_window_size(5).unwrap();
        assert_eq!(conn.in_window_size(), 0xffff + 500 + 5);
        // Overflow!
        assert!(match conn.increase_connection_window_size(0x7fffffff).err().unwrap() {
            HttpError::WindowSizeOverflow => true,
            _ => false,
        });
    }

    /// Tests that the `HttpConnection` correctly notifies the session on a
    /// new headers frame, with no continuation.
    #[test]
    fn test_http_conn_notifies_session_header() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(vec![], 1)),
        ];
        let mut conn = HttpConnection::new(HttpScheme::Http);
        let mut session = TestSession::new();
        let mut frame_provider = MockReceiveFrame::new(frames);

        conn.handle_next_frame(&mut frame_provider, &mut session).unwrap();

        // A poor man's mock...
        // The header callback was called
        assert_eq!(session.curr_header, 1);
        // ...no chunks were seen.
        assert_eq!(session.curr_chunk, 0);
        assert_eq!(session.rst_streams.len(), 0);
    }

    /// Tests that the `HttpConnection` correctly notifies the session on
    /// a new data chunk.
    #[test]
    fn test_http_conn_notifies_session_data() {
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::DataFrame(DataFrame::with_data(1, vec![1, 2, 3, 4, 5, 6])),
        ];
        let mut conn = HttpConnection::new(HttpScheme::Http);
        let mut session = TestSession::new();
        let mut frame_provider = MockReceiveFrame::new(frames);

        conn.handle_next_frame(&mut frame_provider, &mut session).unwrap();

        // The header callback was not called
        assert_eq!(session.curr_header, 0);
        // and exactly one chunk seen.
        assert_eq!(session.curr_chunk, 1);
        // which caused the stream's window to decrease
        assert_eq!(session.stream_window_decreases.len(), 1);
        assert_eq!(session.stream_window_decreases[0], (1, 6));

        // as well as the connection's...
        let new_conn_in_window = 65_535 - 6;
        assert_eq!(conn.in_window_size(), new_conn_in_window);
        // ...which was reported to the session
        assert_eq!(session.conn_in_window_decreases, vec![new_conn_in_window]);

        assert_eq!(session.rst_streams.len(), 0);
    }

    /// Tests that the session gets the correct values for the headers and data
    /// from the `HttpConnection` when multiple frames are handled.
    #[test]
    fn test_http_conn_session_gets_headers_data_values() {
        let expected_headers = vec![(b":method".to_vec(), b"GET".to_vec())];
        let frames: Vec<HttpFrame> = vec![
            HttpFrame::HeadersFrame(HeadersFrame::new(
                    hpack::Encoder::new().encode(
                        expected_headers.iter().map(|h| (&h.0[..], &h.1[..]))),
                    1)),
            HttpFrame::DataFrame(DataFrame::new(1)),
            HttpFrame::DataFrame(DataFrame::with_data(1, &b"1234"[..])),
        ];
        let mut conn = HttpConnection::new(HttpScheme::Http);
        let mut session = TestSession::new_verify(vec![expected_headers],
                                                  vec![b"".to_vec(), b"1234".to_vec()]);
        let mut frame_provider = MockReceiveFrame::new(frames);

        conn.handle_next_frame(&mut frame_provider, &mut session).unwrap();
        conn.handle_next_frame(&mut frame_provider, &mut session).unwrap();
        conn.handle_next_frame(&mut frame_provider, &mut session).unwrap();
        assert_eq!(conn.in_window_size(), 65_535 - 4);
        assert_eq!(session.conn_in_window_decreases, vec![65_535, 65_535 - 4]);
        assert_eq!(session.stream_window_decreases.len(), 2);
        assert_eq!(session.stream_window_decreases[0], (1, 0));
        assert_eq!(session.stream_window_decreases[1], (1, 4));

        // Two chunks and one header processed?
        assert_eq!(session.curr_chunk, 2);
        assert_eq!(session.curr_header, 1);
    }

    /// Tests that the `HttpConnection` correctly notifies the session when a stream is reset.
    #[test]
    fn test_conn_rst_stream() {
        let frames = vec![
            HttpFrame::RstStreamFrame(RstStreamFrame::new(1, ErrorCode::ProtocolError)),
        ];
        let mut conn = HttpConnection::new(HttpScheme::Http);
        let mut session = TestSession::new();
        let mut frame_provider = MockReceiveFrame::new(frames);

        conn.handle_next_frame(&mut frame_provider, &mut session).unwrap();

        // One stream reset.
        assert_eq!(session.rst_streams.len(), 1);
        assert_eq!(session.rst_streams[0], 1);
    }

    /// Tests that the `HttpConnection` correctly notifies the session when it receives a GOAWAY
    /// frame.
    #[test]
    fn test_conn_on_goaway() {
        let frames = vec![
            HttpFrame::GoawayFrame(GoawayFrame::new(0, ErrorCode::ProtocolError)),
        ];
        let mut conn = HttpConnection::new(HttpScheme::Http);
        let mut session = TestSession::new();
        let mut frame_provider = MockReceiveFrame::new(frames);

        conn.handle_next_frame(&mut frame_provider, &mut session).unwrap();

        assert_eq!(session.goaways.len(), 1);
        assert_eq!(session.goaways[0], ErrorCode::ProtocolError);
        assert_eq!(session.curr_header, 0);
        assert_eq!(session.curr_chunk, 0);
        assert_eq!(session.rst_streams.len(), 0);
    }

    #[test]
    fn test_conn_window_update() {
        let frames = vec![
            HttpFrame::WindowUpdateFrame(WindowUpdateFrame::for_connection(100)),
        ];
        let mut conn = HttpConnection::new(HttpScheme::Http);
        let mut session = TestSession::new();
        let mut frame_provider = MockReceiveFrame::new(frames);

        conn.handle_next_frame(&mut frame_provider, &mut session).unwrap();

        assert_eq!(session.conn_window_updates.len(), 1);
        assert_eq!(session.conn_window_updates[0], 0xffff + 100);
        // Nothing happened with the rest...
        assert_eq!(session.stream_window_updates.len(), 0);
        assert_eq!(session.goaways.len(), 0);
        assert_eq!(session.curr_header, 0);
        assert_eq!(session.curr_chunk, 0);
        assert_eq!(session.rst_streams.len(), 0);
    }

    #[test]
    fn test_conn_stream_window_update() {
        let frames = vec![
            HttpFrame::WindowUpdateFrame(WindowUpdateFrame::for_stream(1, 100)),
        ];
        let mut conn = HttpConnection::new(HttpScheme::Http);
        let mut session = TestSession::new();
        let mut frame_provider = MockReceiveFrame::new(frames);

        conn.handle_next_frame(&mut frame_provider, &mut session).unwrap();

        assert_eq!(session.stream_window_updates.len(), 1);
        assert_eq!(session.stream_window_updates[0], (1, 100));
        // Nothing happened with the rest...
        assert_eq!(session.conn_window_updates.len(), 0);
        assert_eq!(session.goaways.len(), 0);
        assert_eq!(session.curr_header, 0);
        assert_eq!(session.curr_chunk, 0);
        assert_eq!(session.rst_streams.len(), 0);
    }

    /// Tests that the connection flow control windows have the correct size when the
    /// HttpConnection is just created.
    #[test]
    fn test_conn_initial_windows() {
        let conn = HttpConnection::new(HttpScheme::Http);
        assert_eq!(conn.in_window_size(), 65_535);
        assert_eq!(conn.out_window_size(), 65_535);
    }

    /// Tests that the `HttpConnection::expect_settings` method works correctly.
    #[test]
    fn test_http_conn_expect_settings() {
        {
            // The next frame is indeed a settings frame.
            let frames = vec![HttpFrame::SettingsFrame(SettingsFrame::new())];
            let mut conn = HttpConnection::new(HttpScheme::Http);
            let mut frame_provider = MockReceiveFrame::new(frames);
            assert!(conn.expect_settings(&mut frame_provider, &mut TestSession::new()).is_ok());
        }
        {
            // The next frame is a data frame...
            let frames = vec![HttpFrame::DataFrame(DataFrame::new(1))];
            let mut conn = HttpConnection::new(HttpScheme::Http);
            let mut frame_provider = MockReceiveFrame::new(frames);
            assert!(conn.expect_settings(&mut frame_provider, &mut TestSession::new()).is_err());
        }
        {
            // The next frame is an ACK settings frame
            let frames = vec![HttpFrame::SettingsFrame(SettingsFrame::new_ack())];
            let mut conn = HttpConnection::new(HttpScheme::Http);
            let mut frame_provider = MockReceiveFrame::new(frames);
            assert!(conn.expect_settings(&mut frame_provider, &mut TestSession::new()).is_err());
        }
    }

    /// Tests that the session is appropriately notified when a PING frame is received.
    #[test]
    fn test_on_ping() {
        let frames = vec![HttpFrame::PingFrame(PingFrame::new())];
        let mut conn = HttpConnection::new(HttpScheme::Http);
        let mut session = TestSession::new();
        let mut frame_provider = MockReceiveFrame::new(frames);

        conn.handle_next_frame(&mut frame_provider, &mut session).unwrap();

        assert_eq!(session.pings, vec![0]);
        assert_eq!(session.pongs, vec![]);
    }

    /// Tests that the session is appropriately notified when a PING ack frame is received.
    #[test]
    fn test_on_pong() {
        let frames = vec![HttpFrame::PingFrame(PingFrame::new_ack(123))];
        let mut conn = HttpConnection::new(HttpScheme::Http);
        let mut session = TestSession::new();
        let mut frame_provider = MockReceiveFrame::new(frames);

        conn.handle_next_frame(&mut frame_provider, &mut session).unwrap();

        assert_eq!(session.pongs, vec![123]);
        assert_eq!(session.pings, vec![]);
    }
}
