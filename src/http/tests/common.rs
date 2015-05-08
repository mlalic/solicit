//! The module contains some common utilities for `solicit::http` tests.

use std::io;

use http::{
    HttpResult,
    HttpScheme
};
use http::frame::RawFrame;
use http::connection::{
    SendFrame,
    ReceiveFrame,
    HttpFrame,
    HttpConnection,
};

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
