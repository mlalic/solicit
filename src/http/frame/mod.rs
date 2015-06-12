//! The module contains the implementation of HTTP/2 frames.

use std::mem;

use http::StreamId;

/// A helper macro that unpacks a sequence of 4 bytes found in the buffer with
/// the given identifier, starting at the given offset, into the given integer
/// type. Obviously, the integer type should be able to support at least 4
/// bytes.
///
/// # Examples
///
/// ```rust
/// let buf: [u8; 4] = [0, 0, 0, 1];
/// assert_eq!(1u32, unpack_octets_4!(buf, 0, u32));
/// ```
#[macro_escape]
macro_rules! unpack_octets_4 {
    ($buf:ident, $offset:expr, $tip:ty) => (
        (($buf[$offset + 0] as $tip) << 24) |
        (($buf[$offset + 1] as $tip) << 16) |
        (($buf[$offset + 2] as $tip) <<  8) |
        (($buf[$offset + 3] as $tip) <<  0)
    );
}

pub mod data;
pub mod headers;
pub mod settings;

/// Rexports related to the `DATA` frame.
pub use self::data::{DataFlag, DataFrame};
/// Rexports related to the `HEADERS` frame.
pub use self::headers::{HeadersFlag, HeadersFrame};
/// Rexports related to the `SETTINGS` frame.
pub use self::settings::{SettingsFlag, SettingsFrame, HttpSetting};

/// An alias for the 9-byte buffer that each HTTP/2 frame header must be stored
/// in.
pub type FrameHeaderBuffer = [u8; 9];
/// An alias for the 4-tuple representing the components of each HTTP/2 frame
/// header.
pub type FrameHeader = (u32, u8, u8, u32);

/// Deconstructs a `FrameHeader` into its corresponding 4 components,
/// represented as a 4-tuple: `(length, frame_type, flags, stream_id)`.
///
/// The frame `type` and `flags` components are returned as their original
/// octet representation, rather than reinterpreted.
pub fn unpack_header(header: &FrameHeaderBuffer) -> FrameHeader {
    let length: u32 =
        ((header[0] as u32) << 16) |
        ((header[1] as u32) <<  8) |
        ((header[2] as u32) <<  0);
    let frame_type = header[3];
    let flags = header[4];
    let stream_id: u32 = unpack_octets_4!(header, 5, u32);

    (length, frame_type, flags, stream_id)
}

/// Constructs a buffer of 9 bytes that represents the given `FrameHeader`.
pub fn pack_header(header: &FrameHeader) -> FrameHeaderBuffer {
    let &(length, frame_type, flags, stream_id) = header;

    [
        (((length >> 16) & 0x000000FF) as u8),
        (((length >>  8) & 0x000000FF) as u8),
        (((length >>  0) & 0x000000FF) as u8),
        frame_type,
        flags,
        (((stream_id >> 24) & 0x000000FF) as u8),
        (((stream_id >> 16) & 0x000000FF) as u8),
        (((stream_id >>  8) & 0x000000FF) as u8),
        (((stream_id >>  0) & 0x000000FF) as u8),
    ]
}

/// A helper function that parses the given payload, considering it padded.
///
/// This means that the first byte is the length of the padding with that many
/// 0 bytes expected to follow the actual payload.
///
/// # Returns
///
/// A slice of the given payload where the actual one is found and the length
/// of the padding.
///
/// If the padded payload is invalid (e.g. the length of the padding is equal
/// to the total length), returns `None`.
fn parse_padded_payload<'a>(payload: &'a [u8]) -> Option<(&'a [u8], u8)> {
    if payload.len() == 0 {
        // We make sure not to index the payload before we're sure how
        // large the buffer is.
        // If this is the case, the frame is invalid as no padding
        // length can be extracted, even though the frame should be
        // padded.
        return None;
    }
    let pad_len = payload[0] as usize;
    if pad_len >= payload.len() {
        // This is invalid: the padding length MUST be less than the
        // total frame size.
        return None;
    }

    Some((&payload[1..payload.len() - pad_len], pad_len as u8))
}

/// A trait that all HTTP/2 frame header flags need to implement.
pub trait Flag {
    /// Returns a bit mask that represents the flag.
    fn bitmask(&self) -> u8;
}

/// A trait that all HTTP/2 frame structs need to implement.
pub trait Frame {
    /// The type that represents the flags that the particular `Frame` can take.
    /// This makes sure that only valid `Flag`s are used with each `Frame`.
    type FlagType: Flag;

    /// Creates a new `Frame` from the given `RawFrame` (i.e. header and
    /// payload), if possible.
    ///
    /// # Returns
    ///
    /// `None` if a valid `Frame` cannot be constructed from the given
    /// `RawFrame`. Some reasons why this may happen is a wrong frame type in
    /// the header, a body that cannot be decoded according to the particular
    /// frame's rules, etc.
    ///
    /// Otherwise, returns a newly constructed `Frame`.
    fn from_raw(raw_frame: RawFrame) -> Option<Self>;

    /// Tests if the given flag is set for the frame.
    fn is_set(&self, flag: Self::FlagType) -> bool;
    /// Returns the `StreamId` of the stream to which the frame is associated
    fn get_stream_id(&self) -> StreamId;
    /// Returns a `FrameHeader` based on the current state of the `Frame`.
    fn get_header(&self) -> FrameHeader;

    /// Sets the given flag for the frame.
    fn set_flag(&mut self, flag: Self::FlagType);

    /// Returns a `Vec` with the serialized representation of the frame.
    fn serialize(&self) -> Vec<u8>;
}

/// A struct that defines the format of the raw HTTP/2 frame, i.e. the frame
/// as it is read from the wire.
///
/// This format is defined in section 4.1. of the HTTP/2 spec.
///
/// The `RawFrame` struct simply stores the raw components of an HTTP/2 frame:
/// its header and the payload as a sequence of bytes.
///
/// It does not try to interpret the payload bytes, nor do any validation in
/// terms of its validity based on the frame type given in the header.
/// It is simply a wrapper around the two parts of an HTTP/2 frame.
#[derive(PartialEq)]
#[derive(Debug)]
#[derive(Clone)]
pub struct RawFrame {
    /// The raw frame representation, including both the raw header representation
    /// (in the first 9 bytes), followed by the raw payload representation.
    raw_content: Vec<u8>,
}

impl RawFrame {
    /// Creates a new `RawFrame` with the given `FrameHeader`. The payload is
    /// left empty.
    pub fn new(header: FrameHeader) -> RawFrame {
        RawFrame::with_payload(header, Vec::new())
    }

    /// Creates a new `RawFrame` with the given header and payload.
    /// Does not do any validation to determine whether the frame is in a correct
    /// state as constructed.
    pub fn with_payload(header: FrameHeader, payload: Vec<u8>) -> RawFrame {
        let mut raw = Vec::new();
        raw.extend(pack_header(&header).into_iter().map(|x| *x));
        raw.extend(payload);

        RawFrame {
            raw_content: raw,
        }
    }

    /// Creates a new `RawFrame` by parsing the given buffer.
    ///
    /// # Returns
    ///
    /// A `RawFrame` instance constructed from the given buffer.
    ///
    /// If the buffer cannot be parsed into a frame, which includes the payload
    /// section having a different length than what was found in the header,
    /// `None` is returned.
    pub fn from_buf(buf: &[u8]) -> Option<RawFrame> {
        if buf.len() < 9 {
            return None;
        }
        let header = unpack_header(unsafe {
            assert!(buf.len() >= 9);
            // We just asserted that this transmute is safe.
            mem::transmute(buf.as_ptr())
        });
        let payload_len = header.0 as usize;

        if buf[9..].len() != payload_len {
            return None;
        }

        Some(RawFrame {
            raw_content: buf.to_vec(),
        })
    }

    /// Returns a `Vec` of bytes representing the serialized (on-the-wire)
    /// representation of this raw frame.
    pub fn serialize(&self) -> Vec<u8> {
        self.raw_content.clone()
    }

    /// Returns a `FrameHeader` instance corresponding to the headers of the
    /// `RawFrame`.
    pub fn header(&self) -> FrameHeader {
        unpack_header(unsafe {
            assert!(self.raw_content.len() >= 9);
            // We just asserted that this transmute is safe.
            mem::transmute(self.raw_content.as_ptr())
        })
    }

    /// Returns a slice representing the payload of the `RawFrame`.
    pub fn payload(&self) -> &[u8] {
        &self.raw_content[9..]
    }
}

/// Provide a conversion into a `Vec`.
impl Into<Vec<u8>> for RawFrame {
    fn into(self) -> Vec<u8> { self.raw_content }
}

/// Provide a conversion from a `Vec`.
///
/// This conversion is unchecked and could cause the resulting `RawFrame` to be an
/// invalid HTTP/2 frame.
impl From<Vec<u8>> for RawFrame {
    fn from(raw: Vec<u8>) -> RawFrame { RawFrame { raw_content: raw } }
}

#[cfg(test)]
mod tests {
    use super::{
        unpack_header,
        pack_header,
        RawFrame,
        FrameHeader,
        Frame,
    };

    /// Tests that the `unpack_header` function correctly returns the
    /// components of HTTP/2 frame headers.
    #[test]
    fn test_unpack_header() {
        {
            let header = [0; 9];
            assert_eq!((0, 0, 0, 0), unpack_header(&header));
        }
        {
            let header = [0, 0, 1, 2, 3, 0, 0, 0, 4];
            assert_eq!((1, 2, 3, 4), unpack_header(&header));
        }
        {
            let header = [0, 0, 1, 200, 100, 0, 0, 0, 4];
            assert_eq!((1, 200, 100, 4), unpack_header(&header));
        }
        {
            let header = [0, 0, 1, 0, 0, 0, 0, 0, 0];
            assert_eq!((1, 0, 0, 0), unpack_header(&header));
        }
        {
            let header = [0, 1, 0, 0, 0, 0, 0, 0, 0];
            assert_eq!((256, 0, 0, 0), unpack_header(&header));
        }
        {
            let header = [1, 0, 0, 0, 0, 0, 0, 0, 0];
            assert_eq!((256 * 256, 0, 0, 0), unpack_header(&header));
        }
        {
            let header = [0, 0, 0, 0, 0, 0, 0, 0, 1];
            assert_eq!((0, 0, 0, 1), unpack_header(&header));
        }
        {
            let header = [0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 1];
            assert_eq!(((1 << 24) - 1, 0, 0, 1), unpack_header(&header));
        }
        {
            let header = [0xFF, 0xFF, 0xFF, 0, 0, 1, 1, 1, 1];
            assert_eq!(
                ((1 << 24) - 1, 0, 0, 1 + (1 << 8) + (1 << 16) + (1 << 24)),
                unpack_header(&header));
        }
    }

    /// Tests that the `pack_header` function correctly returns the buffer
    /// corresponding to components of HTTP/2 frame headers.
    #[test]
    fn test_pack_header() {
        {
            let header = [0; 9];
            assert_eq!(pack_header(&(0, 0, 0, 0)), header);
        }
        {
            let header = [0, 0, 1, 2, 3, 0, 0, 0, 4];
            assert_eq!(pack_header(&(1, 2, 3, 4)), header);
        }
        {
            let header = [0, 0, 1, 200, 100, 0, 0, 0, 4];
            assert_eq!(pack_header(&(1, 200, 100, 4)), header);
        }
        {
            let header = [0, 0, 1, 0, 0, 0, 0, 0, 0];
            assert_eq!(pack_header(&(1, 0, 0, 0)), header);
        }
        {
            let header = [0, 1, 0, 0, 0, 0, 0, 0, 0];
            assert_eq!(pack_header(&(256, 0, 0, 0)), header);
        }
        {
            let header = [1, 0, 0, 0, 0, 0, 0, 0, 0];
            assert_eq!(pack_header(&(256 * 256, 0, 0, 0)), header);
        }
        {
            let header = [0, 0, 0, 0, 0, 0, 0, 0, 1];
            assert_eq!(pack_header(&(0, 0, 0, 1)), header);
        }
        {
            let header = [0xFF, 0xFF, 0xFF, 0, 0, 0, 0, 0, 1];
            assert_eq!(pack_header(&((1 << 24) - 1, 0, 0, 1)), header);
        }
        {
            let header = [0xFF, 0xFF, 0xFF, 0, 0, 1, 1, 1, 1];
            let header_components = (
                (1 << 24) - 1, 0, 0, 1 + (1 << 8) + (1 << 16) + (1 << 24)
            );
            assert_eq!(pack_header(&header_components), header);
        }
    }

    /// Builds a test frame of the given type with the given header and
    /// payload, by using the `Frame::from_raw` method.
    pub fn build_test_frame<F: Frame>(header: &FrameHeader, payload: &[u8]) -> F {
        let raw = RawFrame::with_payload(header.clone(), payload.to_vec());
        Frame::from_raw(raw).unwrap()
    }

    /// Builds a `Vec` containing the given data as a padded HTTP/2 frame.
    ///
    /// It first places the length of the padding, followed by the data,
    /// followed by `pad_len` zero bytes.
    pub fn build_padded_frame_payload(data: &[u8], pad_len: u8) -> Vec<u8> {
        let sz = 1 + data.len() + pad_len as usize;
        let mut payload: Vec<u8> = Vec::with_capacity(sz);
        payload.push(pad_len);
        payload.extend(data.to_vec().into_iter());
        for _ in 0..pad_len { payload.push(0); }

        payload
    }

    /// Tests that the `RawFrame::with_payload` method correctly constructs a
    /// `RawFrame` from the given parts.
    #[test]
    fn test_raw_frame_with_payload() {
        // Correct frame
        {
            let data = b"123";
            let header = (data.len() as u32, 0x1, 0, 1);

            let raw = RawFrame::with_payload(header, data.to_vec());

            assert_eq!(raw.header(), header);
            assert_eq!(raw.payload(), data)
        }
        // Correct frame with trailing data
        {
            let data = b"123456";
            let header = (3, 0x1, 0, 1);

            let raw = RawFrame::with_payload(header, data.to_vec());

            // No validation of whether the parts form a correct frame
            assert_eq!(raw.header(), header);
            assert_eq!(raw.payload(), data)
        }
        // Missing payload chunk
        {
            let data = b"123";
            let header = (6, 0x1, 0, 1);

            let raw = RawFrame::with_payload(header, data.to_vec());

            // No validation of whether the parts form a correct frame
            assert_eq!(raw.header(), header);
            assert_eq!(raw.payload(), data)
        }
    }

    /// Tests that the `RawFrame::from_buf` method correctly constructs a
    /// `RawFrame` from a given buffer.
    #[test]
    fn test_raw_frame_from_buffer() {
        // Correct frame
        {
            let data = b"123";
            let header = (data.len() as u32, 0x1, 0, 1);
            let buf = {
                let mut buf = Vec::new();
                buf.extend(pack_header(&header).to_vec().into_iter());
                buf.extend(data.to_vec().into_iter());
                buf
            };

            let raw = RawFrame::from_buf(&buf).unwrap();

            assert_eq!(raw.header(), header);
            assert_eq!(raw.payload(), data)
        }
        // Correct frame with trailing data
        {
            let data = b"123";
            let header = (data.len() as u32, 0x1, 0, 1);
            let buf = {
                let mut buf = Vec::new();
                buf.extend(pack_header(&header).to_vec().into_iter());
                buf.extend(data.to_vec().into_iter());
                buf.extend(vec![1, 2, 3, 4, 5].into_iter());
                buf
            };

            assert!(RawFrame::from_buf(&buf).is_none());
        }
        // Missing payload chunk
        {
            let data = b"123";
            let header = (data.len() as u32, 0x1, 0, 1);
            let buf = {
                let mut buf = Vec::new();
                buf.extend(pack_header(&header).to_vec().into_iter());
                buf.extend(data[..2].to_vec().into_iter());
                buf
            };

            assert!(RawFrame::from_buf(&buf).is_none());
        }
        // Missing header chunk
        {
            let header = (0, 0x1, 0, 1);
            let buf = {
                let mut buf = Vec::new();
                buf.extend(pack_header(&header)[..5].to_vec().into_iter());
                buf
            };

            assert!(RawFrame::from_buf(&buf).is_none());
        }
        // Completely empty buffer
        {
            assert!(RawFrame::from_buf(&[]).is_none());
        }
    }

    /// Tests that constructing a `RawFrame` from a `Vec<u8>` by using the `From<Vec<u8>>`
    /// trait implementation works as expected.
    #[test]
    fn test_raw_frame_from_vec_buffer_unchecked() {
        // Correct frame
        {
            let data = b"123";
            let header = (data.len() as u32, 0x1, 0, 1);
            let buf = {
                let mut buf = Vec::new();
                buf.extend(pack_header(&header).to_vec().into_iter());
                buf.extend(data.to_vec().into_iter());
                buf
            };
            let buf_clone = buf.clone();

            let raw = RawFrame::from(buf);

            assert_eq!(raw.header(), header);
            assert_eq!(raw.payload(), data);
            assert_eq!(raw.serialize(), buf_clone);
        }
        // Correct frame with trailing data
        {
            let data = b"123";
            let header = (data.len() as u32, 0x1, 0, 1);
            let buf = {
                let mut buf = Vec::new();
                buf.extend(pack_header(&header).to_vec().into_iter());
                buf.extend(data.to_vec().into_iter());
                buf.extend(b"12345".to_vec().into_iter());
                buf
            };
            let buf_clone = buf.clone();

            let raw = RawFrame::from(buf);

            assert_eq!(raw.header(), header);
            assert_eq!(raw.payload(), b"12312345");
            assert_eq!(raw.serialize(), buf_clone);
        }
        // Missing payload chunk
        {
            let data = b"123";
            let header = (data.len() as u32, 0x1, 0, 1);
            let buf = {
                let mut buf = Vec::new();
                buf.extend(pack_header(&header).to_vec().into_iter());
                buf.extend(data[..2].to_vec().into_iter());
                buf
            };
            let buf_clone = buf.clone();

            let raw = RawFrame::from(buf);

            assert_eq!(raw.header(), header);
            assert_eq!(raw.payload(), b"12");
            assert_eq!(raw.serialize(), buf_clone);
        }
        // Missing header chunk
        {
            let header = (0, 0x1, 0, 1);
            let buf = {
                let mut buf = Vec::new();
                buf.extend(pack_header(&header)[..5].to_vec().into_iter());
                buf
            };
            let buf_clone = buf.clone();

            let raw = RawFrame::from(buf);

            assert_eq!(raw.serialize(), buf_clone);
        }
        // Completely empty buffer
        {
            assert_eq!(RawFrame::from(vec![]).serialize(), &[]);
        }
    }

    /// Tests that the `RawFrame::serialize` method correctly serializes a
    /// `RawFrame`.
    #[test]
    fn test_raw_frame_serialize() {
        let data = b"123";
        let header = (data.len() as u32, 0x1, 0, 1);
        let buf = {
            let mut buf = Vec::new();
            buf.extend(pack_header(&header).to_vec().into_iter());
            buf.extend(data.to_vec().into_iter());
            buf
        };
        let raw = RawFrame::from_buf(&buf).unwrap();

        assert_eq!(raw.serialize(), buf);
    }

    /// Tests that converting a `RawFrame` into a `Vec` works correctly.
    #[test]
    fn test_raw_frame_into_vec() {
        let data = b"123";
        let header = (data.len() as u32, 0x1, 0, 1);
        let buf = {
            let mut buf = Vec::new();
            buf.extend(pack_header(&header).to_vec().into_iter());
            buf.extend(data.to_vec().into_iter());
            buf
        };
        let raw = RawFrame::from_buf(&buf).unwrap();

        let serialized = raw.serialize();
        let vec: Vec<_> = raw.into();
        // The vector is equivalent to the original buffer?
        assert_eq!(vec, buf);
        // The vector and the serialized representation are also equivalent
        assert_eq!(vec, serialized);
    }
}
