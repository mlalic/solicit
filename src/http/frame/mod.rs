//! The module contains the implementation of HTTP/2 frames.

use std::mem;
use super::StreamId;

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
pub mod settings;

/// Rexports related to the `DATA` frame.
pub use self::data::{DataFlag, DataFrame};
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

/// An enum representing the flags that a `HeadersFrame` can have.
/// The integer representation associated to each variant is that flag's
/// bitmask.
///
/// HTTP/2 spec, section 6.2.
#[derive(Clone)]
#[derive(PartialEq)]
#[derive(Debug)]
#[derive(Copy)]
pub enum HeadersFlag {
    EndStream = 0x1,
    EndHeaders = 0x4,
    Padded = 0x8,
    Priority = 0x20,
}

impl Flag for HeadersFlag {
    #[inline]
    fn bitmask(&self) -> u8 {
        *self as u8
    }
}

/// The struct represents the dependency information that can be attached to
/// a stream and sent within a HEADERS frame (one with the Priority flag set).
#[derive(PartialEq)]
#[derive(Debug)]
#[derive(Clone)]
pub struct StreamDependency {
    /// The ID of the stream that a particular stream depends on
    pub stream_id: StreamId,
    /// The weight for the stream. The value exposed (and set) here is always
    /// in the range [0, 255], instead of [1, 256] \(as defined in section 5.3.2.)
    /// so that the value fits into a `u8`.
    pub weight: u8,
    /// A flag indicating whether the stream dependency is exclusive.
    pub is_exclusive: bool,
}

impl StreamDependency {
    /// Creates a new `StreamDependency` with the given stream ID, weight, and
    /// exclusivity.
    pub fn new(stream_id: StreamId, weight: u8, is_exclusive: bool)
            -> StreamDependency {
        StreamDependency {
            stream_id: stream_id,
            weight: weight,
            is_exclusive: is_exclusive,
        }
    }

    /// Parses the first 5 bytes in the buffer as a `StreamDependency`.
    /// (Each 5-byte sequence is always decodable into a stream dependency
    /// structure).
    ///
    /// # Panics
    ///
    /// If the given buffer has less than 5 elements, the method will panic.
    pub fn parse(buf: &[u8]) -> StreamDependency {
        // The most significant bit of the first byte is the "E" bit indicating
        // whether the dependency is exclusive.
        let is_exclusive = buf[0] & 0x80 != 0;
        let stream_id = {
            // Parse the first 4 bytes into a u32...
            let mut id = unpack_octets_4!(buf, 0, u32);
            // ...clear the first bit since the stream id is only 31 bits.
            id &= !(1 << 31);
            id
        };

        StreamDependency {
            stream_id: stream_id,
            weight: buf[4],
            is_exclusive: is_exclusive,
        }
    }

    /// Serializes the `StreamDependency` into a 5-byte buffer representing the
    /// dependency description, as described in section 6.2. of the HTTP/2
    /// spec:
    ///
    /// ```notest
    ///  0                   1                   2                   3
    ///  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    /// +-+-------------+-----------------------------------------------+
    /// |E|                 Stream Dependency  (31)                     |
    /// +-+-------------+-----------------------------------------------+
    /// |  Weight  (8)  |
    /// +-+-------------+-----------------------------------------------+
    /// ```
    ///
    /// Where "E" is set if the dependency is exclusive.
    pub fn serialize(&self) -> [u8; 5] {
        let e_bit = if self.is_exclusive {
            1 << 7
        } else {
            0
        };
        [
            (((self.stream_id >> 24) & 0x000000FF) as u8) | e_bit,
            (((self.stream_id >> 16) & 0x000000FF) as u8),
            (((self.stream_id >>  8) & 0x000000FF) as u8),
            (((self.stream_id >>  0) & 0x000000FF) as u8),
            self.weight,
        ]
    }
}

/// A struct representing the HEADERS frames of HTTP/2, as defined in the
/// HTTP/2 spec, section 6.2.
#[derive(PartialEq)]
#[derive(Debug)]
#[derive(Clone)]
pub struct HeadersFrame {
    /// The header fragment bytes stored within the frame.
    pub header_fragment: Vec<u8>,
    /// The ID of the stream with which this frame is associated
    pub stream_id: StreamId,
    /// The stream dependency information, if any.
    pub stream_dep: Option<StreamDependency>,
    /// The length of the padding, if any.
    pub padding_len: Option<u8>,
    /// The set of flags for the frame, packed into a single byte.
    flags: u8,
}

impl HeadersFrame {
    /// Creates a new `HeadersFrame` with the given header fragment and stream
    /// ID. No padding, no stream dependency, and no flags are set.
    pub fn new(fragment: Vec<u8>, stream_id: StreamId) -> HeadersFrame {
        HeadersFrame {
            header_fragment: fragment,
            stream_id: stream_id,
            stream_dep: None,
            padding_len: None,
            flags: 0,
        }
    }

    /// Creates a new `HeadersFrame` with the given header fragment, stream ID
    /// and stream dependency information. No padding and no flags are set.
    pub fn with_dependency(
            fragment: Vec<u8>,
            stream_id: StreamId,
            stream_dep: StreamDependency) -> HeadersFrame {
        HeadersFrame {
            header_fragment: fragment,
            stream_id: stream_id,
            stream_dep: Some(stream_dep),
            padding_len: None,
            flags: HeadersFlag::Priority.bitmask(),
        }
    }

    /// Returns whether this frame ends the headers. If not, there MUST be a
    /// number of follow up CONTINUATION frames that send the rest of the
    /// header data.
    pub fn is_headers_end(&self) -> bool {
        self.is_set(HeadersFlag::EndHeaders)
    }

    /// Returns whther this frame ends the stream it is associated with.
    pub fn is_end_of_stream(&self) -> bool {
        self.is_set(HeadersFlag::EndStream)
    }

    /// Sets the padding length for the frame, as well as the corresponding
    /// Padded flag.
    pub fn set_padding(&mut self, padding_len: u8) {
        self.padding_len = Some(padding_len);
        self.set_flag(HeadersFlag::Padded);
    }

    /// Returns the length of the payload of the current frame, including any
    /// possible padding in the number of bytes.
    fn payload_len(&self) -> u32 {
        let padding = if self.is_set(HeadersFlag::Padded) {
            1 + self.padding_len.unwrap_or(0) as u32
        } else {
            0
        };
        let priority = if self.is_set(HeadersFlag::Priority) {
            5
        } else {
            0
        };

        self.header_fragment.len() as u32 + priority + padding
    }
}

impl Frame for HeadersFrame {
    /// The type that represents the flags that the particular `Frame` can take.
    /// This makes sure that only valid `Flag`s are used with each `Frame`.
    type FlagType = HeadersFlag;

    /// Creates a new `HeadersFrame` with the given `RawFrame` (i.e. header and
    /// payload), if possible.
    ///
    /// # Returns
    ///
    /// `None` if a valid `HeadersFrame` cannot be constructed from the given
    /// `RawFrame`. The stream ID *must not* be 0.
    ///
    /// Otherwise, returns a newly constructed `HeadersFrame`.
    fn from_raw(raw_frame: RawFrame) -> Option<HeadersFrame> {
        // Unpack the header
        let (len, frame_type, flags, stream_id) = raw_frame.header();
        // Check that the frame type is correct for this frame implementation
        if frame_type != 0x1 {
            return None;
        }
        // Check that the length given in the header matches the payload
        // length; if not, something went wrong and we do not consider this a
        // valid frame.
        if (len as usize) != raw_frame.payload().len() {
            return None;
        }
        // Check that the HEADERS frame is not associated to stream 0
        if stream_id == 0 {
            return None;
        }

        // First, we get a slice containing the actual payload, depending on if
        // the frame is padded.
        let padded = (flags & HeadersFlag::Padded.bitmask()) != 0;
        let (actual, pad_len) = if padded {
            match parse_padded_payload(&raw_frame.payload()) {
                Some((data, pad_len)) => (data, Some(pad_len)),
                None => return None,
            }
        } else {
            (raw_frame.payload(), None)
        };

        // From the actual payload we extract the stream dependency info, if
        // the appropriate flag is set.
        let priority = (flags & HeadersFlag::Priority.bitmask()) != 0;
        let (data, stream_dep) = if priority {
            (&actual[5..], Some(StreamDependency::parse(&actual[..5])))
        } else {
            (actual, None)
        };

        Some(HeadersFrame {
            header_fragment: data.to_vec(),
            stream_id: stream_id,
            stream_dep: stream_dep,
            padding_len: pad_len,
            flags: flags,
        })
    }

    /// Tests if the given flag is set for the frame.
    fn is_set(&self, flag: HeadersFlag) -> bool {
        (self.flags & flag.bitmask()) != 0
    }

    /// Returns the `StreamId` of the stream to which the frame is associated.
    ///
    /// A `SettingsFrame` always has to be associated to stream `0`.
    fn get_stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Returns a `FrameHeader` based on the current state of the `Frame`.
    fn get_header(&self) -> FrameHeader {
        (self.payload_len(), 0x1, self.flags, self.stream_id)
    }

    /// Sets the given flag for the frame.
    fn set_flag(&mut self, flag: HeadersFlag) {
        self.flags |= flag.bitmask();
    }

    /// Returns a `Vec` with the serialized representation of the frame.
    ///
    /// # Panics
    ///
    /// If the `HeadersFlag::Priority` flag was set, but no stream dependency
    /// information is given (i.e. `stream_dep` is `None`).
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.payload_len() as usize);
        // First the header...
        buf.extend(pack_header(&self.get_header()).to_vec().into_iter());
        // Now the length of the padding, if any.
        let padded = self.is_set(HeadersFlag::Padded);
        if padded {
            buf.push(self.padding_len.unwrap_or(0));
        }
        // The stream dependency fields follow, if the priority flag is set
        if self.is_set(HeadersFlag::Priority) {
            let dep_buf = match self.stream_dep {
                Some(ref dep) => dep.serialize(),
                None => panic!("Priority flag set, but no dependency information given"),
            };
            buf.extend(dep_buf.to_vec().into_iter());
        }
        // Now the actual headers fragment
        buf.extend(self.header_fragment.clone().into_iter());
        // Finally, add the trailing padding, if required
        if padded {
            for _ in 0..self.padding_len.unwrap_or(0) { buf.push(0); }
        }

        buf
    }
}

#[cfg(test)]
mod tests {
    use super::{
        unpack_header,
        pack_header,
        RawFrame,
        FrameHeader,
        HeadersFrame,
        HeadersFlag,
        Frame,
        StreamDependency,
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

    /// Tests that a stream dependency structure can be correctly parsed by the
    /// `StreamDependency::parse` method.
    #[test]
    fn test_parse_stream_dependency() {
        {
            let buf = [0, 0, 0, 1, 5];

            let dep = StreamDependency::parse(&buf);

            assert_eq!(dep.stream_id, 1);
            assert_eq!(dep.weight, 5);
            // This one was not exclusive!
            assert!(!dep.is_exclusive)
        }
        {
            // Most significant bit set => is exclusive!
            let buf = [128, 0, 0, 1, 5];

            let dep = StreamDependency::parse(&buf);

            assert_eq!(dep.stream_id, 1);
            assert_eq!(dep.weight, 5);
            // This one was indeed exclusive!
            assert!(dep.is_exclusive)
        }
        {
            // Most significant bit set => is exclusive!
            let buf = [255, 255, 255, 255, 5];

            let dep = StreamDependency::parse(&buf);

            assert_eq!(dep.stream_id, (1 << 31) - 1);
            assert_eq!(dep.weight, 5);
            // This one was indeed exclusive!
            assert!(dep.is_exclusive);
        }
        {
            let buf = [127, 255, 255, 255, 5];

            let dep = StreamDependency::parse(&buf);

            assert_eq!(dep.stream_id, (1 << 31) - 1);
            assert_eq!(dep.weight, 5);
            // This one was not exclusive!
            assert!(!dep.is_exclusive);
        }
    }

    /// Tests that a stream dependency structure can be correctly serialized by
    /// the `StreamDependency::serialize` method.
    #[test]
    fn test_serialize_stream_dependency() {
        {
            let buf = [0, 0, 0, 1, 5];
            let dep = StreamDependency::new(1, 5, false);

            assert_eq!(buf, dep.serialize());
        }
        {
            // Most significant bit set => is exclusive!
            let buf = [128, 0, 0, 1, 5];
            let dep = StreamDependency::new(1, 5, true);

            assert_eq!(buf, dep.serialize());
        }
        {
            // Most significant bit set => is exclusive!
            let buf = [255, 255, 255, 255, 5];
            let dep = StreamDependency::new((1 << 31) - 1, 5, true);

            assert_eq!(buf, dep.serialize());
        }
        {
            let buf = [127, 255, 255, 255, 5];
            let dep = StreamDependency::new((1 << 31) - 1, 5, false);

            assert_eq!(buf, dep.serialize());
        }
    }

    /// Tests that a simple HEADERS frame is correctly parsed. The frame does
    /// not contain any padding nor priority information.
    #[test]
    fn test_headers_frame_parse_simple() {
        let data = b"123";
        let payload = data.to_vec();
        let header = (payload.len() as u32, 0x1, 0, 1);

        let frame = build_test_frame::<HeadersFrame>(&header, &payload);

        assert_eq!(frame.header_fragment, data);
        assert_eq!(frame.flags, 0);
        assert_eq!(frame.get_stream_id(), 1);
        assert!(frame.stream_dep.is_none());
        assert!(frame.padding_len.is_none());
    }

    /// Tests that a HEADERS frame with padding is correctly parsed.
    #[test]
    fn test_headers_frame_parse_with_padding() {
        let data = b"123";
        let payload = build_padded_frame_payload(data, 6);
        let header = (payload.len() as u32, 0x1, 0x08, 1);

        let frame = build_test_frame::<HeadersFrame>(&header, &payload);

        assert_eq!(frame.header_fragment, data);
        assert_eq!(frame.flags, 8);
        assert_eq!(frame.get_stream_id(), 1);
        assert!(frame.stream_dep.is_none());
        assert_eq!(frame.padding_len.unwrap(), 6);
    }

    /// Tests that a HEADERS frame with the priority flag (and necessary fields)
    /// is correctly parsed.
    #[test]
    fn test_headers_frame_parse_with_priority() {
        let data = b"123";
        let dep = StreamDependency::new(0, 5, true);
        let payload = {
            let mut buf: Vec<u8> = Vec::new();
            buf.extend(dep.serialize().to_vec().into_iter());
            buf.extend(data.to_vec().into_iter());

            buf
        };
        let header = (payload.len() as u32, 0x1, 0x20, 1);

        let frame = build_test_frame::<HeadersFrame>(&header, &payload);

        assert_eq!(frame.header_fragment, data);
        assert_eq!(frame.flags, 0x20);
        assert_eq!(frame.get_stream_id(), 1);
        assert_eq!(frame.stream_dep.unwrap(), dep);
        assert!(frame.padding_len.is_none());
    }

    /// Tests that a HEADERS frame with both padding and priority gets
    /// correctly parsed.
    #[test]
    fn test_headers_frame_parse_padding_and_priority() {
        let data = b"123";
        let dep = StreamDependency::new(0, 5, true);
        let full = {
            let mut buf: Vec<u8> = Vec::new();
            buf.extend(dep.serialize().to_vec().into_iter());
            buf.extend(data.to_vec().into_iter());

            buf
        };
        let payload = build_padded_frame_payload(&full, 4);
        let header = (payload.len() as u32, 0x1, 0x20 | 0x8, 1);

        let frame = build_test_frame::<HeadersFrame>(&header, &payload);

        assert_eq!(frame.header_fragment, data);
        assert_eq!(frame.flags, 0x20 | 0x8);
        assert_eq!(frame.get_stream_id(), 1);
        assert_eq!(frame.stream_dep.unwrap(), dep);
        assert_eq!(frame.padding_len.unwrap(), 4);
    }

    /// Tests that a HEADERS with stream ID 0 is considered invalid.
    #[test]
    fn test_headers_frame_parse_invalid_stream_id() {
        let data = b"123";
        let payload = data.to_vec();
        let header = (payload.len() as u32, 0x1, 0, 0);

        let frame: Option<HeadersFrame> = Frame::from_raw(
            RawFrame::with_payload(header, payload));
        
        assert!(frame.is_none());
    }

    /// Tests that the `HeadersFrame::parse` method considers any frame with
    /// a frame ID other than 1 in the frame header invalid.
    #[test]
    fn test_headers_frame_parse_invalid_type() {
        let data = b"123";
        let payload = data.to_vec();
        let header = (payload.len() as u32, 0x2, 0, 1);

        let frame: Option<HeadersFrame> = Frame::from_raw(
            RawFrame::with_payload(header, payload));
        
        assert!(frame.is_none());
    }

    /// Tests that a simple HEADERS frame (no padding, no priority) gets
    /// correctly serialized.
    #[test]
    fn test_headers_frame_serialize_simple() {
        let data = b"123";
        let payload = data.to_vec();
        let header = (payload.len() as u32, 0x1, 0, 1);
        let expected = {
            let headers = pack_header(&header);
            let mut res: Vec<u8> = Vec::new();
            res.extend(headers.to_vec().into_iter());
            res.extend(payload.into_iter());

            res
        };
        let frame = HeadersFrame::new(data.to_vec(), 1);

        let actual = frame.serialize();

        assert_eq!(expected, actual);
    }

    /// Tests that a HEADERS frame with padding is correctly serialized.
    #[test]
    fn test_headers_frame_serialize_with_padding() {
        let data = b"123";
        let payload = build_padded_frame_payload(data, 6);
        let header = (payload.len() as u32, 0x1, 0x08, 1);
        let expected = {
            let headers = pack_header(&header);
            let mut res: Vec<u8> = Vec::new();
            res.extend(headers.to_vec().into_iter());
            res.extend(payload.into_iter());

            res
        };
        let mut frame = HeadersFrame::new(data.to_vec(), 1);
        frame.set_padding(6);

        let actual = frame.serialize();

        assert_eq!(expected, actual);
    }

    /// Tests that a HEADERS frame with priority gets correctly serialized.
    #[test]
    fn test_headers_frame_serialize_with_priority() {
        let data = b"123";
        let dep = StreamDependency::new(0, 5, true);
        let payload = {
            let mut buf: Vec<u8> = Vec::new();
            buf.extend(dep.serialize().to_vec().into_iter());
            buf.extend(data.to_vec().into_iter());

            buf
        };
        let header = (payload.len() as u32, 0x1, 0x20, 1);
        let expected = {
            let headers = pack_header(&header);
            let mut res: Vec<u8> = Vec::new();
            res.extend(headers.to_vec().into_iter());
            res.extend(payload.into_iter());

            res
        };
        let frame = HeadersFrame::with_dependency(data.to_vec(), 1, dep.clone());

        let actual = frame.serialize();

        assert_eq!(expected, actual);
    }

    /// Tests that a HEADERS frame with both padding and a priority gets correctly
    /// serialized.
    #[test]
    fn test_headers_frame_serialize_padding_and_priority() {
        let data = b"123";
        let dep = StreamDependency::new(0, 5, true);
        let full = {
            let mut buf: Vec<u8> = Vec::new();
            buf.extend(dep.serialize().to_vec().into_iter());
            buf.extend(data.to_vec().into_iter());

            buf
        };
        let payload = build_padded_frame_payload(&full, 4);
        let header = (payload.len() as u32, 0x1, 0x20 | 0x8, 1);
        let expected = {
            let headers = pack_header(&header);
            let mut res: Vec<u8> = Vec::new();
            res.extend(headers.to_vec().into_iter());
            res.extend(payload.into_iter());

            res
        };
        let mut frame = HeadersFrame::with_dependency(data.to_vec(), 1, dep.clone());
        frame.set_padding(4);

        let actual = frame.serialize();

        assert_eq!(expected, actual);
    }

    /// Tests that the `HeadersFrame::is_headers_end` method returns the correct
    /// value depending on the `EndHeaders` flag being set or not.
    #[test]
    fn test_headers_frame_is_headers_end() {
        let mut frame = HeadersFrame::new(vec![], 1);
        assert!(!frame.is_headers_end());

        frame.set_flag(HeadersFlag::EndHeaders);
        assert!(frame.is_headers_end());
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
