//! The module contains the implementation of HTTP/2 frames.

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
macro_rules! unpack_octets_4 {
    ($buf:ident, $offset:expr, $tip:ty) => (
        (($buf[$offset + 0] as $tip) << 24) |
        (($buf[$offset + 1] as $tip) << 16) |
        (($buf[$offset + 2] as $tip) <<  8) |
        (($buf[$offset + 3] as $tip) <<  0)
    );
}

/// An alias for the 9-byte buffer that each HTTP/2 frame header must be stored
/// in.
type FrameHeaderBuffer = [u8; 9];
/// An alias for the 4-tuple representing the components of each HTTP/2 frame
/// header.
pub type FrameHeader = (u32, u8, u8, u32);
/// An alias for the type that represents the ID of an HTTP/2 stream
pub type StreamId = u32;

/// Deconstructs a `FrameHeader` into its corresponding 4 components,
/// represented as a 4-tuple: `(length, frame_type, flags, stream_id)`.
///
/// The frame `type` and `flags` components are returned as their original
/// octet representation, rather than reinterpreted.
fn unpack_header(header: &FrameHeaderBuffer) -> FrameHeader {
    let length: u32 = (
        ((header[0] as u32) << 16) |
        ((header[1] as u32) <<  8) |
        ((header[2] as u32) <<  0));
    let frame_type = header[3];
    let flags = header[4];
    let stream_id: u32 = unpack_octets_4!(header, 5, u32);

    (length, frame_type, flags, stream_id)
}

/// Constructs a buffer of 9 bytes that represents the given `FrameHeader`.
fn pack_header(header: &FrameHeader) -> FrameHeaderBuffer {
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
pub struct RawFrame {
    /// The parsed header of the frame.
    pub header: FrameHeader,
    /// The payload of the frame, as the raw byte sequence, as received on
    /// the wire.
    pub payload: Vec<u8>,
}

impl RawFrame {
    /// Creates a new `RawFrame` with the given `FrameHeader`. The payload is
    /// left empty.
    pub fn new(header: FrameHeader) -> RawFrame {
        RawFrame::with_payload(header, Vec::new())
    }

    /// Creates a new `Frame` with the given header and payload.
    pub fn with_payload(header: FrameHeader, payload: Vec<u8>) -> RawFrame {
        RawFrame {
            header: header,
            payload: payload,
        }
    }
}

/// An enum representing the flags that a `DataFrame` can have.
/// The integer representation associated to each variant is that flag's
/// bitmask.
///
/// HTTP/2 spec, section 6.1.
#[derive(Clone)]
#[derive(PartialEq)]
#[derive(Debug)]
#[derive(Copy)]
enum DataFlag {
    EndStream = 0x1,
    Padded = 0x8,
}

impl Flag for DataFlag {
    #[inline]
    fn bitmask(&self) -> u8 {
        *self as u8
    }
}

/// A struct representing the DATA frames of HTTP/2, as defined in the HTTP/2
/// spec, section 6.1.
#[derive(PartialEq)]
struct DataFrame {
    /// The data found in the frame as an opaque byte sequence. It never
    /// includes padding bytes.
    pub data: Vec<u8>,
    /// Represents the flags currently set on the `DataFrame`, packed into a
    /// single byte.
    flags: u8,
    /// The ID of the stream with which the frame is associated.
    stream_id: StreamId,
    /// The length of the padding applied to the data. Since the spec defines
    /// that the padding length is at most an unsigned integer value, we also
    /// keep a `u8`, instead of a `usize`.
    padding_len: Option<u8>,
}

impl DataFrame {
    /// Creates a new empty `DataFrame`, associated to the stream with the
    /// given ID.
    pub fn new(stream_id: StreamId) -> DataFrame {
        DataFrame {
            stream_id: stream_id,
            // All flags unset by default
            flags: 0,
            // No data stored in the frame yet
            data: Vec::new(),
            // No padding
            padding_len: None,
        }
    }

    /// Returns `true` if the DATA frame is padded, otherwise false.
    pub fn is_padded(&self) -> bool {
        self.is_set(DataFlag::Padded)
    }

    /// Sets the number of bytes that should be used as padding for this
    /// frame.
    pub fn set_padding(&mut self, pad_len: u8) {
        self.set_flag(DataFlag::Padded);
        self.padding_len = Some(pad_len);
    }

    /// Returns the total length of the payload, taking into account possible
    /// padding.
    fn payload_len(&self) -> u32 {
        if self.is_padded() {
            1 + (self.data.len() as u32) + (self.padding_len.unwrap_or(0) as u32)
        } else {
            // Downcasting here is all right, because the HTTP/2 frames cannot
            // have a length larger than a 32 bit unsigned integer.
            self.data.len() as u32
        }
    }

    /// Parses the given slice as a DATA frame's payload. Depending on the
    /// `padded` flag, it will treat the given bytes as a data frame with
    /// padding or without.
    ///
    /// # Returns
    ///
    /// A tuple wrapped in the `Some` variant, representing the true data and
    /// the original padding length.
    /// If there was no padding, returns `None` for the second tuple member.
    ///
    /// If the payload was invalid for a DATA frame, returns `None`
    fn parse_payload(payload: &[u8], padded: bool)
            -> Option<(Vec<u8>, Option<u8>)> {
        let (start, end, pad_len) = if padded {
            if payload.len() == 0 {
                // We make sure not to index the payload before we're sure how
                // large the buffer is.
                // If this is the case, the frame is invalid as no padding
                // length can be extracted, even though the frame should be
                // padded.
                return None;
            }
            let pad_len = payload[0];
            if (pad_len as usize) >= payload.len() {
                // This is invalid: the padding length MUST be less than the
                // total frame size.
                return None;
            }

            (1, payload.len() - pad_len as usize, Some(pad_len))
        } else {
            (0, payload.len(), None)
        };

        Some((payload[start..end].to_vec(), pad_len))
    }
}

impl Frame for DataFrame {
    type FlagType = DataFlag;

    /// Creates a new `DataFrame` from the given `RawFrame` (i.e. header and
    /// payload), if possible.  Returns `None` if a valid `DataFrame` cannot be
    /// constructed from the given `RawFrame`.
    fn from_raw(raw_frame: RawFrame) -> Option<DataFrame> {
        // Unpack the header
        let (len, frame_type, flags, stream_id) = raw_frame.header;
        // Check that the frame type is correct for this frame implementation
        if frame_type != 0x0 {
            return None;
        }
        // Check that the length given in the header matches the payload
        // length; if not, something went wrong and we do not consider this a
        // valid frame.
        if (len as usize) != raw_frame.payload.len() {
            return None;
        }
        // No validation is required for the flags, since according to the spec,
        // unknown flags MUST be ignored.
        // Everything has been validated so far: try to extract the data from
        // the payload.
        let padded = (flags & DataFlag::Padded.bitmask()) != 0;
        match DataFrame::parse_payload(&raw_frame.payload[], padded) {
            Some((data, Some(padding_len))) => {
                // The data got extracted (from a padded frame)
                Some(DataFrame {
                    stream_id: stream_id,
                    flags: flags,
                    data: data,
                    padding_len: Some(padding_len),
                })
            },
            Some((data, None)) => {
                // The data got extracted (from a no-padding frame)
                Some(DataFrame {
                    stream_id: stream_id,
                    flags: flags,
                    data: data,
                    padding_len: None,
                })
            },
            None => None,
        }
    }

    /// Tests if the given flag is set for the frame.
    fn is_set(&self, flag: DataFlag) -> bool {
        (self.flags & flag.bitmask()) != 0
    }

    /// Sets the given flag for the frame.
    fn set_flag(&mut self, flag: DataFlag) {
        self.flags |= flag.bitmask();
    }

    /// Returns the `StreamId` of the stream to which the frame is associated.
    fn get_stream_id(&self) -> StreamId {
        self.stream_id
    }

    /// Returns a `FrameHeader` based on the current state of the frame.
    fn get_header(&self) -> FrameHeader {
        (self.payload_len(), 0x0, self.flags, self.stream_id)
    }

    /// Returns a `Vec` with the serialized representation of the frame.
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(9 + self.payload_len() as usize);
        // First the header...
        buf.push_all(&pack_header(&self.get_header()));
        // ...now the data, depending on whether it's wrapped or not
        if self.is_padded() {
            let pad_len = self.padding_len.unwrap_or(0);
            buf.push(pad_len);
            buf.push_all(&self.data[]);
            // The padding bytes MUST be 0
            for _ in 0..pad_len { buf.push(0); }
        } else {
            buf.push_all(&self.data[]);
        }

        buf
    }
}

/// An enum that lists all valid settings that can be sent in a SETTINGS
/// frame.
///
/// Each setting has a value that is a 32 bit unsigned integer (6.5.1.).
#[derive(Clone)]
#[derive(PartialEq)]
#[derive(Debug)]
#[derive(Copy)]
pub enum HttpSetting {
    HeaderTableSize(u32),
    EnablePush(u32),
    MaxConcurrentStreams(u32),
    InitialWindowSize(u32),
    MaxFrameSize(u32),
    MaxHeaderListSize(u32),
}

impl HttpSetting {
    /// Creates a new `HttpSetting` with the correct variant corresponding to
    /// the given setting id, based on the settings IDs defined in section
    /// 6.5.2.
    pub fn from_id(id: u16, val: u32) -> Option<HttpSetting> {
        match id {
            1 => Some(HttpSetting::HeaderTableSize(val)),
            2 => Some(HttpSetting::EnablePush(val)),
            3 => Some(HttpSetting::MaxConcurrentStreams(val)),
            4 => Some(HttpSetting::InitialWindowSize(val)),
            5 => Some(HttpSetting::MaxFrameSize(val)),
            6 => Some(HttpSetting::MaxHeaderListSize(val)),
            _ => None,
        }
    }

    /// Creates a new `HttpSetting` by parsing the given buffer of 6 bytes,
    /// which contains the raw byte representation of the setting, according
    /// to the "SETTINGS format" defined in section 6.5.1.
    ///
    /// The `raw_setting` parameter should have length at least 6 bytes, since
    /// the length of the raw setting is exactly 6 bytes.
    ///
    /// # Panics
    ///
    /// If given a buffer shorter than 6 bytes, the function will panic.
    fn parse_setting(raw_setting: &[u8]) -> Option<HttpSetting> {
        let id: u16 = ((raw_setting[0] as u16) << 8) | (raw_setting[1] as u16);
        let val: u32 = unpack_octets_4!(raw_setting, 2, u32);

        HttpSetting::from_id(id, val)
    }

    /// Returns the setting ID as an unsigned 16 bit integer, as defined in
    /// section 6.5.2.
    pub fn get_id(&self) -> u16 {
        match self {
            &HttpSetting::HeaderTableSize(_) => 1,
            &HttpSetting::EnablePush(_) => 2,
            &HttpSetting::MaxConcurrentStreams(_) => 3,
            &HttpSetting::InitialWindowSize(_) => 4,
            &HttpSetting::MaxFrameSize(_) => 5,
            &HttpSetting::MaxHeaderListSize(_) => 6,
        }
    }

    /// Gets the setting value by unpacking it from the wrapped `u32`.
    pub fn get_val(&self) -> u32 {
        match self {
            &HttpSetting::HeaderTableSize(ref val) => val.clone(),
            &HttpSetting::EnablePush(ref val) => val.clone(),
            &HttpSetting::MaxConcurrentStreams(ref val) => val.clone(),
            &HttpSetting::InitialWindowSize(ref val) => val.clone(),
            &HttpSetting::MaxFrameSize(ref val) => val.clone(),
            &HttpSetting::MaxHeaderListSize(ref val) => val.clone(),
        }
    }

    /// Serializes a setting into its "on-the-wire" representation of 6 octets,
    /// according to section 6.5.1.
    fn serialize(&self) -> [u8; 6] {
        let (id, val) = (self.get_id(), self.get_val());
        [
            ((id >> 8) & 0x00FF) as u8,
            ((id >> 0) & 0x00FF) as u8,
            (((val >> 24) & 0x000000FF) as u8),
            (((val >> 16) & 0x000000FF) as u8),
            (((val >>  8) & 0x000000FF) as u8),
            (((val >>  0) & 0x000000FF) as u8),
        ]
    }
}

/// An enum representing the flags that a `SettingsFrame` can have.
/// The integer representation associated to each variant is that flag's
/// bitmask.
///
/// HTTP/2 spec, section 6.5.
#[derive(Clone)]
#[derive(PartialEq)]
#[derive(Debug)]
#[derive(Copy)]
pub enum SettingsFlag {
    Ack = 0x1,
}

impl Flag for SettingsFlag {
    #[inline]
    fn bitmask(&self) -> u8 {
        *self as u8
    }
}

/// A struct representing the SETTINGS frames of HTTP/2, as defined in the
/// HTTP/2 spec, section 6.5.
///
/// The struct does not try to prevent the client from creating malformed
/// SETTINGS frames, such as ones that have the ACK flag set along with some
/// settings values. The users are responsible to follow the prescribed rules
/// before sending the frame to the peer.
///
/// On parsing received frames, it treats the following as errors:
///
/// - ACK flag and a number of settings both set
/// - Payload length not a multiple of 6
/// - Stream ID not zero (SETTINGS frames MUST be associated to stream 0)
///
/// What is *not* treated as an error (for now) are settings values out of
/// allowed bounds such as a EnablePush being set to something other than 0 or
/// 1.
pub struct SettingsFrame {
    /// Contains all the settings that are currently set in the frame. It is
    /// safe to access this field (to read, add, or remove settings), even
    /// though a helper method `add_setting` exists.
    pub settings: Vec<HttpSetting>,
    /// Represents the flags currently set on the `SettingsFrame`, packed into
    /// a single byte.
    flags: u8,
}

impl SettingsFrame {
    /// Creates a new `SettingsFrame`
    pub fn new() -> SettingsFrame {
        SettingsFrame {
            settings: Vec::new(),
            // By default, no flags are set
            flags: 0,
        }
    }

    /// A convenience constructor that returns a `SettingsFrame` with the ACK
    /// flag already set and no settings.
    pub fn new_ack() -> SettingsFrame {
        SettingsFrame {
            settings: Vec::new(),
            flags: SettingsFlag::Ack.bitmask(),
        }
    }

    /// Adds the given setting to the frame.
    pub fn add_setting(&mut self, setting: HttpSetting) {
        self.settings.push(setting);
    }

    /// Sets the ACK flag for the frame. This method is just a convenience
    /// method for calling `frame.set_flag(SettingsFlag::Ack)`.
    pub fn set_ack(&mut self) {
        self.set_flag(SettingsFlag::Ack)
    }

    /// Checks whether the `SettingsFrame` has an ACK attached to it.
    pub fn is_ack(&self) -> bool {
        self.is_set(SettingsFlag::Ack)
    }

    /// Returns the total length of the payload in bytes.
    fn payload_len(&self) -> u32 {
        // Each setting is represented with 6 bytes =>
        6 * self.settings.len() as u32
    }

    /// Parses the given buffer, considering it a representation of a settings
    /// frame payload.
    ///
    /// # Returns
    ///
    /// A `Vec` of settings that are set by the given payload.
    ///
    /// Any unknown setting is ignored, as per the HTTP/2 spec requirement.
    ///
    /// If the frame is invalid (i.e. the length of the payload is not a
    /// multiple of 6) it returns `None`.
    fn parse_payload(payload: &[u8]) -> Option<Vec<HttpSetting>> {
        if payload.len() % 6 != 0 {
            return None;
        }

        // Iterates through chunks of the raw payload of size 6 bytes and
        // parses each of them into an `HttpSetting`
        Some(payload.chunks(6).filter_map(|chunk| {
            HttpSetting::parse_setting(chunk)
        }).collect())
    }
}

impl Frame for SettingsFrame {
    /// The type that represents the flags that the particular `Frame` can take.
    /// This makes sure that only valid `Flag`s are used with each `Frame`.
    type FlagType = SettingsFlag;

    /// Creates a new `SettingsFrame` with the given `RawFrame` (i.e. header and
    /// payload), if possible.
    ///
    /// # Returns
    ///
    /// `None` if a valid `SettingsFrame` cannot be constructed from the given
    /// `RawFrame`. The stream ID *must* be 0 in order for the frame to be
    /// valid. If the `ACK` flag is set, there MUST not be a payload. The
    /// total payload length must be multiple of 6.
    ///
    /// Otherwise, returns a newly constructed `SettingsFrame`.
    fn from_raw(raw_frame: RawFrame) -> Option<SettingsFrame> {
        // Unpack the header
        let (len, frame_type, flags, stream_id) = raw_frame.header;
        // Check that the frame type is correct for this frame implementation
        if frame_type != 0x4 {
            return None;
        }
        // Check that the length given in the header matches the payload
        // length; if not, something went wrong and we do not consider this a
        // valid frame.
        if (len as usize) != raw_frame.payload.len() {
            return None;
        }
        // Check that the SETTINGS frame is associated to stream 0
        if stream_id != 0 {
            return None;
        }
        if (flags & SettingsFlag::Ack.bitmask()) != 0 {
            if len != 0 {
                // The SETTINGS flag MUST not have a payload if Ack is set
                return None;
            } else {
                // Ack is set and there's no payload => just an Ack frame
                return Some(SettingsFrame {
                    settings: Vec::new(),
                    flags: flags,
                });
            }
        }

        match SettingsFrame::parse_payload(&raw_frame.payload[]) {
            Some(settings) => {
                Some(SettingsFrame {
                    settings: settings,
                    flags: flags,
                })
            },
            None => None,
        }
    }

    /// Tests if the given flag is set for the frame.
    fn is_set(&self, flag: SettingsFlag) -> bool {
        (self.flags & flag.bitmask()) != 0
    }

    /// Returns the `StreamId` of the stream to which the frame is associated.
    ///
    /// A `SettingsFrame` always has to be associated to stream `0`.
    fn get_stream_id(&self) -> StreamId {
        0
    }

    /// Returns a `FrameHeader` based on the current state of the `Frame`.
    fn get_header(&self) -> FrameHeader {
        (self.payload_len(), 0x4, self.flags, 0)
    }

    /// Sets the given flag for the frame.
    fn set_flag(&mut self, flag: SettingsFlag) {
        self.flags |= flag.bitmask();
    }

    /// Returns a `Vec` with the serialized representation of the frame.
    fn serialize(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.payload_len() as usize);
        // First the header...
        buf.push_all(&pack_header(&self.get_header()));
        // ...now the settings
        for setting in self.settings.iter() {
            buf.push_all(&setting.serialize());
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
        DataFrame,
        SettingsFrame,
        DataFlag,
        Frame,
        HttpSetting,
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
    fn build_test_frame<F: Frame>(header: &FrameHeader, payload: &[u8]) -> F {
        let raw = RawFrame::with_payload(header.clone(), payload.to_vec());
        Frame::from_raw(raw).unwrap()
    }

    /// Builds a `Vec` containing the given data as a padded HTTP/2 frame.
    ///
    /// It first places the length of the padding, followed by the data,
    /// followed by `pad_len` zero bytes.
    fn build_padded_frame_payload(data: &[u8], pad_len: u8) -> Vec<u8> {
        let sz = 1 + data.len() + pad_len as usize;
        let mut payload: Vec<u8> = Vec::with_capacity(sz);
        payload.push(pad_len);
        payload.push_all(data);
        for _ in 0..pad_len { payload.push(0); }

        payload
    }

    /// Tests that the `DataFrame` struct correctly interprets a DATA frame
    /// with no padding set.
    #[test]
    fn test_data_frame_parse_no_padding() {
        let data = b"asdf";
        let payload = data.to_vec();
        // A header with the flag indicating no padding
        let header = (payload.len() as u32, 0u8, 0u8, 1u32);

        let frame = build_test_frame::<DataFrame>(&header, &payload[]);

        // The frame correctly returns the data?
        assert_eq!(&frame.data[], data);
        // ...and the headers?
        assert_eq!(frame.get_header(), header);
    }

    /// Tests that the `DataFrame` struct correctly interprets a DATA frame
    /// with a number of padding bytes set.
    #[test]
    fn test_data_frame_padded() {
        let data = b"asdf";
        let payload = build_padded_frame_payload(data, 5);
        // A header with the flag indicating padding
        let header = (payload.len() as u32, 0u8, 8u8, 1u32);

        let frame = build_test_frame::<DataFrame>(&header, &payload[]);

        // The frame correctly returns the data?
        assert_eq!(&frame.data[], data);
        // ...and the headers?
        assert_eq!(frame.get_header(), header);
    }

    /// Tests that the `DataFrame` struct correctly handles the case where the
    /// padding is invalid: the size of the padding given is greater than or
    /// equal to the total size of the frame.
    #[test]
    fn test_data_frame_padding_invalid() {
        let payload = [5, b'a', b's', b'd', b'f'];
        // A header with the flag indicating padding
        let header = (payload.len() as u32, 0u8, 8u8, 1u32);

        let frame: Option<DataFrame> = Frame::from_raw(
            RawFrame::with_payload(header.clone(), payload.to_vec()));

        // The frame was not even created since the raw bytes are invalid
        assert!(frame.is_none())
    }

    /// Tests that the `DataFrame` struct correctly interprets a DATA frame
    /// with no padding and no data.
    #[test]
    fn test_data_frame_no_padding_empty() {
        let payload = [];
        let header = (payload.len() as u32, 0u8, 0u8, 1u32);

        let frame = build_test_frame::<DataFrame>(&header, &payload[]);

        // The frame correctly returns the data -- i.e. an empty array?
        assert_eq!(&frame.data[], []);
        // ...and the headers?
        assert_eq!(frame.get_header(), header);
    }

    /// Tests that the `DataFrame` struct correctly interprets a DATA frame
    /// with padding, but an empty payload.
    #[test]
    fn test_data_frame_padding_empty_payload() {
        let payload = [];
        let header = (payload.len() as u32, 0u8, 8u8, 1u32);

        let frame: Option<DataFrame> = Frame::from_raw(
            RawFrame::with_payload(header.clone(), payload.to_vec()));

        // In this case, we cannot receive a frame, since the payload did not
        // contain even the first byte, necessary to find the padding length.
        assert!(frame.is_none());
    }

    /// Tests that the `DataFrame` struct correctly interprets a DATA frame
    /// with padding of size 0.
    #[test]
    fn test_data_frame_null_padding() {
        let data = b"test string";
        let payload = build_padded_frame_payload(data, 0);
        // A header with the flag indicating padding
        let header = (payload.len() as u32, 0u8, 8u8, 1u32);

        let frame = build_test_frame::<DataFrame>(&header, &payload[]);

        // The frame correctly returns the data?
        assert_eq!(&frame.data[], data);
        // ...and the headers?
        assert_eq!(frame.get_header(), header);
    }

    /// Tests that the `DataFrame` struct correctly handles the situation
    /// where the header does not contain a frame type corresponding to the
    /// DATA frame type.
    #[test]
    fn test_data_frame_invalid_type() {
        let data = b"dummy";
        let payload = build_padded_frame_payload(data, 0);
        // The header has an invalid type (0x1 instead of 0x0).
        let header = (payload.len() as u32, 1u8, 8u8, 1u32);

        let frame: Option<DataFrame> = Frame::from_raw(
            RawFrame::with_payload(header.clone(), payload.to_vec()));

        assert!(frame.is_none());
    }

    /// Tests that `DataFrame`s get correctly serialized when created with no
    /// padding and with no data.
    #[test]
    fn test_data_frame_serialize_no_padding_empty() {
        let frame = DataFrame::new(1);
        let expected = {
            let headers = pack_header(&(0, 0, 0, 1));
            let mut res: Vec<u8> = Vec::new();
            res.push_all(&headers[]);

            res
        };

        let serialized = frame.serialize();

        assert_eq!(serialized, expected);
    }

    /// Tests that `DataFrame`s get correctly serialized when created with no
    /// padding and with some amount of data.
    #[test]
    fn test_data_frame_serialize_no_padding() {
        let mut frame = DataFrame::new(1);
        let data = vec![1, 2, 3, 4, 5, 100];
        frame.data = data.clone();
        let expected = {
            let headers = pack_header(&(6, 0, 0, 1));
            let mut res: Vec<u8> = Vec::new();
            res.push_all(&headers[]);
            res.push_all(&data[]);

            res
        };

        let serialized = frame.serialize();

        assert_eq!(serialized, expected);
    }

    /// Tests that `DataFrame`s get correctly serialized when created with
    /// some amount of padding and some data.
    #[test]
    fn test_data_frame_serialize_padding() {
        let mut frame = DataFrame::new(1);
        let data = vec![1, 2, 3, 4, 5, 100];
        frame.data = data.clone();
        frame.set_padding(5);
        let expected = {
            let headers = pack_header(&(6 + 1 + 5, 0, 8, 1));
            let mut res: Vec<u8> = Vec::new();
            // Headers
            res.push_all(&headers[]);
            // Padding len
            res.push(5);
            // Data
            res.push_all(&data[]);
            // Actual padding
            for _ in 0..5 { res.push(0); }

            res
        };

        let serialized = frame.serialize();

        assert_eq!(serialized, expected);
    }

    /// Tests that `DataFrame`s get correctly serialized when created with
    /// 0 padding. This is a distinct case from having *no padding*.
    #[test]
    fn test_data_frame_serialize_null_padding() {
        let mut frame = DataFrame::new(1);
        let data = vec![1, 2, 3, 4, 5, 100];
        frame.data = data.clone();
        frame.set_flag(DataFlag::Padded);
        let expected = {
            let headers = pack_header(&(6 + 1, 0, 8, 1));
            let mut res: Vec<u8> = Vec::new();
            // Headers
            res.push_all(&headers[]);
            // Padding len
            res.push(0);
            // Data
            res.push_all(&data[]);

            res
        };

        let serialized = frame.serialize();

        assert_eq!(serialized, expected);
    }

    /// Tests that the `HttpSetting::parse_setting` method correctly creates
    /// settings from raw bytes.
    #[test]
    fn test_setting_deserialize() {
        {
            let buf = [0, 1, 0, 0, 1, 0];

            let setting = HttpSetting::parse_setting(&buf).unwrap();

            assert_eq!(setting, HttpSetting::HeaderTableSize(1 << 8));
        }
        {
            let buf = [0, 2, 0, 0, 0, 1];

            let setting = HttpSetting::parse_setting(&buf).unwrap();

            assert_eq!(setting, HttpSetting::EnablePush(1));
        }
        {
            let buf = [0, 3, 0, 0, 0, 0];

            let setting = HttpSetting::parse_setting(&buf).unwrap();

            assert_eq!(setting, HttpSetting::MaxConcurrentStreams(0));
        }
        {
            let buf = [0, 4, 0, 0, 0, 1];

            let setting = HttpSetting::parse_setting(&buf).unwrap();

            assert_eq!(setting, HttpSetting::InitialWindowSize(1));
        }
        {
            let buf = [0, 5, 0, 0, 0, 255];

            let setting = HttpSetting::parse_setting(&buf).unwrap();

            assert_eq!(setting, HttpSetting::MaxFrameSize((1 << 8) - 1));
        }
        {
            let buf = [0, 6, 0, 0, 0, 255];

            let setting = HttpSetting::parse_setting(&buf).unwrap();

            assert_eq!(setting, HttpSetting::MaxHeaderListSize((1 << 8) - 1));
        }
        {
            let buf = [0, 7, 0, 0, 0, 255];

            let setting = HttpSetting::parse_setting(&buf);

            assert!(setting.is_none());
        }
        {
            let buf = [0, 0, 0, 0, 0, 255];

            let setting = HttpSetting::parse_setting(&buf);

            assert!(setting.is_none());
        }
    }

    /// Tests that the `HttpSetting::serialize` method correctly creates
    /// a 6 byte buffer based on the given setting.
    #[test]
    fn test_setting_serialize() {
        {
            let buf = [0, 1, 0, 0, 1, 0];

            let setting = HttpSetting::HeaderTableSize(1 << 8);

            assert_eq!(buf, setting.serialize());
        }
        {
            let buf = [0, 2, 0, 0, 0, 1];

            let setting = HttpSetting::EnablePush(1);

            assert_eq!(buf, setting.serialize());
        }
        {
            let buf = [0, 3, 0, 0, 0, 0];

            let setting = HttpSetting::MaxConcurrentStreams(0);

            assert_eq!(buf, setting.serialize());
        }
        {
            let buf = [0, 4, 0, 0, 0, 1];

            let setting = HttpSetting::InitialWindowSize(1);

            assert_eq!(buf, setting.serialize());
        }
        {
            let buf = [0, 5, 0, 0, 0, 255];

            let setting = HttpSetting::MaxFrameSize((1 << 8) - 1);

            assert_eq!(buf, setting.serialize());
        }
        {
            let buf = [0, 6, 0, 0, 0, 255];

            let setting = HttpSetting::MaxHeaderListSize((1 << 8) - 1);

            assert_eq!(buf, setting.serialize());
        }
    }

    /// Tests that a `SettingsFrame` correctly handles a SETTINGS frame with
    /// no ACK flag and only a single setting.
    #[test]
    fn test_settings_frame_parse_no_ack_one_setting() {
        let payload = [0, 1, 0, 0, 0, 1];
        // A header with the flag indicating no padding
        let header = (payload.len() as u32, 4, 0, 0);

        let frame = build_test_frame::<SettingsFrame>(&header, &payload[]);

        // The frame correctly interprets the settings?
        assert_eq!(frame.settings, vec![HttpSetting::HeaderTableSize(1)]);
        // ...and the headers?
        assert_eq!(frame.get_header(), header);
    }

    /// Tests that a `SettingsFrame` correctly handles a SETTINGS frame with
    /// no ACK flag and multiple settings within the frame.
    #[test]
    fn test_settings_frame_parse_no_ack_multiple_settings() {
        let settings = vec![
            HttpSetting::HeaderTableSize(1),
            HttpSetting::MaxHeaderListSize(5),
            HttpSetting::EnablePush(0),
        ];
        let payload = {
            let mut res: Vec<u8> = Vec::new();
            for s in settings.iter().map(|s| s.serialize()) { res.push_all(&s); }

            res
        };
        let header = (payload.len() as u32, 4, 0, 0);

        let frame = build_test_frame::<SettingsFrame>(&header, &payload[]);

        // The frame correctly interprets the settings?
        assert_eq!(frame.settings, settings);
        // ...and the headers?
        assert_eq!(frame.get_header(), header);
        assert!(!frame.is_ack());
    }

    /// Tests that a `SettingsFrame` correctly handles a SETTINGS frame with
    /// no ACK and multiple *duplicate* settings within the frame.
    #[test]
    fn test_settings_frame_parse_no_ack_duplicate_settings() {
        let settings = vec![
            HttpSetting::HeaderTableSize(1),
            HttpSetting::MaxHeaderListSize(5),
            HttpSetting::EnablePush(0),
            HttpSetting::HeaderTableSize(2),
        ];
        let payload = {
            let mut res: Vec<u8> = Vec::new();
            for s in settings.iter().map(|s| s.serialize()) { res.push_all(&s); }

            res
        };
        let header = (payload.len() as u32, 4, 0, 0);

        let frame = build_test_frame::<SettingsFrame>(&header, &payload[]);

        // All the settings are returned, even the duplicates
        assert_eq!(frame.settings, settings);
        // ...and the headers?
        assert_eq!(frame.get_header(), header);
        assert!(!frame.is_ack());
    }

    /// Tests that a `SettingsFrame` correctly handles a SETTING frame with no
    /// ACK and an unknown setting within the frame. The unknown setting is
    /// simply ignored.
    #[test]
    fn test_settings_frame_parse_no_ack_unknown_setting() {
        let settings = vec![
            HttpSetting::HeaderTableSize(1),
            HttpSetting::MaxHeaderListSize(5),
        ];
        let payload = {
            let mut res: Vec<u8> = Vec::new();
            for s in settings.iter().map(|s| s.serialize()) { res.push_all(&s); }
            res.push_all(&[0, 10, 0, 0, 0, 0]);
            for s in settings.iter().map(|s| s.serialize()) { res.push_all(&s); }

            res
        };
        let header = (payload.len() as u32, 4, 0, 0);

        let frame = build_test_frame::<SettingsFrame>(&header, &payload[]);

        // All the settings are returned twice, but the unkown isn't found in
        // the returned Vec. For now, we ignore the unknown setting fully, not
        // exposing it in any way to any other higher-level clients.
        assert_eq!(frame.settings.len(), 4);
        assert_eq!(&frame.settings[0..2], &settings[]);
        assert_eq!(&frame.settings[2..], &settings[]);
        assert!(!frame.is_ack());
    }

    /// Tests that a `SettingsFrame` correctly handles a SETTINGS frame with an
    /// ACK flag and no settings.
    #[test]
    fn test_settings_frame_parse_ack_no_settings() {
        let payload = [];
        let header = (payload.len() as u32, 4, 1, 0);

        let frame = build_test_frame::<SettingsFrame>(&header, &payload[]);

        // No settings there?
        assert_eq!(frame.settings, vec![]);
        // ...and the headers?
        assert_eq!(frame.get_header(), header);
        // ...and the frame indicates it's an ACK
        assert!(frame.is_ack());
    }

    /// Tests that a `SettingsFrame` correctly handles a SETTINGS frame with an
    /// ACK flag, along with settings. In this case, the frame needs to be
    /// considered invalid.
    #[test]
    fn test_settings_frame_parse_ack_with_settings() {
        let settings = [
            HttpSetting::EnablePush(0),
        ];
        let payload = {
            let mut res: Vec<u8> = Vec::new();
            for s in settings.iter().map(|s| s.serialize()) { res.push_all(&s); }

            res
        };
        let header = (payload.len() as u32, 4, 1, 0);

        let frame: Option<SettingsFrame> = Frame::from_raw(
            RawFrame::with_payload(header, payload));

        assert!(frame.is_none());
    }

    /// Tests that a `SettingsFrame` correctly handles a SETTINGS frame which
    /// was not associated to stream 0 by returning an error.
    #[test]
    fn test_settings_frame_parse_not_stream_zero() {
        let payload = vec![];
        // Header indicates that it is associated to stream 1
        let header = (payload.len() as u32, 4, 1, 1);

        let frame: Option<SettingsFrame> = Frame::from_raw(
            RawFrame::with_payload(header, payload));

        assert!(frame.is_none());
    }

    /// Tests that a `SettingsFrame` correctly handles a SETTINGS frame which
    /// does not have a payload with a number of bytes that's a multiple of 6.
    #[test]
    fn test_settings_frame_parse_not_multiple_of_six() {
        let payload = vec![1, 2, 3];

        let header = (payload.len() as u32, 4, 0, 0);

        let frame: Option<SettingsFrame> = Frame::from_raw(
            RawFrame::with_payload(header, payload));

        assert!(frame.is_none());
    }

    /// Tests that a `SettingsFrame` gets correctly serialized when it contains
    /// only settings and no ACK.
    #[test]
    fn test_settings_frame_serialize_no_ack_settings() {
        let mut frame = SettingsFrame::new();
        frame.add_setting(HttpSetting::EnablePush(0));
        let expected = {
            let mut res: Vec<u8> = Vec::new();
            res.push_all(&pack_header(&(6, 4, 0, 0)));
            res.push_all(&HttpSetting::EnablePush(0).serialize());

            res
        };

        let serialized = frame.serialize();

        assert_eq!(serialized, expected);
    }

    /// Tests that a `SettingsFrame` gets correctly serialized when it contains
    /// multiple settings and no ACK.
    #[test]
    fn test_settings_frame_serialize_no_ack_multiple_settings() {
        let mut frame = SettingsFrame::new();
        frame.add_setting(HttpSetting::EnablePush(0));
        frame.add_setting(HttpSetting::MaxHeaderListSize(0));
        let expected = {
            let mut res: Vec<u8> = Vec::new();
            res.push_all(&pack_header(&(6 * 2, 4, 0, 0)));
            res.push_all(&HttpSetting::EnablePush(0).serialize());
            res.push_all(&HttpSetting::MaxHeaderListSize(0).serialize());

            res
        };

        let serialized = frame.serialize();

        assert_eq!(serialized, expected);
    }

    /// Tests that a `SettingsFrame` gets correctly serialized when it contains
    /// multiple settings and no ACK.
    #[test]
    fn test_settings_frame_serialize_ack() {
        let frame = SettingsFrame::new_ack();
        let expected = pack_header(&(0, 4, 1, 0)).to_vec();

        let serialized = frame.serialize();

        assert_eq!(serialized, expected);
    }
}
