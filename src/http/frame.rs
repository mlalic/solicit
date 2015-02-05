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
type FrameHeader = (u32, u8, u8, u32);

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

#[cfg(test)]
mod tests {
    use super::{
        unpack_header,
        pack_header,
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
}
