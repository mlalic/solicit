//! The module contains the implementation of HTTP/2 frames.

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
    let stream_id: u32 = (
        ((header[5] as u32) << 24) |
        ((header[6] as u32) << 16) |
        ((header[7] as u32) <<  8) |
        ((header[8] as u32) <<  0));

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

#[cfg(test)]
mod tests {
    use super::{
        unpack_header,
        pack_header
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
}
