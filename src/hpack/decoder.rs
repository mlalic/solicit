/// Exposes the struct `Decoder` that allows for HPACK-encoded header blocks to
/// be decoded into a header list.
///
/// The decoder only follows HPACK rules, without performing any additional
/// (semantic) checks on the header name/value pairs, i.e. it considers the
/// headers as opaque octets.

use std::fmt;
use std::collections::RingBuf;

/// Decodes an integer encoded with a given prefix size (in bits).
/// Assumes that the buffer `buf` contains the integer to be decoded,
/// with the first byte representing the octet that contains the
/// prefix.
///
/// Returns a tuple representing the decoded integer and the number
/// of bytes from the buffer that were used.
fn decode_integer(buf: &[u8], prefix_size: u8) -> (usize, usize) {
    assert!(prefix_size >= 1 && prefix_size <= 8);
    assert!(buf.len() >= 1);
    let mask = (1u8 << prefix_size) - 1;
    let mut value: usize = (buf[0] & mask) as usize;
    if value < (mask as usize) {
        return (value, 1);
    }

    // Already one byte used (the prefix)
    let mut total = 1;
    let mut m = 0;
    for &b in buf[1..].iter() {
        total += 1;
        value += ((b & 127) as usize) * (1us << m);
        m += 7;
        if b & 128 != 128 {
            break;
        }
    }

    // TODO Error situation -- what happens if we reach here w/o having
    //      `b` byte-sized...
    (value, total)
}

/// Encode an integer to the representation defined by HPACK.
///
/// Returns a newly allocated `Vec` containing the encoded bytes.
/// Only `prefix_size` lowest-order bits of the first byte in the
/// array are guaranteed to be used.
fn encode_integer(mut value: usize, prefix_size: u8) -> Vec<u8> {
    let mask: usize = ((1u8 << prefix_size) - 1) as usize;
    if value < mask {
        // Right now, the caller would need to be the one to combine
        // the other part of the prefix byte (but would know that it's
        // safe to do so using the bit-wise or).
        return vec![value as u8];
    }

    let mut res: Vec<u8> = Vec::new();
    res.push(mask as u8);
    value -= mask;
    while value >= 128 {
        res.push(((value % 128) + 128) as u8);
        value = value / 128;
    }
    res.push(value as u8);

    res
}

/// The table represents the static header table defined by the HPACK spec.
/// (HPACK, Appendix A)
static STATIC_TABLE: &'static [(&'static [u8], &'static [u8])] = &[
  (b":authority", b""),
  (b":method", b"GET"),
  (b":method", b"POST"),
  (b":path", b"/"),
  (b":path", b"/index.html"),
  (b":scheme", b"http"),
  (b":scheme", b"https"),
  (b":status", b"200"),
  (b":status", b"204"),
  (b":status", b"206"),
  (b":status", b"304"),
  (b":status", b"400"),
  (b":status", b"404"),
  (b":status", b"500"),
  (b"accept-", b""),
  (b"accept-encoding", b"gzip, deflate"),
  (b"accept-language", b""),
  (b"accept-ranges", b""),
  (b"accept", b""),
  (b"access-control-allow-origin", b""),
  (b"age", b""),
  (b"allow", b""),
  (b"authorization", b""),
  (b"cache-control", b""),
  (b"content-disposition", b""),
  (b"content-encoding", b""),
  (b"content-language", b""),
  (b"content-length", b""),
  (b"content-location", b""),
  (b"content-range", b""),
  (b"content-type", b""),
  (b"cookie", b""),
  (b"date", b""),
  (b"etag", b""),
  (b"expect", b""),
  (b"expires", b""),
  (b"from", b""),
  (b"host", b""),
  (b"if-match", b""),
  (b"if-modified-since", b""),
  (b"if-none-match", b""),
  (b"if-range", b""),
  (b"if-unmodified-since", b""),
  (b"last-modified", b""),
  (b"link", b""),
  (b"location", b""),
  (b"max-forwards", b""),
  (b"proxy-authenticate", b""),
  (b"proxy-authorization", b""),
  (b"range", b""),
  (b"referer", b""),
  (b"refresh", b""),
  (b"retry-after", b""),
  (b"server", b""),
  (b"set-cookie", b""),
  (b"strict-transport-security", b""),
  (b"transfer-encoding", b""),
  (b"user-agent", b""),
  (b"vary", b""),
  (b"via", b""),
  (b"www-authenticate", b""),
];

/// A struct representing the dynamic table that needs to be maintained by the
/// coder.
struct DynamicTable {
    table: RingBuf<(Vec<u8>, Vec<u8>)>,
    size: usize,
    max_size: usize,
}

impl DynamicTable {
    /// Creates a new empty dynamic table with a default size.
    fn new() -> DynamicTable {
        // The default maximum size corresponds to the default HTTP/2
        // setting
        DynamicTable::with_size(4096)
    }

    /// Creates a new empty dynamic table with the given maximum size.
    fn with_size(max_size: usize) -> DynamicTable {
        DynamicTable {
            table: RingBuf::new(),
            size: 0,
            max_size: max_size,
        }
    }

    /// Returns the current size of the table in octets, as defined by the IETF
    /// HPACK spec.
    fn get_size(&self) -> usize {
        self.size
    }

    /// Sets the new maximum table size.
    ///
    /// If the current size of the table is larger than the new maximum size,
    /// existing headers are evicted in a FIFO fashion until the size drops
    /// below the new maximum.
    fn set_max_table_size(&mut self, new_max_size: usize) {
        self.max_size = new_max_size;
        // Make the table size fit within the new constraints.
        self.consolidate_table();
    }

    /// Returns the maximum size of the table in octets.
    fn get_max_table_size(&self) -> usize {
        self.max_size
    }

    /// Add a new header to the dynamic table.
    ///
    /// The table automatically gets resized, if necessary.
    ///
    /// Do note that, under the HPACK rules, it is possible the given header
    /// is not found in the dynamic table after this operation finishes, in
    /// case the total size of the given header exceeds the maximum size of the
    /// dynamic table.
    fn add_header(&mut self, name: Vec<u8>, value: Vec<u8>) {
        // This is how the HPACK spec makes us calculate the size.  The 32 is
        // a magic number determined by them (under reasonable assumptions of
        // how the table is stored).
        self.size += name.len() + value.len() + 32;
        debug!("New dynamic table size {}", self.size);
        // Now add it to the internal buffer
        self.table.push_front((name, value));
        // ...and make sure we're not over the maximum size.
        self.consolidate_table();
        debug!("After consolidation dynamic table size {}", self.size);
    }

    fn consolidate_table(&mut self) {
        while self.size > self.max_size {
            {
                let last_header = match self.table.back() {
                    Some(x) => x,
                    None => {
                        // Can never happen as the size of the table must reach 0,
                        // by the time we've exhausted all elements.
                        // Only time it *could* happen is if max_size were 0 too.
                        panic!("Somehow managed to have size != 0, with no headers");
                    }
                };
                self.size -= last_header.0.len() + last_header.1.len() + 32;
            }
            self.table.pop_back();
        }
    }

    /// Returns the number of headers in the dynamic table.
    ///
    /// This is different than the size of the dynamic table.
    fn len(&self) -> usize {
        self.table.len()
    }

    /// Converts the current state of the table to a `Vec`
    fn get_table_as_list(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut ret: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
        for elem in self.table.iter() {
            ret.push(elem.clone());
        }

        ret
    }

    /// Returns a reference to the header at the given index, if found in the
    /// dynamic table.
    fn get(&self, index: usize) -> Option<&(Vec<u8>, Vec<u8>)> {
        self.table.get(index)
    }
}

impl fmt::Show for DynamicTable {
    fn fmt(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
        write!(formatter, "{:?}", self.table)
    }
}

/// Decodes headers encoded using HPACK.
///
/// For now, incremental decoding is not supported, i.e. it is necessary
/// to pass in the entire encoded representation of all headers to the
/// decoder, rather than processing it piece-by-piece.
pub struct Decoder {
    // The dynamic table will own its own copy of headers
    dynamic_table: DynamicTable,
}

/// Different variants of how a particular header field can be represented in
/// an HPACK encoding.
enum FieldRepresentation {
    Indexed,
    LiteralWithIncrementalIndexing,
    SizeUpdate,
    LiteralNeverIndexed,
    LiteralWithoutIndexing,
}

impl FieldRepresentation {
    /// Based on the given octet, returns the type of the field representation.
    ///
    /// The given octet should be the top-order byte of the header field that
    /// is about to be decoded.
    fn new(octet: u8) -> FieldRepresentation {
        if octet & 128 == 128 {
            // High-order bit set
            FieldRepresentation::Indexed
        } else if octet & 64 == 64 {
            // Bit pattern `01`
            FieldRepresentation::LiteralWithIncrementalIndexing
        } else if octet & 32 == 32 {
            // Bit pattern `001`
            FieldRepresentation::SizeUpdate
        } else if octet & 16 == 16 {
            // Bit pattern `0001`
            FieldRepresentation::LiteralNeverIndexed
        } else {
            // None of the top 4 bits is set => bit pattern `0000xxxx`
            FieldRepresentation::LiteralWithoutIndexing
        }
    }
}

/// Decodes an octet string under HPACK rules of encoding found in the given
/// buffer `buf`.
///
/// It is assumed that the first byte in the buffer represents the start of the
/// encoded octet string.
///
/// Returns the decoded string in a newly allocated `Vec` and the number of
/// bytes consumed from the given buffer.
fn decode_string(buf: &[u8]) -> (Vec<u8>, usize) {
    let (len, consumed) = decode_integer(buf, 7);
    debug!("decode_string: Consumed = {}, len = {}", consumed, len);
    let raw_string = &buf[consumed..consumed + len];
    if buf[0] & 128 == 128 {
        debug!("decode_string: Using the Huffman code");
        // Huffman coding used: pass the raw octets to the Huffman decoder
        // and return its result.
        (vec![], len)
    } else {
        // The octets were transmitted raw
        debug!("decode_string: Raw octet string received");
        (raw_string.to_vec(), consumed + len)
    }
}

/// Represents a decoder of HPACK encoded headers. Maintains the state
/// necessary to correctly decode subsequent HPACK blocks.
impl Decoder {
    /// Creates a new `Decoder` with all settings set to default values.
    pub fn new() -> Decoder {
        Decoder {
            dynamic_table: DynamicTable::new(),
        }
    }
}

mod tests {
    use super::{decode_integer};
    use super::{encode_integer};
    use super::DynamicTable;
    use super::FieldRepresentation;
    use super::decode_string;
    use super::Decoder;

    #[test]
    fn test_dynamic_table_size_calculation_simple() {
        let mut table = DynamicTable::new();
        // Sanity check
        assert_eq!(0, table.get_size());

        table.add_header(b"a".to_vec(), b"b".to_vec());

        assert_eq!(32 + 2, table.get_size());
    }

    #[test]
    fn test_dynamic_table_size_calculation() {
        let mut table = DynamicTable::new();

        table.add_header(b"a".to_vec(), b"b".to_vec());
        table.add_header(b"123".to_vec(), b"456".to_vec());
        table.add_header(b"a".to_vec(), b"b".to_vec());

        assert_eq!(3 * 32 + 2 + 6 + 2, table.get_size());
    }

    /// Tests that the `DynamicTable` gets correctly resized (by evicting old
    /// headers) if it exceeds the maximum size on an insertion.
    #[test]
    fn test_dynamic_table_auto_resize() {
        let mut table = DynamicTable::with_size(38);
        table.add_header(b"a".to_vec(), b"b".to_vec());
        assert_eq!(32 + 2, table.get_size());

        table.add_header(b"123".to_vec(), b"456".to_vec());

        // Resized?
        assert_eq!(32 + 6, table.get_size());
        // Only has the second header?
        assert_eq!(table.get_table_as_list(), vec![
            (b"123".to_vec(), b"456".to_vec())]);
    }

    /// Tests that when inserting a new header whose size is larger than the
    /// size of the entire table, the table is fully emptied.
    #[test]
    fn test_dynamic_table_auto_resize_into_empty() {
        let mut table = DynamicTable::with_size(38);
        table.add_header(b"a".to_vec(), b"b".to_vec());
        assert_eq!(32 + 2, table.get_size());

        table.add_header(b"123".to_vec(), b"4567".to_vec());

        // Resized and empty?
        assert_eq!(0, table.get_size());
        assert_eq!(0, table.get_table_as_list().len());
    }

    /// Tests that when changing the maximum size of the `DynamicTable`, the
    /// headers are correctly evicted in order to keep its size below the new
    /// max.
    #[test]
    fn test_dynamic_table_change_max_size() {
        let mut table = DynamicTable::new();
        table.add_header(b"a".to_vec(), b"b".to_vec());
        table.add_header(b"123".to_vec(), b"456".to_vec());
        table.add_header(b"c".to_vec(), b"d".to_vec());
        assert_eq!(3 * 32 + 2 + 6 + 2, table.get_size());

        table.set_max_table_size(38);

        assert_eq!(32 + 2, table.get_size());
        assert_eq!(table.get_table_as_list(), vec![
            (b"c".to_vec(), b"d".to_vec())]);
    }

    /// Tests that setting the maximum table size to 0 clears the dynamic
    /// table.
    #[test]
    fn test_dynamic_table_clear() {
        let mut table = DynamicTable::new();
        table.add_header(b"a".to_vec(), b"b".to_vec());
        table.add_header(b"123".to_vec(), b"456".to_vec());
        table.add_header(b"c".to_vec(), b"d".to_vec());
        assert_eq!(3 * 32 + 2 + 6 + 2, table.get_size());

        table.set_max_table_size(0);

        assert_eq!(0, table.len());
        assert_eq!(0, table.get_table_as_list().len());
        assert_eq!(0, table.get_size());
        assert_eq!(0, table.get_max_table_size());
    }

    #[test]
    fn test_decode_integer() {
        assert_eq!((10us, 1), decode_integer(&[10], 5));
        assert_eq!((1337us, 3), decode_integer(&[31, 154, 10], 5));
        assert_eq!((1337us, 3), decode_integer(&[31 + 32, 154, 10], 5));
        assert_eq!((1337us, 3), decode_integer(&[31 + 64, 154, 10], 5));
        assert_eq!((1337us, 3), decode_integer(&[31, 154, 10, 342, 22], 5));

        assert_eq!((127us, 2), decode_integer(&[255, 0], 7));
        assert_eq!((127us, 2), decode_integer(&[127, 0], 7));
    }

    #[test]
    fn test_encode_integer() {
        assert_eq!(encode_integer(10, 5), [10]);
        assert_eq!(encode_integer(1337, 5), [31, 154, 10]);
        assert_eq!(encode_integer(127, 7), [127, 0]);
    }

    #[test]
    fn test_detect_literal_without_indexing() {
        assert!(match FieldRepresentation::new(0) {
            FieldRepresentation::LiteralWithoutIndexing => true,
            _ => false,
        });
        assert!(match FieldRepresentation::new((1 << 4) - 1) {
            FieldRepresentation::LiteralWithoutIndexing => true,
            _ => false,
        });
        assert!(match FieldRepresentation::new(2) {
            FieldRepresentation::LiteralWithoutIndexing => true,
            _ => false,
        });
    }

    #[test]
    fn test_detect_literal_never_indexed() {
        assert!(match FieldRepresentation::new(1 << 4) {
            FieldRepresentation::LiteralNeverIndexed => true,
            _ => false,
        });
        assert!(match FieldRepresentation::new((1 << 4) + 15) {
            FieldRepresentation::LiteralNeverIndexed => true,
            _ => false,
        });
    }

    #[test]
    fn test_detect_literal_incremental_indexing() {
        assert!(match FieldRepresentation::new(1 << 6) {
            FieldRepresentation::LiteralWithIncrementalIndexing => true,
            _ => false,
        });
        assert!(match FieldRepresentation::new((1 << 6) + (1 << 4)) {
            FieldRepresentation::LiteralWithIncrementalIndexing => true,
            _ => false,
        });
        assert!(match FieldRepresentation::new((1 << 7) - 1) {
            FieldRepresentation::LiteralWithIncrementalIndexing => true,
            _ => false,
        });
    }

    #[test]
    fn test_detect_indexed() {
        assert!(match FieldRepresentation::new(1 << 7) {
            FieldRepresentation::Indexed => true,
            _ => false,
        });
        assert!(match FieldRepresentation::new((1 << 7) + (1 << 4)) {
            FieldRepresentation::Indexed => true,
            _ => false,
        });
        assert!(match FieldRepresentation::new((1 << 7) + (1 << 5)) {
            FieldRepresentation::Indexed => true,
            _ => false,
        });
        assert!(match FieldRepresentation::new((1 << 7) + (1 << 6)) {
            FieldRepresentation::Indexed => true,
            _ => false,
        });
        assert!(match FieldRepresentation::new(255) {
            FieldRepresentation::Indexed => true,
            _ => false,
        });
    }

    #[test]
    fn test_detect_dynamic_table_size_update() {
        assert!(match FieldRepresentation::new(1 << 5) {
            FieldRepresentation::SizeUpdate => true,
            _ => false,
        });
        assert!(match FieldRepresentation::new((1 << 5) + (1 << 4)) {
            FieldRepresentation::SizeUpdate => true,
            _ => false,
        });
        assert!(match FieldRepresentation::new((1 << 6) - 1) {
            FieldRepresentation::SizeUpdate => true,
            _ => false,
        });
    }

    #[test]
    fn test_decode_string_no_huffman() {
        assert_eq!((b"abc".to_vec(), 4), decode_string(&[3, b'a', b'b', b'c']));
        assert_eq!((b"a".to_vec(), 2), decode_string(&[1, b'a']));
        assert_eq!((b"".to_vec(), 1), decode_string(&[0, b'a']));
    }

    /// Tests that an octet string is correctly decoded when it's length
    /// is longer than what can fit into the 7-bit prefix.
    #[test]
    fn test_decode_string_no_huffman_long() {
        {
            let full_string: Vec<u8> = (0u8..200).collect();
            let mut encoded = encode_integer(full_string.len(), 7);
            encoded.push_all(full_string.as_slice());

            assert_eq!(
                (full_string, encoded.len()),
                decode_string(encoded.as_slice()));
        }
        {
            let full_string: Vec<u8> = (0u8..127).collect();
            let mut encoded = encode_integer(full_string.len(), 7);
            encoded.push_all(full_string.as_slice());

            assert_eq!(
                (full_string, encoded.len()),
                decode_string(encoded.as_slice()));
        }
    }
}
