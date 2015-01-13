/// Exposes the struct `Decoder` that allows for HPACK-encoded header blocks to
/// be decoded into a header list.
///
/// The decoder only follows HPACK rules, without performing any additional
/// (semantic) checks on the header name/value pairs, i.e. it considers the
/// headers as opaque octets.
///
/// # Example
///
/// A simple example of using the decoder that demonstrates its API:
///
/// ```rust
/// use solicit::hpack::Decoder;
/// let mut decoder = Decoder::new();
///
/// let header_list = decoder.decode(&[0x82]);
///
/// assert_eq!([(b":method".to_vec(), b"GET".to_vec())], header_list);
/// ```
use std::fmt;
use std::collections::RingBuf;

use super::huffman::HuffmanDecoder;

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
///
/// The dynamic table contains a number of recently used headers. The size of
/// the table is constrained to a certain number of octets. If on insertion of
/// a new header into the table, the table would exceed the maximum size,
/// headers are evicted in a FIFO fashion until there is enough room for the
/// new header to be inserted. (Therefore, it is possible that though all
/// elements end up being evicted, there is still not enough space for the new
/// header: when the size of this individual header exceeds the maximum size of
/// the table.)
///
/// The current size of the table is calculated, based on the IETF definition,
/// as the sum of sizes of each header stored within the table, where the size
/// of an individual header is
/// `len_in_octets(header_name) + len_in_octets(header_value) + 32`.
///
/// Note: the maximum size of the dynamic table does not have to be equal to
/// the maximum header table size as defined by a "higher level" protocol
/// (such as the `SETTINGS_HEADER_TABLE_SIZE` setting in HTTP/2), since HPACK
/// can choose to modify the dynamic table size on the fly (as long as it keeps
/// it below the maximum value set by the protocol). So, the `DynamicTable`
/// only cares about the maximum size as set by the HPACK {en,de}coder and lets
/// *it* worry about making certain that the changes are valid according to
/// the (current) constraints of the protocol.
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

    /// Consolidates the table entries so that the table size is below the
    /// maximum allowed size, by evicting headers from the table in a FIFO
    /// fashion.
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
        let mut decoder = HuffmanDecoder::new();
        (decoder.decode(raw_string), consumed + len)
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
    /// Decode the header block found in the given buffer.
    ///
    /// The buffer should represent the entire block that should be decoded.
    /// For example, in HTTP/2, all continuation frames need to be concatenated
    /// to a single buffer before passing them to the decoder.
    pub fn decode(&mut self, buf: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
        let mut current_octet_index = 0;
        let mut header_list = Vec::new();

        while current_octet_index < buf.len() {
            let initial_octet = buf[current_octet_index];
            let consumed = match FieldRepresentation::new(initial_octet) {
                FieldRepresentation::Indexed => {
                    let ((name, value), consumed) =
                        self.decode_indexed(&buf[current_octet_index..]);
                    header_list.push((name, value));

                    consumed
                },
                FieldRepresentation::LiteralWithIncrementalIndexing => {
                    let ((name, value), consumed) =
                        self.decode_literal(&buf[current_octet_index..], true);
                    header_list.push((name, value));

                    consumed
                },
                FieldRepresentation::LiteralWithoutIndexing => {
                    let ((name, value), consumed) =
                        self.decode_literal(&buf[current_octet_index..], false);
                    header_list.push((name, value));

                    consumed
                },
                FieldRepresentation::LiteralNeverIndexed => {
                    // Same as the previous one, except if we were also a proxy
                    // we would need to make sure not to change the
                    // representation received here. We don't care about this
                    // for now.
                    let ((name, value), consumed) =
                        self.decode_literal(&buf[current_octet_index..], false);
                    header_list.push((name, value));

                    consumed
                },
                FieldRepresentation::SizeUpdate => {
                    // Handle the dynamic table size update...
                    self.update_max_dynamic_size(&buf[current_octet_index..])
                }
            };

            current_octet_index += consumed;
        }

        header_list
    }

    /// Decodes an indexed header representation.
    fn decode_indexed(&self, buf: &[u8]) -> ((Vec<u8>, Vec<u8>), usize) {
        let (index, consumed) = decode_integer(buf, 7);
        debug!("Decoding indexed: index = {}, consumed = {}", index, consumed);

        let (name, value) = match self.get_from_table(index) {
            Some((name, value)) => (name.to_vec(), value.to_vec()),
            None => panic!("Error handling not yet implemented, table index out of bounds"),
        };

        ((name, value), consumed)
    }

    /// Gets the header (name, value) pair with the given index from the table.
    ///
    /// In this context, the "table" references the definition of the table
    /// where the static table is concatenated with the dynamic table and is
    /// 1-indexed.
    fn get_from_table(&self, index: usize) -> Option<(&[u8], &[u8])> {
        // The IETF defined table indexing as 1-based
        let real_index = index - 1;

        if real_index < STATIC_TABLE.len() {
            // It is in the static table so just return that...
            Some(STATIC_TABLE[real_index])
        } else {
            // It is in the dynamic table ...
            let dynamic_index = real_index - STATIC_TABLE.len();
            if dynamic_index < self.dynamic_table.len() {
                match self.dynamic_table.get(dynamic_index) {
                    Some(&(ref name, ref value)) => {
                        Some((name.as_slice(), value.as_slice()))
                    },
                    None => None,
                }
            } else {
                // Index out of bounds!
                None
            }
        }
    }

    /// Decodes a literal header representation from the given buffer.
    ///
    /// # Parameters
    ///
    /// - index: whether or not the decoded value should be indexed (i.e.
    ///   included in the dynamic table).
    fn decode_literal(&mut self, buf: &[u8], index: bool) -> ((Vec<u8>, Vec<u8>), usize) {
        let prefix = if index {
            6
        } else {
            4
        };
        let (table_index, mut consumed) = decode_integer(buf, prefix);

        // First read the name appropriately
        let name = if table_index == 0 {
            // Read name string as literal
            let (name, name_len) = decode_string(&buf[consumed..]);
            consumed += name_len;
            name
        } else {
            // Read name indexed from the table
            // TODO Gracefully handle an index out of bounds!
            // (i.e. a failed unwrap)
            let (name, _) = self.get_from_table(table_index).unwrap();
            name.to_vec()
        };

        // Now read the value as a literal...
        let (value, value_len) = decode_string(&buf[consumed..]);
        consumed += value_len;

        if index {
            // We add explicit copies to the dynamic table, as we want to
            // be able to relinquish ownership of the final decoded header
            // list to the client, but also keep entries in the dynamic table
            // for decoding the next blocks.
            self.add_to_dynamic_table(name.clone(), value.clone());
        }
        ((name, value), consumed)
    }

    /// Internal helper function for adding elements to the dynamic table.
    /// Simply proxies it to the internal `dynamic_table` member.
    fn add_to_dynamic_table(&mut self, name: Vec<u8>, value: Vec<u8>) {
        self.dynamic_table.add_header(name, value);
    }

    /// Handles processing the `SizeUpdate` HPACK block: updates the maximum
    /// size of the underlying dynamic table, possibly causing a number of
    /// headers to be evicted from it.
    ///
    /// Assumes that the first byte in the given buffer `buf` is the first
    /// octet in the `SizeUpdate` block.
    ///
    /// Returns the number of octets consumed from the given buffer.
    fn update_max_dynamic_size(&mut self, buf: &[u8]) -> usize {
        let (new_size, consumed) = decode_integer(buf, 5);
        self.dynamic_table.set_max_table_size(new_size);

        info!("Decoder changed max table size from {} to {}",
              self.dynamic_table.get_size(),
              new_size);

        consumed
    }

    /// Sets a new maximum dynamic table size for the decoder.
    fn set_max_table_size(&mut self, new_max_size: usize) {
        self.dynamic_table.set_max_table_size(new_max_size);
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

    /// Tests that a header list with only a single header found fully in the
    /// static header table is correctly decoded.
    /// (example from: HPACK-draft-10, C.2.4.)
    #[test]
    fn test_decode_fully_in_static_table() {
        let mut decoder = Decoder::new();

        let header_list = decoder.decode(&[0x82]);

        assert_eq!([(b":method".to_vec(), b"GET".to_vec())], header_list);
    }

    #[test]
    fn test_decode_multiple_fully_in_static_table() {
        let mut decoder = Decoder::new();

        let header_list = decoder.decode(&[0x82, 0x86, 0x84]);

        assert_eq!(header_list, [
            (b":method".to_vec(), b"GET".to_vec()),
            (b":scheme".to_vec(), b"http".to_vec()),
            (b":path".to_vec(), b"/".to_vec()),
        ]);
    }

    /// Tests that a literal with an indexed name and literal value is correctly
    /// decoded.
    /// (example from: HPACK-draft-10, C.2.2.)
    #[test]
    fn test_decode_literal_indexed_name() {
        let mut decoder = Decoder::new();
        let hex_dump = [
            0x04, 0x0c, 0x2f, 0x73, 0x61, 0x6d, 0x70,
            0x6c, 0x65, 0x2f, 0x70, 0x61, 0x74, 0x68,
        ];

        let header_list = decoder.decode(&hex_dump);

        assert_eq!(header_list, [
            (b":path".to_vec(), b"/sample/path".to_vec()),
        ]);
        // Nothing was added to the dynamic table
        assert_eq!(decoder.dynamic_table.len(), 0);
    }

    /// Tests that a header with both a literal name and value is correctly
    /// decoded.
    /// (example from: HPACK-draft-10, C.2.1.)
    #[test]
    fn test_decode_literal_both() {
        let mut decoder = Decoder::new();
        let hex_dump = [
            0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65,
            0x79, 0x0d, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x68, 0x65,
            0x61, 0x64, 0x65, 0x72,
        ];

        let header_list = decoder.decode(&hex_dump);

        assert_eq!(header_list, [
            (b"custom-key".to_vec(), b"custom-header".to_vec()),
        ]);
        // The entry got added to the dynamic table?
        assert_eq!(decoder.dynamic_table.len(), 1);
        let mut expected_table = vec![
            (b"custom-key".to_vec(), b"custom-header".to_vec())
        ];
        let actual = decoder.dynamic_table.get_table_as_list();
        assert_eq!(actual, expected_table);
    }

    /// Tests that a header with a name indexed from the dynamic table and a
    /// literal value is correctly decoded.
    #[test]
    fn test_decode_literal_name_in_dynamic() {
        let mut decoder = Decoder::new();
        {
            // Prepares the context: the dynamic table contains a custom-key.
            let hex_dump = [
                0x40, 0x0a, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x6b, 0x65,
                0x79, 0x0d, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x68, 0x65,
                0x61, 0x64, 0x65, 0x72,
            ];

            let header_list = decoder.decode(&hex_dump);

            assert_eq!(header_list, [
                (b"custom-key".to_vec(), b"custom-header".to_vec()),
            ]);
            // The entry got added to the dynamic table?
            assert_eq!(decoder.dynamic_table.len(), 1);
            let mut expected_table = vec![
                (b"custom-key".to_vec(), b"custom-header".to_vec())
            ];
            let actual = decoder.dynamic_table.get_table_as_list();
            assert_eq!(actual, expected_table);
        }
        {
            let hex_dump = [
                0x40 + 62,  // Index 62 in the table => 1st in dynamic table
                0x0e, 0x63, 0x75, 0x73, 0x74, 0x6f, 0x6d, 0x2d, 0x68, 0x65,
                0x61, 0x64, 0x65, 0x72, 0x2d,
            ];

            let header_list = decoder.decode(&hex_dump);

            assert_eq!(header_list, [
                (b"custom-key".to_vec(), b"custom-header-".to_vec()),
            ]);
            // The entry got added to the dynamic table, so now we have two?
            assert_eq!(decoder.dynamic_table.len(), 2);
            let mut expected_table = vec![
                (b"custom-key".to_vec(), b"custom-header-".to_vec()),
                (b"custom-key".to_vec(), b"custom-header".to_vec()),
            ];
            let actual = decoder.dynamic_table.get_table_as_list();
            assert_eq!(actual, expected_table);
        }
    }

    /// Tests that a header with a "never indexed" type is correctly
    /// decoded.
    /// (example from: HPACK-draft-10, C.2.3.)
    #[test]
    fn test_decode_literal_field_never_indexed() {
        let mut decoder = Decoder::new();
        let hex_dump = [
            0x10, 0x08, 0x70, 0x61, 0x73, 0x73, 0x77, 0x6f, 0x72, 0x64, 0x06,
            0x73, 0x65, 0x63, 0x72, 0x65, 0x74,
        ];

        let header_list = decoder.decode(&hex_dump);

        assert_eq!(header_list, [
            (b"password".to_vec(), b"secret".to_vec()),
        ]);
        // Nothing was added to the dynamic table
        assert_eq!(decoder.dynamic_table.len(), 0);
    }

    /// Tests that a each header list from a sequence of requests is correctly
    /// decoded.
    /// (example from: HPACK-draft-10, C.3.*)
    #[test]
    fn test_request_sequence_no_huffman() {
        let mut decoder = Decoder::new();
        {
            // First Request (C.3.1.)
            let hex_dump = [
                0x82, 0x86, 0x84, 0x41, 0x0f, 0x77, 0x77, 0x77, 0x2e, 0x65,
                0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
            ];

            let header_list = decoder.decode(&hex_dump);

            assert_eq!(header_list, [
                (b":method".to_vec(), b"GET".to_vec()),
                (b":scheme".to_vec(), b"http".to_vec()),
                (b":path".to_vec(), b"/".to_vec()),
                (b":authority".to_vec(), b"www.example.com".to_vec()),
            ]);
            // Only one entry got added to the dynamic table?
            assert_eq!(decoder.dynamic_table.len(), 1);
            let mut expected_table = vec![
                (b":authority".to_vec(), b"www.example.com".to_vec())
            ];
            let actual = decoder.dynamic_table.get_table_as_list();
            assert_eq!(actual, expected_table);
        }
        {
            // Second Request (C.3.2.)
            let hex_dump = [
                0x82, 0x86, 0x84, 0xbe, 0x58, 0x08, 0x6e, 0x6f, 0x2d, 0x63,
                0x61, 0x63, 0x68, 0x65,
            ];

            let header_list = decoder.decode(&hex_dump);

            assert_eq!(header_list, [
                (b":method".to_vec(), b"GET".to_vec()),
                (b":scheme".to_vec(), b"http".to_vec()),
                (b":path".to_vec(), b"/".to_vec()),
                (b":authority".to_vec(), b"www.example.com".to_vec()),
                (b"cache-control".to_vec(), b"no-cache".to_vec()),
            ]);
            // One entry got added to the dynamic table, so we have two?
            let mut expected_table = vec![
                (b"cache-control".to_vec(), b"no-cache".to_vec()),
                (b":authority".to_vec(), b"www.example.com".to_vec()),
            ];
            let actual = decoder.dynamic_table.get_table_as_list();
            assert_eq!(actual, expected_table);
        }
        {
            // Third Request (C.3.3.)
            let hex_dump = [
                0x82, 0x87, 0x85, 0xbf, 0x40, 0x0a, 0x63, 0x75, 0x73, 0x74,
                0x6f, 0x6d, 0x2d, 0x6b, 0x65, 0x79, 0x0c, 0x63, 0x75, 0x73,
                0x74, 0x6f, 0x6d, 0x2d, 0x76, 0x61, 0x6c, 0x75, 0x65,
            ];

            let header_list = decoder.decode(&hex_dump);

            assert_eq!(header_list, [
                (b":method".to_vec(), b"GET".to_vec()),
                (b":scheme".to_vec(), b"https".to_vec()),
                (b":path".to_vec(), b"/index.html".to_vec()),
                (b":authority".to_vec(), b"www.example.com".to_vec()),
                (b"custom-key".to_vec(), b"custom-value".to_vec()),
            ]);
            // One entry got added to the dynamic table, so we have three at
            // this point...?
            let mut expected_table = vec![
                (b"custom-key".to_vec(), b"custom-value".to_vec()),
                (b"cache-control".to_vec(), b"no-cache".to_vec()),
                (b":authority".to_vec(), b"www.example.com".to_vec()),
            ];
            let actual = decoder.dynamic_table.get_table_as_list();
            assert_eq!(actual, expected_table);
        }
    }

    /// Tests that a each header list from a sequence of responses is correctly
    /// decoded.
    /// (example from: HPACK-draft-10, C.5.*)
    #[test]
    fn response_sequence_no_huffman() {
        let mut decoder = Decoder::new();
        // The example sets the max table size to 256 octets.
        decoder.set_max_table_size(256);
        {
            // First Response (C.5.1.)
            let hex_dump = [
                0x48, 0x03, 0x33, 0x30, 0x32, 0x58, 0x07, 0x70, 0x72, 0x69,
                0x76, 0x61, 0x74, 0x65, 0x61, 0x1d, 0x4d, 0x6f, 0x6e, 0x2c,
                0x20, 0x32, 0x31, 0x20, 0x4f, 0x63, 0x74, 0x20, 0x32, 0x30,
                0x31, 0x33, 0x20, 0x32, 0x30, 0x3a, 0x31, 0x33, 0x3a, 0x32,
                0x31, 0x20, 0x47, 0x4d, 0x54, 0x6e, 0x17, 0x68, 0x74, 0x74,
                0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x65,
                0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
            ];

            let header_list = decoder.decode(&hex_dump);

            assert_eq!(header_list, [
                (b":status".to_vec(), b"302".to_vec()),
                (b"cache-control".to_vec(), b"private".to_vec()),
                (b"date".to_vec(), b"Mon, 21 Oct 2013 20:13:21 GMT".to_vec()),
                (b"location".to_vec(), b"https://www.example.com".to_vec()),
            ]);
            // All entries in the dynamic table too?
            let mut expected_table = vec![
                (b"location".to_vec(), b"https://www.example.com".to_vec()),
                (b"date".to_vec(), b"Mon, 21 Oct 2013 20:13:21 GMT".to_vec()),
                (b"cache-control".to_vec(), b"private".to_vec()),
                (b":status".to_vec(), b"302".to_vec()),
            ];
            let actual = decoder.dynamic_table.get_table_as_list();
            assert_eq!(actual, expected_table);
        }
        {
            // Second Response (C.5.2.)
            let hex_dump = [
                0x48, 0x03, 0x33, 0x30, 0x37, 0xc1, 0xc0, 0xbf,
            ];

            let header_list = decoder.decode(&hex_dump);

            assert_eq!(header_list, [
                (b":status".to_vec(), b"307".to_vec()),
                (b"cache-control".to_vec(), b"private".to_vec()),
                (b"date".to_vec(), b"Mon, 21 Oct 2013 20:13:21 GMT".to_vec()),
                (b"location".to_vec(), b"https://www.example.com".to_vec()),
            ]);
            // The new status replaces the old status in the table, since it
            // cannot fit without evicting something from the table.
            let mut expected_table = vec![
                (b":status".to_vec(), b"307".to_vec()),
                (b"location".to_vec(), b"https://www.example.com".to_vec()),
                (b"date".to_vec(), b"Mon, 21 Oct 2013 20:13:21 GMT".to_vec()),
                (b"cache-control".to_vec(), b"private".to_vec()),
            ];
            let actual = decoder.dynamic_table.get_table_as_list();
            assert_eq!(actual, expected_table);
        }
        {
            // Third Response (C.5.3.)
            let hex_dump = [
                0x88, 0xc1, 0x61, 0x1d, 0x4d, 0x6f, 0x6e, 0x2c, 0x20, 0x32,
                0x31, 0x20, 0x4f, 0x63, 0x74, 0x20, 0x32, 0x30, 0x31, 0x33,
                0x20, 0x32, 0x30, 0x3a, 0x31, 0x33, 0x3a, 0x32, 0x32, 0x20,
                0x47, 0x4d, 0x54, 0xc0, 0x5a, 0x04, 0x67, 0x7a, 0x69, 0x70,
                0x77, 0x38, 0x66, 0x6f, 0x6f, 0x3d, 0x41, 0x53, 0x44, 0x4a,
                0x4b, 0x48, 0x51, 0x4b, 0x42, 0x5a, 0x58, 0x4f, 0x51, 0x57,
                0x45, 0x4f, 0x50, 0x49, 0x55, 0x41, 0x58, 0x51, 0x57, 0x45,
                0x4f, 0x49, 0x55, 0x3b, 0x20, 0x6d, 0x61, 0x78, 0x2d, 0x61,
                0x67, 0x65, 0x3d, 0x33, 0x36, 0x30, 0x30, 0x3b, 0x20, 0x76,
                0x65, 0x72, 0x73, 0x69, 0x6f, 0x6e, 0x3d, 0x31,
            ];

            let header_list = decoder.decode(&hex_dump);

            let expected_header_list = [
                (b":status".to_vec(), b"200".to_vec()),
                (b"cache-control".to_vec(), b"private".to_vec()),
                (b"date".to_vec(), b"Mon, 21 Oct 2013 20:13:22 GMT".to_vec()),
                (b"location".to_vec(), b"https://www.example.com".to_vec()),
                (b"content-encoding".to_vec(), b"gzip".to_vec()),
                (
                    b"set-cookie".to_vec(),
                    b"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1".to_vec()
                ),
            ];
            assert_eq!(header_list, expected_header_list);
            // The new status replaces the old status in the table, since it
            // cannot fit without evicting something from the table.
            let mut expected_table = vec![
                (
                    b"set-cookie".to_vec(),
                    b"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1".to_vec()
                ),
                (b"content-encoding".to_vec(), b"gzip".to_vec()),
                (b"date".to_vec(), b"Mon, 21 Oct 2013 20:13:22 GMT".to_vec()),
            ];
            let actual = decoder.dynamic_table.get_table_as_list();
            // assert_eq!(actual, expected_table);
        }
    }

    /// Tests that when the decoder receives an update of the max dynamic table
    /// size as 0, all entries are cleared from the dynamic table.
    #[test]
    fn test_decoder_clear_dynamic_table() {
        let mut decoder = Decoder::new();
        {
            let hex_dump = [
                0x48, 0x03, 0x33, 0x30, 0x32, 0x58, 0x07, 0x70, 0x72, 0x69,
                0x76, 0x61, 0x74, 0x65, 0x61, 0x1d, 0x4d, 0x6f, 0x6e, 0x2c,
                0x20, 0x32, 0x31, 0x20, 0x4f, 0x63, 0x74, 0x20, 0x32, 0x30,
                0x31, 0x33, 0x20, 0x32, 0x30, 0x3a, 0x31, 0x33, 0x3a, 0x32,
                0x31, 0x20, 0x47, 0x4d, 0x54, 0x6e, 0x17, 0x68, 0x74, 0x74,
                0x70, 0x73, 0x3a, 0x2f, 0x2f, 0x77, 0x77, 0x77, 0x2e, 0x65,
                0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x2e, 0x63, 0x6f, 0x6d,
            ];

            let header_list = decoder.decode(&hex_dump);

            assert_eq!(header_list, [
                (b":status".to_vec(), b"302".to_vec()),
                (b"cache-control".to_vec(), b"private".to_vec()),
                (b"date".to_vec(), b"Mon, 21 Oct 2013 20:13:21 GMT".to_vec()),
                (b"location".to_vec(), b"https://www.example.com".to_vec()),
            ]);
            // All entries in the dynamic table too?
            let mut expected_table = vec![
                (b"location".to_vec(), b"https://www.example.com".to_vec()),
                (b"date".to_vec(), b"Mon, 21 Oct 2013 20:13:21 GMT".to_vec()),
                (b"cache-control".to_vec(), b"private".to_vec()),
                (b":status".to_vec(), b"302".to_vec()),
            ];
            let actual = decoder.dynamic_table.get_table_as_list();
            assert_eq!(actual, expected_table);
        }
        {
            let hex_dump = [
                0x48, 0x03, 0x33, 0x30, 0x37, 0xc1, 0xc0, 0xbf,
                // This instructs the decoder to clear the list
                // (it's doubtful that it would ever be found there in a real
                // response, though...)
                0x20,
            ];

            let header_list = decoder.decode(&hex_dump);

            // Headers have been correctly decoded...
            assert_eq!(header_list, [
                (b":status".to_vec(), b"307".to_vec()),
                (b"cache-control".to_vec(), b"private".to_vec()),
                (b"date".to_vec(), b"Mon, 21 Oct 2013 20:13:21 GMT".to_vec()),
                (b"location".to_vec(), b"https://www.example.com".to_vec()),
            ]);
            // Expect an empty table!
            let mut expected_table = vec![];
            let actual = decoder.dynamic_table.get_table_as_list();
            assert_eq!(actual, expected_table);
            assert_eq!(0, decoder.dynamic_table.get_max_table_size());
        }
    }

    /// Tests that a each header list from a sequence of requests is correctly
    /// decoded, when Huffman coding is used
    /// (example from: HPACK-draft-10, C.4.*)
    #[test]
    fn request_sequence_huffman() {
        let mut decoder = Decoder::new();
        {
            // First Request (B.4.1.)
            let hex_dump = [
                0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2,
                0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff,
            ];

            let header_list = decoder.decode(&hex_dump);

            assert_eq!(header_list, [
                (b":method".to_vec(), b"GET".to_vec()),
                (b":scheme".to_vec(), b"http".to_vec()),
                (b":path".to_vec(), b"/".to_vec()),
                (b":authority".to_vec(), b"www.example.com".to_vec()),
            ]);
            // Only one entry got added to the dynamic table?
            assert_eq!(decoder.dynamic_table.len(), 1);
            let mut expected_table = vec![
                (b":authority".to_vec(), b"www.example.com".to_vec())
            ];
            let actual = decoder.dynamic_table.get_table_as_list();
            assert_eq!(actual, expected_table);
        }
        {
            // Second Request (C.4.2.)
            let hex_dump = [
                0x82, 0x86, 0x84, 0xbe, 0x58, 0x86, 0xa8, 0xeb, 0x10, 0x64,
                0x9c, 0xbf,
            ];

            let header_list = decoder.decode(&hex_dump);

            assert_eq!(header_list, [
                (b":method".to_vec(), b"GET".to_vec()),
                (b":scheme".to_vec(), b"http".to_vec()),
                (b":path".to_vec(), b"/".to_vec()),
                (b":authority".to_vec(), b"www.example.com".to_vec()),
                (b"cache-control".to_vec(), b"no-cache".to_vec()),
            ]);
            // One entry got added to the dynamic table, so we have two?
            let mut expected_table = vec![
                (b"cache-control".to_vec(), b"no-cache".to_vec()),
                (b":authority".to_vec(), b"www.example.com".to_vec()),
            ];
            let actual = decoder.dynamic_table.get_table_as_list();
            assert_eq!(actual, expected_table);
        }
        {
            // Third Request (C.4.3.)
            let hex_dump = [
                0x82, 0x87, 0x85, 0xbf, 0x40, 0x88, 0x25, 0xa8, 0x49, 0xe9,
                0x5b, 0xa9, 0x7d, 0x7f, 0x89, 0x25, 0xa8, 0x49, 0xe9, 0x5b,
                0xb8, 0xe8, 0xb4, 0xbf,
            ];

            let header_list = decoder.decode(&hex_dump);

            assert_eq!(header_list, [
                (b":method".to_vec(), b"GET".to_vec()),
                (b":scheme".to_vec(), b"https".to_vec()),
                (b":path".to_vec(), b"/index.html".to_vec()),
                (b":authority".to_vec(), b"www.example.com".to_vec()),
                (b"custom-key".to_vec(), b"custom-value".to_vec()),
            ]);
            // One entry got added to the dynamic table, so we have three at
            // this point...?
            let mut expected_table = vec![
                (b"custom-key".to_vec(), b"custom-value".to_vec()),
                (b"cache-control".to_vec(), b"no-cache".to_vec()),
                (b":authority".to_vec(), b"www.example.com".to_vec()),
            ];
            let actual = decoder.dynamic_table.get_table_as_list();
            assert_eq!(actual, expected_table);
        }
    }

    /// Tests that a each header list from a sequence of responses is correctly
    /// decoded, when Huffman encoding is used
    /// (example from: HPACK-draft-10, C.6.*)
    #[test]
    fn response_sequence_huffman() {
        let mut decoder = Decoder::new();
        // The example sets the max table size to 256 octets.
        decoder.set_max_table_size(256);
        {
            // First Response (C.6.1.)
            let hex_dump = [
                0x48, 0x82, 0x64, 0x02, 0x58, 0x85, 0xae, 0xc3, 0x77, 0x1a,
                0x4b, 0x61, 0x96, 0xd0, 0x7a, 0xbe, 0x94, 0x10, 0x54, 0xd4,
                0x44, 0xa8, 0x20, 0x05, 0x95, 0x04, 0x0b, 0x81, 0x66, 0xe0,
                0x82, 0xa6, 0x2d, 0x1b, 0xff, 0x6e, 0x91, 0x9d, 0x29, 0xad,
                0x17, 0x18, 0x63, 0xc7, 0x8f, 0x0b, 0x97, 0xc8, 0xe9, 0xae,
                0x82, 0xae, 0x43, 0xd3,
            ];

            let header_list = decoder.decode(&hex_dump);

            assert_eq!(header_list, [
                (b":status".to_vec(), b"302".to_vec()),
                (b"cache-control".to_vec(), b"private".to_vec()),
                (b"date".to_vec(), b"Mon, 21 Oct 2013 20:13:21 GMT".to_vec()),
                (b"location".to_vec(), b"https://www.example.com".to_vec()),
            ]);
            // All entries in the dynamic table too?
            let mut expected_table = vec![
                (b"location".to_vec(), b"https://www.example.com".to_vec()),
                (b"date".to_vec(), b"Mon, 21 Oct 2013 20:13:21 GMT".to_vec()),
                (b"cache-control".to_vec(), b"private".to_vec()),
                (b":status".to_vec(), b"302".to_vec()),
            ];
            let actual = decoder.dynamic_table.get_table_as_list();
            assert_eq!(actual, expected_table);
        }
        {
            // Second Response (C.6.2.)
            let hex_dump = [
                0x48, 0x83, 0x64, 0x0e, 0xff, 0xc1, 0xc0, 0xbf,
            ];

            let header_list = decoder.decode(&hex_dump);

            assert_eq!(header_list, [
                (b":status".to_vec(), b"307".to_vec()),
                (b"cache-control".to_vec(), b"private".to_vec()),
                (b"date".to_vec(), b"Mon, 21 Oct 2013 20:13:21 GMT".to_vec()),
                (b"location".to_vec(), b"https://www.example.com".to_vec()),
            ]);
            // The new status replaces the old status in the table, since it
            // cannot fit without evicting something from the table.
            let mut expected_table = vec![
                (b":status".to_vec(), b"307".to_vec()),
                (b"location".to_vec(), b"https://www.example.com".to_vec()),
                (b"date".to_vec(), b"Mon, 21 Oct 2013 20:13:21 GMT".to_vec()),
                (b"cache-control".to_vec(), b"private".to_vec()),
            ];
            let actual = decoder.dynamic_table.get_table_as_list();
            assert_eq!(actual, expected_table);
        }
        {
            // Third Response (C.6.3.)
            let hex_dump = [
                0x88, 0xc1, 0x61, 0x96, 0xd0, 0x7a, 0xbe, 0x94, 0x10, 0x54,
                0xd4, 0x44, 0xa8, 0x20, 0x05, 0x95, 0x04, 0x0b, 0x81, 0x66,
                0xe0, 0x84, 0xa6, 0x2d, 0x1b, 0xff, 0xc0, 0x5a, 0x83, 0x9b,
                0xd9, 0xab, 0x77, 0xad, 0x94, 0xe7, 0x82, 0x1d, 0xd7, 0xf2,
                0xe6, 0xc7, 0xb3, 0x35, 0xdf, 0xdf, 0xcd, 0x5b, 0x39, 0x60,
                0xd5, 0xaf, 0x27, 0x08, 0x7f, 0x36, 0x72, 0xc1, 0xab, 0x27,
                0x0f, 0xb5, 0x29, 0x1f, 0x95, 0x87, 0x31, 0x60, 0x65, 0xc0,
                0x03, 0xed, 0x4e, 0xe5, 0xb1, 0x06, 0x3d, 0x50, 0x07,
            ];

            let header_list = decoder.decode(&hex_dump);

            let expected_header_list = [
                (b":status".to_vec(), b"200".to_vec()),
                (b"cache-control".to_vec(), b"private".to_vec()),
                (b"date".to_vec(), b"Mon, 21 Oct 2013 20:13:22 GMT".to_vec()),
                (b"location".to_vec(), b"https://www.example.com".to_vec()),
                (b"content-encoding".to_vec(), b"gzip".to_vec()),
                (
                    b"set-cookie".to_vec(),
                    b"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1".to_vec()
                ),
            ];
            assert_eq!(header_list, expected_header_list);
            // The new status replaces the old status in the table, since it
            // cannot fit without evicting something from the table.
            let mut expected_table = vec![
                (
                    b"set-cookie".to_vec(),
                    b"foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1".to_vec()
                ),
                (b"content-encoding".to_vec(), b"gzip".to_vec()),
                (b"date".to_vec(), b"Mon, 21 Oct 2013 20:13:22 GMT".to_vec()),
            ];
            let actual = decoder.dynamic_table.get_table_as_list();
            assert_eq!(actual, expected_table);
        }
    }
}
