//! Implements all functionality related to encoding header blocks using
//! HPACK.
//!
//! Clients should use the `Encoder` struct as the API for performing HPACK
//! encoding.
//!
//! # Examples
//!
//! Encodes a header using a literal encoding.
//!
//! ```rust
//! use solicit::hpack::Encoder;
//!
//! let mut encoder = Encoder::new();
//!
//! let headers = vec![
//!     (b"custom-key".to_vec(), b"custom-value".to_vec()),
//! ];
//! // First encoding...
//! let result = encoder.encode(&headers);
//! // The result is a literal encoding of the header name and value, with an
//! // initial byte representing the type of the encoding
//! // (incremental indexing).
//! assert_eq!(
//!     vec![0x40,
//!          10, b'c', b'u', b's', b't', b'o', b'm', b'-', b'k', b'e', b'y',
//!          12, b'c', b'u', b's', b't', b'o', b'm', b'-', b'v', b'a', b'l',
//!          b'u', b'e'],
//!     result);
//! ```
use super::STATIC_TABLE;
use super::HeaderTable;


/// Encode an integer to the representation defined by HPACK.
///
/// Returns a newly allocated `Vec` containing the encoded bytes.
/// Only `prefix_size` lowest-order bits of the first byte in the
/// array are guaranteed to be used.
pub fn encode_integer(mut value: usize, prefix_size: u8) -> Vec<u8> {
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

/// Represents an HPACK encoder. Allows clients to encode arbitrary header sets
/// and tracks the encoding context. That is, encoding subsequent header sets
/// will use the context built by previous encode calls.
///
/// This is the main API for performing HPACK encoding of headers.
///
/// # Examples
///
/// Encoding a header two times in a row produces two different
/// representations, due to the utilization of HPACK compression.
///
/// ```rust
/// use solicit::hpack::Encoder;
///
/// let mut encoder = Encoder::new();
///
/// let headers = vec![
///     (b"custom-key".to_vec(), b"custom-value".to_vec()),
/// ];
/// // First encoding...
/// let result = encoder.encode(&headers);
/// // The result is a literal encoding of the header name and value, with an
/// // initial byte representing the type of the encoding
/// // (incremental indexing).
/// assert_eq!(
///     vec![0x40,
///          10, b'c', b'u', b's', b't', b'o', b'm', b'-', b'k', b'e', b'y',
///          12, b'c', b'u', b's', b't', b'o', b'm', b'-', b'v', b'a', b'l',
///          b'u', b'e'],
///     result);
///
/// // Encode the same headers again!
/// let result = encoder.encode(&headers);
/// // The result is simply the index of the header in the header table (62),
/// // with a flag representing that the decoder should use the index.
/// assert_eq!(vec![0x80 | 62], result);
/// ```
pub struct Encoder<'a> {
    /// The header table represents the encoder's context
    header_table: HeaderTable<'a>,
}

impl<'a> Encoder<'a> {
    /// Creates a new `Encoder` with a default static table, as defined by the
    /// HPACK spec (Appendix A).
    pub fn new() -> Encoder<'a> {
        Encoder {
            header_table: HeaderTable::with_static_table(STATIC_TABLE),
        }
    }

    /// Encodes the given headers using the HPACK rules and returns a newly
    /// allocated `Vec` containing the bytes representing the encoded header
    /// set.
    ///
    /// The encoder so far supports only a single, extremely simple encoding
    /// strategy, whereby each header is represented as an indexed header if
    /// already found in the header table and a literal otherwise. When a
    /// header isn't found in the table, it is added if the header name wasn't
    /// found either (i.e. there are never two header names with different
    /// values in the produced header table). Strings are always encoded as
    /// literals (Huffman encoding is not used).
    pub fn encode(&mut self, headers: &Vec<(Vec<u8>, Vec<u8>)>) -> Vec<u8> {
        let mut encoded: Vec<u8> = Vec::new();

        for header in headers.iter() {
            match self.header_table.find_header((&header.0, &header.1)) {
                None => {
                    // The name of the header is in no tables: need to encode
                    // it with both a literal name and value.
                    self.encode_literal(header, true, &mut encoded);
                    self.header_table.add_header(header.0.clone(), header.1.clone());
                },
                Some((index, false)) => {
                    // The name of the header is at the given index, but the
                    // value does not match the current one: need to encode
                    // only the value as a literal.
                    self.encode_literal(header, false, &mut encoded);
                },
                Some((index, true)) => {
                    // The full header was found in one of the tables, so we
                    // just encode the index.
                    self.encode_indexed(index, &mut encoded);
                }
            };
        }

        encoded
    }

    /// Encodes a header as a literal (i.e. both the name and the value are
    /// encoded as a string literal) and places the result in the given buffer
    /// `buf`.
    ///
    /// # Parameters
    ///
    /// - `header` - the header to be encoded
    /// - `should_index` - indicates whether the given header should be indexed, i.e.
    ///                    inserted into the dynamic table
    /// - `buf` - The buffer into which the result is placed
    ///
    fn encode_literal(&mut self,
                      header: &(Vec<u8>, Vec<u8>),
                      should_index: bool,
                      buf: &mut Vec<u8>) {
        let mask = if should_index {
            0x40
        } else {
            0x0
        };

        buf.push(mask);
        self.encode_string_literal(&header.0, buf);
        self.encode_string_literal(&header.1, buf);
    }

    /// Encodes a string literal and places the result in the given buffer
    /// `buf`.
    ///
    /// The function does not consider Huffman encoding for now, but always
    /// produces a string literal representations, according to the HPACK spec
    /// section 5.2.
    fn encode_string_literal(&mut self, octet_str: &[u8], buf: &mut Vec<u8>) {
        buf.extend(encode_integer(octet_str.len(), 7).into_iter());
        buf.extend(octet_str.to_vec().into_iter());
    }

    /// Encodes a header whose name is indexed and places the result in the
    /// given buffer `buf`.
    fn encode_indexed_name(&mut self, header: (usize, &Vec<u8>), should_index: bool, buf: &mut Vec<u8>) {
        let (mask, prefix) = if should_index {
            (0x40, 6)
        } else {
            (0x0, 4)
        };

        let mut encoded_index = encode_integer(header.0, prefix);
        encoded_index[0] |= mask;
        buf.extend(encoded_index.into_iter());
        // So far, we rely on just one strategy for encoding string literals.
        self.encode_string_literal(&header.1, buf);
    }

    /// Encodes an indexed header (a header that is fully in the header table)
    /// and places the result in the given buffer `buf`.
    ///
    /// The encoding is according to the rules of the HPACK spec, section 6.1.
    fn encode_indexed(&self, index: usize, buf: &mut Vec<u8>) {
        let mut encoded = encode_integer(index, 7);
        // We need to set the most significant bit, since the bit-pattern is
        // `1xxxxxxx` for indexed headers.
        encoded[0] |= 0x80;

        buf.extend(encoded.into_iter());
    }
}

#[cfg(test)]
mod tests {
    use super::encode_integer;
    use super::Encoder;

    use super::super::Decoder;

    #[test]
    fn test_encode_integer() {
        assert_eq!(encode_integer(10, 5), [10]);
        assert_eq!(encode_integer(1337, 5), [31, 154, 10]);
        assert_eq!(encode_integer(127, 7), [127, 0]);
    }

    /// A helper function that checks whether the given buffer can be decoded
    /// into a set of headers that corresponds to the given `headers` list.
    /// Relies on using the `solicit::hpack::decoder::Decoder`` struct for
    /// performing the decoding.
    ///
    /// # Returns
    ///
    /// A `bool` indicating whether such a decoding can be performed.
    fn is_decodable(buf: &Vec<u8>, headers: &Vec<(Vec<u8>, Vec<u8>)>) -> bool {
        let mut decoder = Decoder::new();
        match decoder.decode(buf).ok() {
            Some(h) => h == *headers,
            None => false,
        }
    }

    /// Tests that encoding only the `:method` header works.
    #[test]
    fn test_encode_only_method() {
        let mut encoder: Encoder = Encoder::new();
        let headers = vec![
            (b":method".to_vec(), b"GET".to_vec()),
        ];

        let result = encoder.encode(&headers);

        debug!("{:?}", result);
        assert!(is_decodable(&result, &headers));
    }

    /// Tests that when a single custom header is sent it gets indexed by the
    /// coder.
    #[test]
    fn test_custom_header_gets_indexed() {
        let mut encoder: Encoder = Encoder::new();
        let headers = vec![
            (b"custom-key".to_vec(), b"custom-value".to_vec()),
        ];

        let result = encoder.encode(&headers);
        assert!(is_decodable(&result, &headers));
        // The header is in the encoder's dynamic table.
        assert_eq!(encoder.header_table.dynamic_table.to_vec(), headers);
        // ...but also indicated as such in the output.
        assert!(0x40 == (0x40 & result[0]));
        debug!("{:?}", result);
    }

    /// Tests that when a header gets added to the dynamic table, the encoder
    /// will use the index, instead of the literal representation on the next
    /// encoding of the same header.
    #[test]
    fn test_uses_index_on_second_iteration() {
        let mut encoder: Encoder = Encoder::new();
        let headers = vec![
            (b"custom-key".to_vec(), b"custom-value".to_vec()),
        ];
        // First encoding...
        let _ = encoder.encode(&headers);

        // Encode the same headers again!
        let result = encoder.encode(&headers);

        // The header is in the encoder's dynamic table.
        assert_eq!(encoder.header_table.dynamic_table.to_vec(), headers);
        // The output is a single index byte?
        assert_eq!(result.len(), 1);
        // The index is correctly encoded:
        // - The most significant bit is set
        assert_eq!(0x80 & result[0], 0x80);
        // - The other 7 bits decode to an integer giving the index in the full
        //   header address space.
        assert_eq!(result[0] ^ 0x80, 62);
        // The header table actually contains the header at that index?
        assert_eq!(
            encoder.header_table.get_from_table(62).unwrap(),
            (&headers[0].0[..], &headers[0].1[..]));
    }

    /// Tests that multiple headers are correctly encoded (i.e. can be decoded
    /// back to their original representation).
    #[test]
    fn test_multiple_headers_encoded() {
        let mut encoder = Encoder::new();
        let headers = vec![
            (b"custom-key".to_vec(), b"custom-value".to_vec()),
            (b":method".to_vec(), b"GET".to_vec()),
            (b":path".to_vec(), b"/some/path".to_vec()),
        ];

        let result = encoder.encode(&headers);

        assert!(is_decodable(&result, &headers));
    }
}
