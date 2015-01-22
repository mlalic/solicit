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
}

#[cfg(test)]
mod tests {
    use super::encode_integer;

    #[test]
    fn test_encode_integer() {
        assert_eq!(encode_integer(10, 5), [10]);
        assert_eq!(encode_integer(1337, 5), [31, 154, 10]);
        assert_eq!(encode_integer(127, 7), [127, 0]);
    }
}
