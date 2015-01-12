/// A module exposing utilities for encoding and decoding Huffman-coded octet
/// strings, under the Huffman code defined by HPACK.
/// (HPACK-draft-10, Appendix B)

use std::collections::HashMap;

/// Represents a symbol that can be inserted into a Huffman-encoded octet
/// string.
enum HuffmanCodeSymbol {
    /// Any octet is a valid symbol
    Symbol(u8),
    /// A special symbol represents the end of the string
    EndOfString,
}

impl HuffmanCodeSymbol {
    pub fn new(symbol: usize) -> HuffmanCodeSymbol {
        if symbol == 256 {
            HuffmanCodeSymbol::EndOfString
        } else {
            // It is safe to downcast since now we know that the value
            // is in the half-open interval [0, 256)
            HuffmanCodeSymbol::Symbol(symbol as u8)
        }
    }
}

/// A helper struct that represents an iterator over individual bits of all
/// bytes found in a wrapped Iterator over bytes.
/// Bits are represented as `bool`s, where `true` corresponds to a set bit and
/// `false` to a 0 bit.
///
/// Bits are yielded in order of significance, starting from the
/// most-significant bit.
struct BitIterator<'a, I: Iterator> {
    buffer_iterator: I,
    current_byte: Option<&'a u8>,
    /// The bit-position within the current byte
    pos: u8,
}

impl<'a, I: Iterator> BitIterator<'a, I>
        where I: Iterator<Item=&'a u8> {
    pub fn new(iterator: I) -> BitIterator<'a, I> {
        BitIterator::<'a, I> {
            buffer_iterator: iterator,
            current_byte: None,
            pos: 7,
        }
    }
}

impl<'a, I> Iterator for BitIterator<'a, I>
        where I: Iterator<Item=&'a u8> {
    type Item = bool;

    fn next(&mut self) -> Option<bool> {
        if self.current_byte.is_none() {
            self.current_byte = self.buffer_iterator.next();
            self.pos = 7;
        }

        // If we still have `None`, it means the buffer has been exhausted
        if self.current_byte.is_none() {
            return None;
        }

        let b = *self.current_byte.unwrap();

        let is_set = (b & (1 << self.pos)) == (1 << self.pos);
        if self.pos == 0 {
            // We have exhausted all bits from the current byte -- try to get
            // a new one on the next pass.
            self.current_byte = None;
        } else {
            // Still more bits left here...
            self.pos -= 1;
        }

        Some(is_set)
    }
}

mod tests {
    use super::BitIterator;

    /// A helper function that converts the given slice containing values `1`
    /// and `0` to a `Vec` of `bool`s, according to the number.
    fn to_expected_bit_result(numbers: &[u8]) -> Vec<bool> {
        numbers.iter().map(|b| -> bool {
            *b == 1
        }).collect()
    }

    #[test]
    fn test_bit_iterator_single_byte() {
        let expected_result = to_expected_bit_result(
            &[0, 0, 0, 0, 1, 0, 1, 0]);

        let mut res: Vec<bool> = Vec::new();
        for b in BitIterator::new(vec![10u8].iter()) {
            res.push(b);
        }

        assert_eq!(res, expected_result);
    }

    #[test]
    fn test_bit_iterator_multiple_bytes() {
        let expected_result = to_expected_bit_result(
            &[0, 0, 0, 0, 1, 0, 1, 0,
              1, 1, 1, 1, 1, 1, 1, 1,
              1, 0, 0, 0, 0, 0, 0, 0,
              0, 0, 0, 0, 0, 0, 0, 1,
              0, 0, 0, 0, 0, 0, 0, 0,
              1, 0, 1, 0, 1, 0, 1, 0]);

        let mut res: Vec<bool> = Vec::new();
        for b in BitIterator::new(vec![10u8, 255, 128, 1, 0, 170].iter()) {
            res.push(b);
        }

        assert_eq!(res, expected_result);
    }
}
