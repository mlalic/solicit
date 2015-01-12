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


mod tests {
    use super::{decode_integer};

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

}
