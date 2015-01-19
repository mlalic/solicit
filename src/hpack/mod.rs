// Publicly exposes the `Decoder` directly from the module.
use std::fmt;
use std::collections::RingBuf;

pub use self::decoder::Decoder;

pub mod encoder;
pub mod decoder;
pub mod huffman;

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
                        // Can never happen as the size of the table must reach
                        // 0 by the time we've exhausted all elements.
                        panic!("Size of table != 0, but no headers left!");
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
    fn to_vec(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
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

/// Represents the type of the static table, as defined by the HPACK spec.
type StaticTable<'a> = &'a [(&'a [u8], &'a [u8])];

/// The struct represents the header table obtained by merging the static and
/// dynamic tables into a single index address space, as described in section
/// `2.3.3.` of the HPACK spec.
struct HeaderTable<'a> {
    static_table: StaticTable<'a>,
    dynamic_table: DynamicTable,
}

impl<'a> HeaderTable<'a> {
    /// Creates a new header table where the static part is initialized with
    /// the given static table.
    pub fn with_static_table(static_table: StaticTable<'a>) -> HeaderTable<'a> {
        HeaderTable {
            static_table: static_table,
            dynamic_table: DynamicTable::new(),
        }
    }

    /// Adds the given header to the table. Of course, this means that the new
    /// header is added to the dynamic part of the table.
    ///
    /// If the size of the new header is larger than the current maximum table
    /// size of the dynamic table, the effect will be that the dynamic table
    /// gets emptied and the new header does *not* get inserted into it.
    #[inline]
    pub fn add_header(&mut self, name: Vec<u8>, value: Vec<u8>) {
        self.dynamic_table.add_header(name, value);
    }

    /// Returns a reference to the header (a `(name, value)` pair) with the
    /// given index in the table.
    ///
    /// The table is 1-indexed and constructed in such a way that the first
    /// entries belong to the static table, followed by entries in the dynamic
    /// table. They are merged into a single index address space, though.
    ///
    /// This is according to the [HPACK spec, section 2.3.3.]
    /// (http://http2.github.io/http2-spec/compression.html#index.address.space)
    pub fn get_from_table(&self, index: usize)
            -> Option<(&[u8], &[u8])> {
        // The IETF defined table indexing as 1-based.
        // So, before starting, make sure the given index is within the proper
        // bounds.
        let real_index = if index > 0 {
            index - 1
        } else {
            return None
        };

        if real_index < self.static_table.len() {
            // It is in the static table so just return that...
            Some(self.static_table[real_index])
        } else {
            // Maybe it's in the dynamic table then?
            let dynamic_index = real_index - self.static_table.len();
            if dynamic_index < self.dynamic_table.len() {
                match self.dynamic_table.get(dynamic_index) {
                    Some(&(ref name, ref value)) => {
                        Some((&name[0..], &value[0..]))
                    },
                    None => None
                }
            } else {
                // Index out of bounds!
                None
            }
        }
    }
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

#[cfg(test)]
mod tests {
    use super::DynamicTable;
    use super::HeaderTable;
    use super::STATIC_TABLE;

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
        assert_eq!(table.to_vec(), vec![
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
        assert_eq!(0, table.to_vec().len());
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
        assert_eq!(table.to_vec(), vec![
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
        assert_eq!(0, table.to_vec().len());
        assert_eq!(0, table.get_size());
        assert_eq!(0, table.get_max_table_size());
    }

    /// Tests that when the initial max size of the table is 0, nothing
    /// can be added to the table.
    #[test]
    fn test_dynamic_table_max_size_zero() {
        let mut table = DynamicTable::with_size(0);

        table.add_header(b"a".to_vec(), b"b".to_vec());

        assert_eq!(0, table.len());
        assert_eq!(0, table.to_vec().len());
        assert_eq!(0, table.get_size());
        assert_eq!(0, table.get_max_table_size());
    }

    /// Tests that indexing the header table with indices that correspond to
    /// entries found in the static table works.
    #[test]
    fn test_header_table_index_static() {
        let table = HeaderTable::with_static_table(STATIC_TABLE);

        for (index, entry) in STATIC_TABLE.iter().enumerate() {
            assert_eq!(table.get_from_table(index + 1).unwrap(), *entry);
        }
    }

    /// Tests that when the given index is out of bounds, the `HeaderTable`
    /// returns a `None`
    #[test]
    fn test_header_table_index_out_of_bounds() {
        let table = HeaderTable::with_static_table(STATIC_TABLE);

        assert!(table.get_from_table(0).is_none());
        assert!(table.get_from_table(STATIC_TABLE.len() + 1).is_none());
    }

    /// Tests that adding entries to the dynamic table through the
    /// `HeaderTable` interface works.
    #[test]
    fn test_header_table_add_to_dynamic() {
        let mut table = HeaderTable::with_static_table(STATIC_TABLE);
        let header = (b"a".to_vec(), b"b".to_vec());

        table.add_header(header.0.clone(), header.1.clone());

        assert_eq!(table.dynamic_table.to_vec(), vec![header]);
    }

    /// Tests that indexing the header table with indices that correspond to
    /// entries found in the dynamic table works.
    #[test]
    fn test_header_table_index_dynamic() {
        let mut table = HeaderTable::with_static_table(STATIC_TABLE);
        let header = (b"a".to_vec(), b"b".to_vec());

        table.add_header(header.0.clone(), header.1.clone());

        assert_eq!(table.get_from_table(STATIC_TABLE.len() + 1).unwrap(),
                   ((&header.0[0..], &header.1[0..])));
    }
}
