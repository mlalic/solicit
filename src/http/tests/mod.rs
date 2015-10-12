#[cfg(test)]
pub mod common;

/// Tests for the structs defined in the root of the `solicit::http` module.
#[cfg(test)]
mod root_tests {
    use http::{Response, HttpError, HttpScheme};

    /// Tests that the `Response` struct correctly parses a status code from
    /// its headers list.
    #[test]
    fn test_parse_status_code_response() {
        {
            // Only status => Ok
            let resp = Response::new(
                1,
                vec![(b":status".to_vec(), b"200".to_vec())],
                vec![]);
            assert_eq!(resp.status_code().ok().unwrap(), 200);
        }
        {
            // Extra headers => still works
            let resp = Response::new(
                1,
                vec![(b":status".to_vec(), b"200".to_vec()),
                (b"key".to_vec(), b"val".to_vec())],
                vec![]);
            assert_eq!(resp.status_code().ok().unwrap(), 200);
        }
        {
            // Status is not the first header => malformed
            let resp = Response::new(
                1,
                vec![(b"key".to_vec(), b"val".to_vec()),
                (b":status".to_vec(), b"200".to_vec())],
                vec![]);
            assert_eq!(resp.status_code().err().unwrap(),
            HttpError::MalformedResponse);
        }
        {
            // No headers at all => Malformed
            let resp = Response::new(1, vec![], vec![]);
            assert_eq!(resp.status_code().err().unwrap(),
            HttpError::MalformedResponse);
        }
    }

    /// Tests that the `HttpScheme` enum returns the correct scheme strings for
    /// the two variants.
    #[test]
    fn test_scheme_string() {
        assert_eq!(HttpScheme::Http.as_bytes(), b"http");
        assert_eq!(HttpScheme::Https.as_bytes(), b"https");
    }

    /// Make sure that the `HttpError` is both `Sync` and `Send`
    #[test]
    fn _assert_error_is_sync_send() {
        fn _is_sync_send<T: Sync + Send>() {}
        _is_sync_send::<HttpError>();
    }
}

#[cfg(test)]
mod test_header {
    use http::{Header, OwnedHeader};
    use std::borrow::Cow;

    fn _assert_is_static(_: Header<'static, 'static>) {}

    #[test]
    fn test_owned_to_header_is_static_lifetime() {
        let owned = (vec![1u8], vec![2u8]);
        _assert_is_static(owned.into());
    }

    #[test]
    fn test_header_from_static_slices_lifetime() {
        let header = Header::new(b":method", b"GET");
        _assert_is_static(header);
    }

    #[test]
    fn test_header_to_owned_header() {
        let header = Header::new(b":method", b"GET");
        let (name, value): OwnedHeader = header.into();

        assert_eq!(name, b":method".to_vec());
        assert_eq!(value, b"GET".to_vec());
    }

    #[test]
    fn test_partial_eq_of_headers() {
        let fully_static = Header::new(b":method", b"GET");
        let static_name = Header::new(b":method", b"GET".to_vec());
        let other = Header::new(b":path", b"/");

        assert!(fully_static == static_name);
        assert!(fully_static != other);
        assert!(static_name != other);
    }

    #[test]
    fn test_partial_eq_to_owned_header() {
        let fully_static = Header::new(b":method", b"GET");
        let owned: OwnedHeader = fully_static.clone().into();

        assert!(fully_static == owned);
    }

    #[test]
    fn test_clone_keeps_borrows() {
        let header = Header::new(b":method", b"GET");
        let clone = header.clone();

        match clone.name {
            Cow::Owned(_) => panic!("Expected a borrowed name"),
            _ => {},
        };
        match clone.value {
            Cow::Owned(_) => panic!("Expected a borrowed value"),
            _ => {},
        };
    }
}
