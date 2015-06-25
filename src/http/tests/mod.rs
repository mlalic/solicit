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
