//! Tests for the `solict::client` module.

#[cfg(feature="live_tests")]
mod simple {
    use http::{Response, HttpError};
    use http::client::CleartextConnector;
    use client::SimpleClient;
    use std::str;

    /// The function establishes a (prior knowledge clear-text TCP) HTTP/2 connection to the given
    /// host and GETs the resource at the given paths. Returns a list of responses
    fn get(host: &str, paths: &[String]) -> Vec<Response> {
        let mut client = SimpleClient::with_connector(CleartextConnector::new(host)).unwrap();
        paths.iter().map(|path| client.get(path.as_bytes(), &[]).unwrap()).collect()
    }

    #[test]
    fn test_live_get() {
        let paths = vec![
            "/get".into(),
            "/status/404".into(),
            "/status/418".into(),
        ];
        let res = get("http2bin.org", &paths);
        let statuses: Vec<_> = res.into_iter().map(|r| r.status_code().unwrap()).collect();

        assert_eq!(statuses, vec![200, 404, 418]);
    }

    #[test]
    fn test_live_post() {
        let host = "http2bin.org";
        let mut client = SimpleClient::with_connector(CleartextConnector::new(host)).unwrap();

        let res = client.post(b"/post", &[], b"Hello, World!".to_vec()).unwrap();

        let body = str::from_utf8(&res.body).unwrap();
        assert!(body.contains("Hello, World!"));
    }

    /// Tests that `with_connector` returns an error when the connector is unable to establish a
    /// new connection.
    #[test]
    fn test_error_on_connect_failure() {
        let connector = CleartextConnector::new("unknown.host.name.lcl");
        let client = SimpleClient::with_connector(connector);

        assert!(client.is_err());
        assert!(match client.err().unwrap() {
            HttpError::Other(_) => true,
            _ => false,
        });
    }
}

#[cfg(feature="live_tests")]
mod async {
    use std::str;
    use std::thread;

    use http::Response;
    use http::client::CleartextConnector;
    use client::Client;

    /// The function establishes a (prior knowledge clear-text TCP) HTTP/2 connection to the given
    /// host and GETs the resource at the given paths. Returns a list of responses.
    ///
    /// The requests are all issued concurrently (spawning as many threads as there are requests).
    fn get(host: &str, paths: &[String]) -> Vec<Response> {
        let client = Client::with_connector(CleartextConnector::new(host)).unwrap();
        let threads: Vec<_> = paths.iter().map(|path| {
            let this = client.clone();
            let path = path.clone();
            thread::spawn(move || {
                this.get(path.as_bytes(), &[]).unwrap().recv().unwrap()
            })
        }).collect();

        threads.into_iter().map(|t| t.join().unwrap()).collect()
    }

    #[test]
    fn test_live_get() {
        let paths = vec![
            "/get".into(),
            "/status/404".into(),
            "/status/418".into(),
        ];
        let res = get("http2bin.org", &paths);
        let statuses: Vec<_> = res.into_iter().map(|r| r.status_code().unwrap()).collect();

        assert_eq!(statuses, vec![200, 404, 418]);
    }

    #[test]
    fn test_live_post() {
        let host = "http2bin.org";
        let client = Client::with_connector(CleartextConnector::new(host)).unwrap();

        let res = client.post(b"/post", &[], b"Hello, World!".to_vec()).unwrap();
        let res = res.recv().unwrap();

        let body = str::from_utf8(&res.body).unwrap();
        assert!(body.contains("Hello, World!"));
    }
}
