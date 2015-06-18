//! An example of usage of the `solicit::client::SimpleClient` API.
//!
//! This is a simple implementation of an HTTP/2 client, built on top of the API of `solicit::http`
//! that performs all IO in the main thread.

extern crate solicit;

use std::env;
use std::str;

use solicit::http::Response;
use solicit::http::client::CleartextConnector;
use solicit::client::SimpleClient;

fn fetch(host: &str, port: u16, paths: &[String]) -> Vec<Response> {
    let mut client = SimpleClient::with_connector(CleartextConnector::with_port(host, port)).unwrap();
    paths.iter().map(|path| client.get(path.as_bytes(), &[]).unwrap()).collect()
}

fn main() {
    fn print_usage() {
        println!("Usage: client_simple <host>[:<port>] <path> [<path>...]");
        println!(
            "NOTE: The example does not accept URLs, rather the host name and a list of paths");
    }

    let host = env::args().nth(1);
    let paths: Vec<_> = env::args().skip(2).collect();

    if host.is_none() || paths.is_empty() {
        print_usage();
        return;
    }
    let host = host.unwrap();
    // Split off the port, if present
    let parts: Vec<_> = host.split(":").collect();
    if parts.len() > 2 {
        println!("Invalid host!");
        print_usage();
        return;
    }

    let (host, port) = if parts.len() == 1 {
        (parts[0], 80)
    } else {
        let port = match str::FromStr::from_str(parts[1]) {
            Err(_) => {
                println!("Invalid host (invalid port given)");
                print_usage();
                return;
            },
            Ok(port) => port,
        };
        (parts[0], port)
    };

    let responses = fetch(&host, port, &paths);
    for (path, response) in paths.iter().zip(responses) {
        println!("Request path: {}", path);

        println!("  status == {}", response.status_code().unwrap());
        // Dump the headers and the response body to stdout.
        // They are returned as raw bytes for the user to do as they please.
        // (Note: in general directly decoding assuming a utf8 encoding might not
        // always work -- this is meant as a simple example that shows that the
        // response is well formed.)
        for header in response.headers.iter() {
            println!("  {}: {}",
                     str::from_utf8(&header.0).unwrap(),
                     str::from_utf8(&header.1).unwrap());
        }
        println!("");
        println!("{}", str::from_utf8(&response.body).unwrap());
    }
}
