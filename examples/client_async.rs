extern crate solicit;

use solicit::http::Header;
use solicit::client::Client;
use solicit::http::client::CleartextConnector;
use std::thread;
use std::str;

fn main() {
    // Connect to a server that supports HTTP/2
    let connector = CleartextConnector::new("http2bin.org");
    let client = Client::with_connector(connector).unwrap();

    // Issue 5 requests from 5 different threads concurrently and wait for all
    // threads to receive their response.
    let threads: Vec<_> = (0..5).map(|i| {
        let this = client.clone();
        thread::spawn(move || {
            let resp = this.get(b"/get", &[
                // A fully static header
                Header::new(&b"x-solicit"[..], &b"Hello"[..]),
                // A header with a static name, but dynamically allocated value
                Header::new(&b"x-solicit"[..], vec![b'0' + i as u8]),
            ]).unwrap();
            let response = resp.recv().unwrap();
            println!("Thread {} got response ... {}", i, response.status_code().ok().unwrap());
            println!("The response contains the following headers:");
            for header in response.headers.iter() {
                println!("  {}: {}",
                      str::from_utf8(header.name()).unwrap(),
                      str::from_utf8(header.value()).unwrap());
            }
            println!("Body:");
            println!("{}", str::from_utf8(&response.body).unwrap());
        })
    }).collect();

    let _: Vec<_> = threads.into_iter().map(|thread| thread.join()).collect();
}
