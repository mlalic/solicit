//! An example of usage of the `solicit::server::SimpleServer` API.
//!
//! It spawns a new dedicated thread for handling each new HTTP/2 connection (which corresponds to
//! a single TCP connection). Within that thread, all requests that are received are handled
//! sequentially, returning identical dummy "Hello, World!" responses.
//!
//! Only for demonstration purposes.

extern crate solicit;

use std::str;
use std::net::{TcpListener, TcpStream};
use std::thread;

use solicit::http::Response;
use solicit::server::SimpleServer;

fn main() {
    fn handle_client(stream: TcpStream) {
        let mut server = SimpleServer::new(stream, |req| {
            println!("Received request:");
            for header in req.headers.iter() {
                println!("  {}: {}",
                str::from_utf8(&header.0).unwrap(),
                str::from_utf8(&header.1).unwrap());
            }
            println!("Body:\n{}", str::from_utf8(&req.body).unwrap());

            // Return a dummy response for every request
            Response {
                headers: vec![
                    (b":status".to_vec(), b"200".to_vec()),
                    (b"x-solicit".to_vec(), b"Hello, World!".to_vec()),
                ],
                body: req.body.to_vec(),
                stream_id: req.stream_id,
           }
        }).unwrap();
        while let Ok(_) = server.handle_next() {}
        println!("Server done (client disconnected)");
    }

    let listener = TcpListener::bind("127.0.0.1:8080").unwrap();
    println!("Server started on 127.0.0.1:8080...");
    println!("Waiting for clients...");
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        println!("New client connected!");
        thread::spawn(move || {
            handle_client(stream)
        });
    }
}
