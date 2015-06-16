# solicit

[![Travis Build Status](https://img.shields.io/travis/mlalic/solicit/master.svg?style=flat-square&label=Travis%20Build)](https://travis-ci.org/mlalic/solicit)
[![AppVeyor Build Status](https://img.shields.io/appveyor/ci/mlalic/solicit/master.svg?style=flat-square&label=AppVeyor%20Build)](https://ci.appveyor.com/project/mlalic/solicit)
[![Crates.io](https://img.shields.io/crates/v/solicit.svg?style=flat-square)](https://crates.io/crates/solicit)

An HTTP/2 implementation in Rust.

[API Documentation](https://mlalic.github.io/solicit/)

# Goals

The main goal of the project is to provide a low-level implementation of the
HTTP/2 protocol and expose it in a way that higher-level libraries can make use
of it. For example, it should be possible for a higher level libary to write a
simple adapter that exposes the responses obtained over an HTTP/2 connection in
the same manner as those obtained over HTTP/1.1.

The API should make it possible to use an HTTP/2 connection at any level --
everything from sending and managing individual HTTP/2 frames to only
manipulating requests and responses -- depending on the needs of the end users
of the library.

The core of the library should be decoupled from the particulars of the
underlying IO -- it should be possible to use the same APIs regardless if the
IO is evented or blocking. In the same time, the library provides convenience
adapters that allow the usage of Rust's standard library socket IO as the
transport layer out of the box.

Extensive test coverage is also a major goal. No code is committed without
accompanying tests.

At this stage, performance was not considered as one of the primary goals.

# Examples

As mentioned in the goals section, this library does not aim to provide a
full high-level client or server implementation (no caching, no automatic
redirect following, no strongly-typed headers, etc.).

However, in order to demonstrate how such components could be built or provide
a baseline for less demanding versions of the same, implementations of a limited
client and server are included in the crate (the modules `solicit::client` and
`solicit::server`, respectively).

## Simple Client

The [simple client](https://github.com/mlalic/solicit/blob/master/src/client/simple.rs)
implementation allows users to issue a number of requests before blocking to
read one of the responses. After a response is received, more requests can
be sent over the same connection; however, requests cannot be queued while a
response is being read.

In a way, this is similar to how HTTP/1.1 connections with keep-alive (and
pipelining) work.

### Example

A clear-text (`http://`) connection.

```rust
extern crate solicit;
use solicit::http::client::CleartextConnector;
use solicit::client::SimpleClient;
use std::str;

fn main() {
  // Connect to an HTTP/2 aware server
  let connector = CleartextConnector::new("http2bin.org");
  let mut client = SimpleClient::with_connector(connector).unwrap();
  let response = client.get(b"/get", &[]).unwrap();
  assert_eq!(response.stream_id, 1);
  assert_eq!(response.status_code().unwrap(), 200);
  // Dump the headers and the response body to stdout.
  // They are returned as raw bytes for the user to do as they please.
  // (Note: in general directly decoding assuming a utf8 encoding might not
  // always work -- this is meant as a simple example that shows that the
  // response is well formed.)
  for header in response.headers.iter() {
    println!("{}: {}",
        str::from_utf8(&header.0).unwrap(),
        str::from_utf8(&header.1).unwrap());
  }
  println!("{}", str::from_utf8(&response.body).unwrap());
  // We can issue more requests after reading this one...
  // These calls block until the request itself is sent, but do not wait
  // for a response.
  let req_id1 = client.request(b"GET", b"/get?hi=hello", &[], None).unwrap();
  let req_id2 = client.request(b"GET", b"/asdf", &[], None).unwrap();
  // Now we get a response for both requests... This does block.
  let (resp1, resp2) = (
      client.get_response(req_id1).unwrap(),
      client.get_response(req_id2).unwrap(),
  );
  assert_eq!(resp1.status_code().unwrap(), 200);
  assert_eq!(resp2.status_code().unwrap(), 404);
}
```

A TLS-protected (and negotiated) `https://` connection. The only difference is
in the type of the connector provided to the `SimpleClient`.

Requires the `tls` feature of the crate.

```rust
extern crate solicit;
use solicit::http::client::tls::TlsConnector;
use solicit::client::SimpleClient;
use std::str;

fn main() {
  // Connect to an HTTP/2 aware server
  let path = "/path/to/certs.pem";
  let connector = TlsConnector::new("http2bin.org", &path);
  let mut client = SimpleClient::with_connector(connector).unwrap();
  let response = client.get(b"/get", &[]).unwrap();
  assert_eq!(response.stream_id, 1);
  assert_eq!(response.status_code().unwrap(), 200);
  // Dump the headers and the response body to stdout.
  // They are returned as raw bytes for the user to do as they please.
  // (Note: in general directly decoding assuming a utf8 encoding might not
  // always work -- this is meant as a simple example that shows that the
  // response is well formed.)
  for header in response.headers.iter() {
    println!("{}: {}",
        str::from_utf8(&header.0).unwrap(),
        str::from_utf8(&header.1).unwrap());
  }
  println!("{}", str::from_utf8(&response.body).unwrap());
}
```

For how it leverages the `solicit::http` API for its implementation, check out the
[`solicit::client::simple`](https://github.com/mlalic/solicit/blob/master/src/client/simple.rs)
module.

## Async Client

The [async client](https://github.com/mlalic/solicit/blob/master/src/client/async.rs)
leverages more features specific to HTTP/2, as compared to HTTP/1.1.

It allows multiple clients to issue requests to the same underlying
connection concurrently. The responses are returned to the clients in the form
of a `Future`, allowing them to block on waiting for the response only once
they don't have anything else to do (which could be immediately after issuing
it).

This client spawns one background thread per HTTP/2 connection, which exits
gracefully once there are no more clients connected to it (and thus no more
potential requests can be issued) or the HTTP/2 connection returns an error.

This client implementation is also just an example of what can be achieved
using the `solicit::htp` API -- see:
[`solicit::client::async`](https://github.com/mlalic/solicit/blob/master/src/client/async.rs)

### Example

```rust
extern crate solicit;

use solicit::client::Client;
use solicit::http::client::CleartextConnector;
use std::thread;
use std::str;

fn main() {
  // Connect to a server that supports HTTP/2
  let connector = CleartextConnector::new(host: "http2bin.org");
  let client = Client::with_connector(connector).unwrap();

  // Issue 5 requests from 5 different threads concurrently and wait for all
  // threads to receive their response.
  let threads: Vec<_> = (0..5).map(|i| {
      let this = client.clone();
      thread::spawn(move || {
          let resp = this.get(b"/get", &[(b"x-thread".to_vec(), vec![b'0' + i])]).unwrap();
          let response = resp.recv().unwrap();

          println!("Thread {} got response ... {}", i, response.status_code().ok().unwrap());

          response
      })
      }).collect();

  let responses: Vec<_> = threads.into_iter().map(|thread| thread.join())
                                             .collect();

  println!("All threads joined. Full responses are:");
  for response in responses.into_iter() {
      let response = response.unwrap();
      println!("The response contains the following headers:");
      for header in response.headers.iter() {
          println!("  {}: {}",
                   str::from_utf8(&header.0).unwrap(),
                   str::from_utf8(&header.1).unwrap());
      }
      println!("{}", str::from_utf8(&response.body).unwrap());
  }
}
```

## Simple Server

The simple server implementation works similarly to the `SimpleClient`; this
server implementation is fully single-threaded: no responses can be written
while reading a request (and vice-versa). It does show how the API can be used
to implement an HTTP/2 server, though.

Provided by the [`solicit::server`](https://github.com/mlalic/solicit/blob/master/src/server/mod.rs)
module.

### Example

A server that echoes the body of each request that it receives.

```rust
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
    for stream in listener.incoming() {
        let stream = stream.unwrap();
        thread::spawn(move || {
            handle_client(stream)
        });
    }
}
```

# License

The project is published under the terms of the [MIT License](https://github.com/mlalic/solicit/blob/master/LICENSE).
