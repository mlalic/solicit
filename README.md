# solicit
[![Build Status](https://travis-ci.org/mlalic/solicit.svg?branch=master)](https://travis-ci.org/mlalic/solicit)

An HTTP/2 implementation in Rust.

[API Documentation](https://mlalic.github.io/solicit/)

# Goals

The main goal of the project is to provide a low-level implementation of the
client side of the HTTP/2 protocol and expose it in a way that higher-level
libraries can make use of it. For example, it should be possible for a higher
level libary to write a very simple adapter that exposes the responses
obtained over an HTTP/2 connection in the same manner as those obtained over
HTTP/1.1.

The exposed API should make it possible to customize any stage of handling
an HTTP/2 response, such as adding custom handlers for partial response data
(to make it viable to either save the response in memory, stream it to a
file, or just notify a different process on every new chunk or even something
else entirely).

The library itself should never spawn any threads, but the primitives exposed
by it should be flexible enough to allow a multi-threaded client implementation
(one where requests can be made from different threads, using the same underlying
HTTP/2 connection).

Extensive test coverage is also a major goal. No code is committed without
accompanying tests.

At this stage, performance was not considered as one of the primary goals.

# Status

Only a small subset of the full HTTP/2 spec is implemented so far, however it
is already possible to issue requests and read their corresponding responses.

The only caveat is that (for now) only HTTP/2 connections over clear-text TCP
are supported. Implementing a TLS protected (and negotiated) connection is the
next planned feature.

Some features that are implemented:

- Connection establishment: only prior knowledge connections (implying a cleartext TCP
  transport-layer connection)
- HPACK compression and decompression: based on the
  [`hpack-rs`](https://github.com/mlalic/hpack-rs) crate (which was extracted from
  `solicit`).
- The framing layer correctly handles incoming frames, discarding frame types for which
  the handling (parsing, processing) is not yet implemented.
  Handling is implemented for `DATA`, `HEADERS`, and `SETTINGS` frames.
- Frame serialization is also implemented for the aforementioned 3 frame types.


# Examples

As mentioned in the goals section, this library does not aim to provide a
full high-level client implementation (no caching, no automatic redirect
following, no strongly-typed headers, etc.). Rather, it implements the lower
level details of an HTTP/2 connection -- what is essentially an additional
transport layer on top of the socket connection -- and exposes an API that
allows a full-featured client to be built on top of that.

However, in order to showcase how such clients might be built and in order to
make sure that the main goals for such clients are achievable, there are two
example implementations (included in the
[`solicit::client`](https://github.com/mlalic/solicit/blob/master/src/client/mod.rs)
module) built on top of the underlying abstractions of the
[`solicit::http`](https://github.com/mlalic/solicit/blob/master/src/http/mod.rs)
module.

## Simple Client

The [simple client](https://github.com/mlalic/solicit/blob/master/src/client/simple.rs)
implementation allows users to issue a number of requests before blocking to
read one of the responses. After a response is received, more requests can
be sent over the same connection; however, requests cannot be queued while a
response is being read.

In a way, this is similar to how HTTP/1.1 connections with keep-alive (and
pipelining) work.

### Example

```rust
use solicit::client::SimpleClient;
use std::str;
// Connect to an HTTP/2 aware server
let mut client = SimpleClient::connect("nghttp2.org", 80).ok().unwrap();
// This blocks until the response is received...
let response = client.get(b"/", &[]).unwrap();
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
let req_id1 = client.request(b"GET", b"/", &[]).unwrap();
let req_id2 = client.request(b"GET", b"/asdf", &[]).unwrap();
// Now we get a response for both requests... This does block.
let (resp1, resp2) = (
    client.get_response(req_id1).unwrap(),
    client.get_response(req_id2).unwrap(),
);
assert_eq!(resp1.status_code().unwrap(), 200);
assert_eq!(resp2.status_code().unwrap(), 404);
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
#![feature(std_misc)]

use solicit::client::Client;
use std::thread;
use std::str;

// Connect to a server that supports HTTP/2
let client = Client::new("nghttp2.org", 80).unwrap();

// Issue 5 requests from 5 different threads concurrently and wait for all
// threads to receive their response.
let _: Vec<_> = (0..5).map(|i| {
    let this = client.clone();
    thread::scoped(move || {
        // This call returns immediately...
        let resp = this.get(b"/", &[]).unwrap();
        // ...this one blocks until the full response is ready!
        let response = resp.into_inner();
        println!("Thread {} got response ... {}", i, response.status_code().unwrap());
        println!("The response contains the following headers:");
        for header in response.headers.iter() {
            println!("  {}: {}",
                  str::from_utf8(&header.0).unwrap(),
                  str::from_utf8(&header.1).unwrap());
        }
    })
}).collect();
```

# License

The project is published under the terms of the [MIT License](https://github.com/mlalic/solicit/blob/master/LICENSE).
