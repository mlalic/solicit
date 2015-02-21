# solicit
[![Build Status](https://travis-ci.org/mlalic/solicit.svg?branch=master)](https://travis-ci.org/mlalic/solicit)

An HTTP/2 implementation in Rust

# Goals

The main goal of the project is to provide a low-level implementation of the
client side of the HTTP/2 protocol and expose it in a way that higher-level
libraries can make use of it. For example, it should be possible for a higher
level libary to write a very simple adapter that exposes the responses
obtained over an HTTP/2 connection in the same manner as those obtained over
HTTP/1.1.

The library itself should never spawn any threads, but the primitives exposed
by it should be flexible enough to allow a multi-threaded client implementation
(one where requests can be made from different threads, using the same underlying
HTTP/2 connection).

Extensive test coverage is also a major goal. No code is comitted without
accompanying tests.

At this stage, performance was not considered as one of the primary goals.

# Status

A subset of functionality that is already implemented and a *small* subset of
some that still is not:

- The libarary already provides full support for HPACK draft-16 decoding.
  It is tested for interoperability with libraries that have published their
  encoding results of stories at [http2jp/hpack-test-case](https://github.com/http2jp/hpack-test-case).
- The HPACK encoder only supports a simple encoding strategy and no Huffman-coding
  is ever used.
- The framing layer correctly handles incoming frames, discarding frame types for which
  the handling (parsing, processing) is not yet implemented.
  Handling is implemented for `DATA`, `HEADERS`, and `SETTINGS` frames.
- Frame serialization is also implemented for the aforementioned 3 frame types.
- No connection-level error handling or signalling is implemented, e.g. `RST_STREAM` frames
  are not sent when a stream error is detected.
- Requests with no body can be sent and their subsequent responses retrieved
  (barring any stream-errors, which would go unnoticed).

This just goes to show that what is here is a work in progress, but that already
allows at least a glimpse at how it can be used to perform real HTTP/2
request.

# License

The project is published under the terms of the [MIT License](https://github.com/mlalic/solicit/blob/master/LICENSE).
