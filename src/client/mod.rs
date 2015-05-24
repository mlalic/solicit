//! The module contains implementations of HTTP/2 clients that could be
//! directly used to access HTTP/2 servers, i.e. send requests and read
//! responses.

pub use self::simple::SimpleClient;
pub use self::async::Client;

mod simple;
mod async;
#[cfg(test)] mod tests;
