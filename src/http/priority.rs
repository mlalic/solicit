//! The module exposes an API for defining data prioritization strategies.
//!
//! Types that implement the `DataPrioritizer` trait can be used to provide new data for an
//! `HttpConnection` to send to its peer. Neither the `HttpConnection` nor the `DataPrioritizer`
//! have control over exactly *when* the data is sent. This is left up to the particular client
//! implementations to trigger.

use http::{HttpResult};
use http::connection::{
    DataChunk,
};

/// A trait that types that want to provide data to an HTTP/2 connection need to implement.
pub trait DataPrioritizer {
    /// Returns the next `DataChunk` that should be sent on the HTTP/2 connection. `None` indicates
    /// that currently there was no data that could be sent at that point.
    fn get_next_chunk(&mut self) -> HttpResult<Option<DataChunk>>;
}
