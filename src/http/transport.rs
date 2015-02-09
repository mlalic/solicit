//! The module contains implementations of the transport layer functionality
//! that HTTP/2 requires. It exposes APIs that allow the HTTP/2 connection to
//! use the transport layer without requiring it to know which exact
//! implementation they are using (i.e. a clear-text TCP connection, a TLS
//! protected connection, or even a mock implementation).
