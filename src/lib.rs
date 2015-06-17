#![doc(html_root_url="https://mlalic.github.io/solicit/")]

#[macro_use] extern crate log;
extern crate hpack;
#[cfg(feature="tls")] extern crate openssl;

pub mod http;
pub mod client;
pub mod server;

mod tests {
}
