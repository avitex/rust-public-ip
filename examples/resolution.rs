use std::any::Any;

use public_ip::{self, dns, http, Version};

#[tokio::main]
async fn main() {
    // Attempt to get an IP address and print it
    if let Some((addr, details)) =
        public_ip::resolve_details(&[dns::OPENDNS_RESOLVER], Version::V6).await
    {
        if let Some(resolution) = Any::downcast_ref::<http::Details>(details.as_ref()) {
            println!(
                "public ip address {:?} resolved from {} ({:?})",
                addr,
                resolution.uri(),
                resolution.server(),
            );
        }
        if let Some(resolution) = Any::downcast_ref::<dns::Details>(details.as_ref()) {
            println!(
                "public ip address {:?} resolved from {} ({:?})",
                addr,
                resolution.name(),
                resolution.server(),
            );
        }
    } else {
        println!("couldn't get an IP address");
    }
}
