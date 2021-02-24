use std::any::Any;

use public_ip::{dns, http, Version};

#[tokio::main]
async fn main() {
    // List of resolvers to try and get an IP address from.
    let resolver = &[
        http::HTTP_WHATISMYIPADDRESS_COM_RESOLVER,
        dns::GOOGLE_DNS_TXT_RESOLVER,
    ];
    // Attempt to get an IP address and print it.
    if let Some((addr, details)) =
        public_ip::resolve_details(resolver, Version::Any).await
    {
        // Downcast the HTTP details (if the resolution was from a HTTP resolver).
        if let Some(details) = Any::downcast_ref::<http::Details>(details.as_ref()) {
            println!(
                "public ip address {:?} resolved from {} ({:?})",
                addr,
                details.uri(),
                details.server(),
            );
        }
        // Downcast the DNS details (if the resolution was from a DNS resolver).
        if let Some(details) = Any::downcast_ref::<dns::Details>(details.as_ref()) {
            println!(
                "public ip address {:?} resolved from {} ({:?})",
                addr,
                details.name(),
                details.server(),
            );
        }
    } else {
        println!("couldn't get an IP address");
    }
}
