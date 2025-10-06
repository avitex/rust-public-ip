use std::any::Any;

use public_ip::{Version, dns, http};

#[tokio::main]
async fn main() {
    // List of resolvers to try and get an IP address from.
    let resolver = &[http::HTTP_IPIFY_ORG, dns::GOOGLE];
    // Attempt to get an IP address and print it.
    if let Some((addr, details)) = public_ip::addr_with_details(resolver, Version::Any).await {
        // Downcast the HTTP details (if the resolution was from a HTTP resolver).
        if let Some(details) = <dyn Any>::downcast_ref::<http::Details>(details.as_ref()) {
            println!(
                "public ip address {:?} resolved from {} ({:?})",
                addr,
                details.uri(),
                details.server(),
            );
        }
        // Downcast the DNS details (if the resolution was from a DNS resolver).
        if let Some(details) = <dyn Any>::downcast_ref::<dns::Details>(details.as_ref()) {
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
