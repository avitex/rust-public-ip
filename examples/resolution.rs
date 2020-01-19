use std::any::Any;

use async_std::task;
use public_ip::{self, dns, Resolution, ToResolver};

fn main() {
    // List of resolvers to try and get an IP address from
    let resolver = dns::OPENDNS_RESOLVER.to_resolver();
    // Attempt to get an IP address and print it
    if let Some(resolution) = task::block_on(public_ip::resolve(resolver)) {
        if let Some(resolution) = Any::downcast_ref::<dns::DnsResolution>(&resolution) {
            println!(
                "public ip address {:?} resolved from {:?} ({:?})",
                resolution.address(),
                resolution.name(),
                resolution.server(),
            );
        }
    } else {
        println!("couldn't get an IP address");
    }
}
