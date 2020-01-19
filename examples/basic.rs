use async_std::task;
use public_ip::{self, dns, http, BoxToResolver, ToResolver};

fn main() {
    // List of resolvers to try and get an IP address from
    let resolver = vec![
        BoxToResolver::new(http::HTTP_IPIFY_ORG_RESOLVER),
        BoxToResolver::new(dns::OPENDNS_RESOLVER_V4),
    ]
    .to_resolver();
    // Attempt to get an IP address and print it
    if let Some(ip) = task::block_on(public_ip::resolve_address(resolver)) {
        println!("public ip address: {:?}", ip);
    } else {
        println!("couldn't get an IP address");
    }
}
