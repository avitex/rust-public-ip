use async_std::task;
use public_ip::{self, dns, http, ToResolver, BoxToResolver};

fn main() {
    // List of resolvers to try and get an IP address from
    let resolver = vec![
        BoxToResolver::new(dns::OPENDNS_RESOLVER),
        BoxToResolver::new(http::HTTP_IPIFY_ORG_RESOLVER),
    ].to_resolver();
    // Attempt to get an IP address and print it
    if let Some(ip) = task::block_on(public_ip::resolve_address(resolver)) {
        println!("public ip address: {:?}", ip);
    } else {
        println!("couldn't get an IP address");
    }
}
