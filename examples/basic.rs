use public_ip::{dns, http, Version};

#[tokio::main]
async fn main() {
    // List of resolvers to try and get an IP address from.
    let resolver = &[
        http::HTTP_WHATISMYIPADDRESS_COM_RESOLVER,
        dns::GOOGLE_DNS_TXT_RESOLVER,
    ];
    // Attempt to get an IP address and print it.
    if let Some(ip) = public_ip::resolve_address(resolver, Version::Any).await {
        println!("public ip address: {:?}", ip);
    } else {
        println!("couldn't get an IP address");
    }
}
