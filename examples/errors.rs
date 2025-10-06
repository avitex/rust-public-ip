use futures_util::{StreamExt, TryStreamExt, future};
use public_ip::{Version, dns, http};

#[tokio::main]
async fn main() {
    // List of resolvers to try and get an IP address from.
    let resolver = &[http::HTTP_IPIFY_ORG, dns::GOOGLE];
    let addr = public_ip::resolve(resolver, Version::Any)
        // For each error in the stream we print it out to STDERR (console).
        .inspect_err(|err| eprintln!("resolver error: {}", err))
        // We filter out the errors and leave just the resolved addresses in the stream.
        .filter_map(|result| future::ready(result.ok()))
        // We get the first resolved address in the stream.
        .next()
        // Wait for the future to finish.
        .await
        // We remove the details of the resolution if we don't care about them.
        .map(|(addr, _details)| addr);

    dbg!(addr);
}
