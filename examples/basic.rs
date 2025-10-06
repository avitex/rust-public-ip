#[tokio::main]
async fn main() {
    println!("builtin support: {:?}", public_ip::support());

    // Attempt to get an IP address and print it.
    if let Some(ip) = public_ip::addr().await {
        println!("public ip address: {:?}", ip);
    } else {
        println!("couldn't get an IP address");
    }
}
