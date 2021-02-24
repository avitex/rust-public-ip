[![Build Status](https://travis-ci.com/avitex/rust-public-ip.svg?branch=master)](https://travis-ci.com/avitex/rust-public-ip)
[![Crate](https://img.shields.io/crates/v/public-ip.svg)](https://crates.io/crates/public-ip)
[![Docs](https://docs.rs/public-ip/badge.svg)](https://docs.rs/public-ip)

# rust-public-ip

**Find the public IP address of a device**  
Documentation hosted on [docs.rs](https://docs.rs/public-ip).

```toml
public-ip = "0.1.0"
```

## Example usage

```rust
#[tokio::main]
async fn main() {
    // Attempt to get an IP address and print it.
    if let Some(ip) = public_ip::addr().await {
        println!("public ip address: {:?}", ip);
    } else {
        println!("couldn't get an IP address");
    }
}
```
