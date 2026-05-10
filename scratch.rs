use std::net::IpAddr;
use url::Url;

fn main() {
    let hosts = [
        "127.0.0.1",
        "127.1",
        "127.0.0.1.",
        "192.168.001.001",
        "0177.0.0.1",
        "[::ffff:127.0.0.1]",
        "[::ffff:7f00:1]",
        "localhost",
    ];

    for h in hosts {
        let url_str = format!("http://{}", h);
        let u = Url::parse(&url_str);
        match u {
            Ok(url) => {
                let host_str = url.host_str().unwrap_or("");
                let parsed_ip = host_str.parse::<IpAddr>();
                println!("Host: {:<20} | URL host: {:<20} | IpAddr parse: {:?}", h, host_str, parsed_ip);
            }
            Err(e) => {
                println!("Host: {:<20} | URL parse error: {:?}", h, e);
            }
        }
    }
}
