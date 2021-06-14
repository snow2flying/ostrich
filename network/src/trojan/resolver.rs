use async_std_resolver::{config, resolver};
use errors::Error;
use std::fmt::Display;
use std::net::SocketAddr;
use trust_dns_resolver::{IntoName, TryParseIp};

pub async fn resolve<N: IntoName + Display + TryParseIp + Clone + 'static>(
    host: N,
    port: u16,
) -> Result<SocketAddr, Error> {
    let resolver = resolver(
        config::ResolverConfig::default(),
        config::ResolverOpts::default(),
    )
    .await?;
    let response = resolver.lookup_ip(host).await?;
    let address = response
        .iter()
        .map(move |ip| SocketAddr::new(ip, port))
        .next()
        .unwrap();
    // for address in response.iter(){
    //     if address.is_ipv4() {
    //         println!("ipv4: {:?}",address.to_string());
    //         // assert_eq!(address, IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)));
    //     } else {
    //         println!("ipv6: {:?}",address.to_string());
    //
    //         // assert_eq!(address, IpAddr::V6(Ipv6Addr::new(0x2606, 0x2800, 0x220, 0x1, 0x248, 0x1893, 0x25c8, 0x1946)));
    //     }
    // }
    Ok(address)
}
