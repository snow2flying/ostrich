use async_std::sync::Mutex;
use async_std_resolver::{config, resolver, AsyncStdResolver};
use errors::{Error, Result};
use log::error;
use lru_time_cache::LruCache;
use std::collections::HashMap;
use std::fmt::Display;
use std::net::SocketAddr;
use std::sync::Arc;
use trust_dns_resolver::{IntoName, TryParseIp};

// use std::sync::Mutex;
pub struct Resolver {
    pub dns: AsyncStdResolver,
    pub cache: Arc<Mutex<LruCache<String, SocketAddr>>>,
}

pub async fn resolve<N: IntoName + Display + TryParseIp + Clone + 'static>(
    resolver: Arc<Resolver>,
    host: N,
    port: u16,
) -> Result<Option<SocketAddr>> {
    // let resolver = resolver(
    //     config::ResolverConfig::default(),
    //     config::ResolverOpts::default(),
    // )
    // .await?;
    let response = resolver.dns.lookup_ip(host.clone()).await.map_err(|e| {
        error!(
            "dns bad request with host: {:?}",
            host.clone().to_string().as_str()
        );
        anyhow::anyhow!("{:?}", e)
    })?;
    let address = response
        .iter()
        .map(move |ip| SocketAddr::new(ip, port))
        .next();
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
