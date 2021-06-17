use std::fmt;
use std::net::SocketAddr;
// use async_std_resolver::AsyncStdResolver;
use crate::trojan::resolver::Resolver;
use errors::Result;
use std::sync::Arc;
pub mod trojan;
use log::info;
impl fmt::Display for MaybeSocketAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MaybeSocketAddr::SocketAddr(addr) => write!(f, "{}", addr),
            MaybeSocketAddr::HostAndPort(host, port) => write!(f, "{}:{}", host, port),
        }
    }
}

#[derive(Debug, PartialEq)]
pub enum MaybeSocketAddr {
    SocketAddr(SocketAddr),
    HostAndPort(String, u16),
}

impl From<SocketAddr> for MaybeSocketAddr {
    fn from(addr: SocketAddr) -> Self {
        MaybeSocketAddr::SocketAddr(addr)
    }
}

impl From<(String, u16)> for MaybeSocketAddr {
    fn from(domain_and_port: (String, u16)) -> Self {
        MaybeSocketAddr::HostAndPort(domain_and_port.0, domain_and_port.1)
    }
}
#[macro_export]
macro_rules! bad_request {
    ($s:ident) => {
        $s.write_all(b"HTTP/1.1 400 bad request\r\nconnection: closed\r\n\r\nbad request")
            .await?;
        $s.flush().await?;
        $s.close().await?;
    };
}

pub async fn try_resolve(resolver: Arc<Resolver>, addr: &MaybeSocketAddr) -> Result<SocketAddr> {
    match addr {
        MaybeSocketAddr::SocketAddr(ref addr) => Ok(*addr),
        MaybeSocketAddr::HostAndPort(host, port) => {
            let mut cache = resolver.cache.lock().await;
            match cache.get(host) {
                Some(addr) => {
                    info!("dns cache matched host: {:?}", host);
                    let ret = addr.clone();
                    drop(cache);
                    Ok(ret)
                }
                None => {
                    let addr =
                        crate::trojan::resolver::resolve(resolver.clone(), host.clone(), *port)
                            .await?
                            .ok_or(anyhow::anyhow!("can not resolve host: {:?}", host))?;
                    cache.insert(host.to_owned(), addr);
                    drop(cache);
                    Ok(addr.clone())
                }
            }
        }
    }
}
