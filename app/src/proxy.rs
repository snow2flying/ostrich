use futures_util::io::{AsyncReadExt, WriteHalf};
use futures_util::stream::StreamExt;
use log::debug;
use log::error;
use log::info;
use std::sync::Arc;

use async_std::net::TcpStream;
use async_tls::server::TlsStream;
use async_tls::TlsAcceptor;

use crate::authenticator::{Authenticator, NullAuthenticator};
use anyhow::anyhow;
use async_std::net::UdpSocket;
use async_std::sync::Mutex;
use async_std_resolver::{config, resolver};
use errors::{Error, Result};
use futures::future::Either;
use futures::future::{self, AbortHandle};
use futures_util::AsyncWriteExt;
use glommio::{Local, Task};
use lru_time_cache::LruCache;
use network::trojan::header::{Decoder, TrojanDecoder};
use network::trojan::resolver::Resolver;
use network::trojan::udp::{to_ipv6_address, udp_bitransfer, udp_transfer_to_upstream};
use network::{bad_request, try_resolve};
use once_cell::sync::Lazy;
use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};
use std::time::Duration;

use crate::DNS_CHCAE_TIMEOUT;

pub enum Mode {
    Server,
    Client,
}

type SharedAuthenticator = Arc<Box<dyn Authenticator>>;
static UNSPECIFIED: Lazy<SocketAddr> =
    Lazy::new(|| SocketAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));
// /// start TLS proxy at addr to target
// pub async fn start(addr: SocketAddr, acceptor: TlsAcceptor, i: usize) -> Result<()> {
//     let builder = ProxyBuilder::new(addr, acceptor).await;
//     builder.start(i).await
// }

// /// start TLS proxy with authenticator at addr to target
// pub async fn start_with_authenticator(
//     addr: SocketAddr,
//     acceptor: TlsAcceptor,
//     // target: String,
//     i: usize,
//     authenticator: Box<dyn Authenticator>,
// ) -> Result<()> {
//     let builder = ProxyBuilder::new(addr, acceptor)
//         .await
//         .with_authenticator(authenticator);
//     builder.start(i).await
// }

pub struct ProxyBuilder {
    addr: SocketAddr,
    acceptor: TlsAcceptor,
    // target: String,
    authenticator: Box<dyn Authenticator>,
    // terminate: TerminateEvent,
    resolver: Arc<Resolver>,
    cleanup_abortable: AbortHandle,
}
impl Drop for ProxyBuilder {
    fn drop(&mut self) {
        self.cleanup_abortable.abort();
    }
}

impl ProxyBuilder {
    pub async fn new(
        addr: SocketAddr,
        acceptor: TlsAcceptor,
        cleanup_abortable: AbortHandle,
        cache: Arc<Mutex<LruCache<String, SocketAddr>>>,
    ) -> Self {
        // use std::sync::Mutex;
        let resolver = resolver(
            config::ResolverConfig::default(),
            config::ResolverOpts::default(),
        )
        .await
        .unwrap();

        Self {
            addr,
            acceptor,
            // target,
            authenticator: Box::new(NullAuthenticator),
            // terminate: Arc::new(Event::new()),
            resolver: Arc::new(Resolver {
                dns: resolver,
                cache,
            }),
            cleanup_abortable,
        }
    }

    pub fn with_authenticator(mut self, authenticator: Box<dyn Authenticator>) -> Self {
        self.authenticator = authenticator;
        self
    }

    // pub fn with_terminate(mut self, terminate: TerminateEvent) -> Self {
    //     self.terminate = terminate;
    //     self
    // }

    pub async fn start(self, i: usize) -> Result<()> {
        use async_std::net::TcpListener;
        use socket2::{Domain, Protocol, Socket, Type};
        // use fluvio_future::task::spawn;
        // use futures::future::select;
        let addr = self
            .addr
            .clone()
            .to_socket_addrs()
            .unwrap()
            .next()
            .ok_or_else(|| io::Error::new(io::ErrorKind::Other, "empty address"))?;

        let domain = if addr.is_ipv6() {
            Domain::ipv6()
        } else {
            Domain::ipv4()
        };
        let sk = Socket::new(domain, Type::stream(), Some(Protocol::tcp()))?;
        let addr = socket2::SockAddr::from(addr);
        sk.set_reuse_port(true)?;
        sk.bind(&addr)?;
        sk.listen(1024)?;
        let listener = sk.into_tcp_listener();

        let listener = TcpListener::from(listener);
        // let listener = TcpListener::bind(&self.addr).await?;
        info!("worker {} proxy started at: {}", i, self.addr);
        // let shared_authenticator = Arc::new(self.authenticator);
        let udp_pairs: Arc<Mutex<HashMap<SocketAddrV6, (WriteHalf<TlsStream<TcpStream>>, u64)>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let udp_socket = Arc::new(
            UdpSocket::bind(SocketAddr::from(SocketAddrV6::new(
                Ipv6Addr::UNSPECIFIED,
                0,
                0,
                0,
            )))
            .await?,
        );
        while let Some(incoming_stream) = listener.incoming().next().await {
            match incoming_stream {
                Err(_) => continue,
                Ok(stream) => {
                    let acceptor = self.acceptor.clone();
                    // let target = self.target.clone();
                    Task::local(process_stream(
                        acceptor,
                        stream,
                        // target,
                        // shared_authenticator.clone(),
                        udp_pairs.clone(),
                        udp_socket.clone(),
                        self.resolver.clone(),
                    ))
                    .detach();
                    // Ok(())
                }
            }
        }
        Ok(())
    }
}

/// start TLS stream at addr to target
async fn process_stream(
    acceptor: TlsAcceptor,
    raw_stream: TcpStream,
    // target: String,
    // authenticator: SharedAuthenticator,
    udp_pairs: Arc<Mutex<HashMap<SocketAddrV6, (WriteHalf<TlsStream<TcpStream>>, u64)>>>,
    udp_socket: Arc<UdpSocket>,
    resolver: Arc<Resolver>,
) {
    let source = raw_stream
        .peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "".to_owned());

    debug!("new connection from {}", source);

    let handshake = acceptor.accept(raw_stream).await;

    match handshake {
        Ok(inner_stream) => {
            debug!("handshake success from: {}", source);
            if let Err(err) = proxy(
                inner_stream,
                // target,
                source.clone(),
                // authenticator,
                udp_pairs,
                udp_socket,
                resolver,
            )
            .await
            {
                error!("errors processing tls: {:?} from source: {}", err, source);
            }
        }
        Err(err) => error!("errors handshaking: {:?} from source: {}", err, source),
    }
}

async fn proxy(
    mut tls_stream: TlsStream<TcpStream>,
    // _target: String,
    source: String,
    // authenticator: SharedAuthenticator,
    udp_pairs: Arc<Mutex<HashMap<SocketAddrV6, (WriteHalf<TlsStream<TcpStream>>, u64)>>>,
    udp_socket: Arc<UdpSocket>,
    resolver: Arc<Resolver>,
) -> Result<()> {
    use crate::copy::copy;
    use bytes::{Buf, BytesMut};
    // use futures_util::FutureExt;
    // use network::MaybeSocketAddr;
    let mut buf1 = vec![0u8; 65536];
    // let mut buf = BytesMut::new();
    let n = tls_stream.read(&mut buf1).await?;
    info!("stream.read {:?} bytes", n);
    let mut buf = BytesMut::with_capacity(n);
    buf.extend_from_slice(&buf1[..n]);
    // let mut buf = BytesMut::from(buf1.as_slice());
    info!("before decode: {:?}", buf.chunk().len());
    if n == 0 {
        bad_request!(tls_stream);
        // break;
    }
    match TrojanDecoder.decode(&mut buf) {
        Ok(Some(header)) => {
            // if !users.read().await.contains_key(&header.password) {
            //     bad_request!(stream);
            //     break;
            // }
            info!("after decode: {:?}", buf.chunk().len());
            let target = try_resolve(resolver.clone(), &header.addr).await?;
            info!("resolve incoming host: {:?}", &header.addr);
            debug!(
                "trying to connect to target at: {} from source: {}",
                target, source
            );

            // let (upload, download) =
            if header.udp_associate {
                let (read_half, write_half) = tls_stream.split();
                let cached = {
                    if target == *UNSPECIFIED {
                        Some(write_half)
                    } else {
                        let addr = to_ipv6_address(&target);
                        let mut udp_pairs = udp_pairs.lock().await;
                        if udp_pairs.contains_key(&addr) {
                            drop(udp_pairs);

                            Some(write_half)
                        } else {
                            udp_pairs.insert(addr, (write_half, 0));
                            drop(udp_pairs);

                            None
                        }
                    }
                };
                if let Some(write_half) = cached {
                    udp_bitransfer(source, read_half, write_half, buf, resolver.clone()).await?
                } else {
                    let upload = udp_transfer_to_upstream(
                        read_half,
                        target,
                        udp_socket,
                        buf,
                        resolver.clone(),
                    )
                    .await;
                    let mut guard = udp_pairs.lock().await;
                    let addr = to_ipv6_address(&target);
                    let pair = guard.remove(&addr);
                    if let Some((mut write_half, download)) = pair {
                        write_half.flush().await?;
                        write_half.close().await?;
                        (upload?, download)
                    } else {
                        unreachable!()
                    }
                };
            } else {
                let mut tcp_stream = TcpStream::connect(&target).await?;

                // let auth_success = authenticator.authenticate(&tls_stream, &tcp_stream).await?;
                // if !auth_success {
                //     debug!("authentication failed, dropping connection");
                //     return Ok(());
                // } else {
                //     debug!("authentication succeeded");
                // }

                debug!("connect to target: {} from source: {}", target, source);
                if buf.remaining() > 0 {
                    tcp_stream.write_all(buf.as_ref()).await.unwrap();
                }

                let (mut target_stream, mut target_sink) = tcp_stream.split();
                let (mut from_tls_stream, mut from_tls_sink) = tls_stream.split();

                let s_t = format!("{}->{}", source, target);
                let t_s = format!("{}->{}", target, source);
                /*                let mut source_to_target_ft = Box::pin(async move {
                    match copy(&mut from_tls_stream, &mut target_sink, s_t.clone()).await {
                        Ok(len) => {
                            debug!("total {} bytes copied from source to target: {}", len, s_t);
                            Ok(())
                        }
                        Err(err) => {
                            error!("{} errors copying: {}", s_t, err);
                            Err(Error::Eor(anyhow!("proxy error: {} ", err)))
                        }
                    }
                })
                .fuse();

                let mut target_to_source_ft = Box::pin(async move {
                    match copy(&mut target_stream, &mut from_tls_sink, t_s.clone()).await {
                        Ok(len) => {
                            debug!("total {:?} bytes copied from target: {}", len, t_s);
                            Ok(())
                        }
                        Err(err) => {
                            error!("{} errors copying: {}", t_s, err);
                            Err(Error::Eor(anyhow!("proxy error: {} ", err)))
                        }
                    }
                })
                .fuse();
                let r = futures::select! {
                   r = source_to_target_ft =>r,
                   r = target_to_source_ft =>r,
                };
                if let Err(e) = r {
                    return Err(Error::from(e));
                }*/

                let source_to_target_ft = async move {
                    match copy(&mut from_tls_stream, &mut target_sink, s_t.clone()).await {
                        Ok(len) => {
                            debug!("total {} bytes copied from source to target: {}", len, s_t);
                            Ok(())
                        }
                        Err(err) => {
                            error!("{} errors copying: {}", s_t, err);
                            Err(Error::Eor(anyhow!("proxy error: {} ", err)))
                        }
                    }
                };

                let target_to_source_ft = async move {
                    match copy(&mut target_stream, &mut from_tls_sink, t_s.clone()).await {
                        Ok(len) => {
                            debug!("total {:?} bytes copied from target: {}", len, t_s);
                            Ok(())
                        }
                        Err(err) => {
                            error!("{} errors copying: {}", t_s, err);
                            Err(Error::Eor(anyhow!("proxy error: {} ", err)))
                        }
                    }
                };

                futures::pin_mut!(source_to_target_ft);
                futures::pin_mut!(target_to_source_ft);
                let res = futures::future::select(source_to_target_ft, target_to_source_ft).await;
                match res {
                    Either::Left((Err(e), _)) => {
                        debug!("tcp copy to remote closed");
                        Err(anyhow::anyhow!("====================tcp copy local to remote error: {:?}=================",e))?
                    }
                    Either::Right((Err(e), _)) => {
                        debug!("tcp copy to local closed");
                        Err(anyhow::anyhow!("====================tcp copy remote to local error: {:?}==================",e))?
                    }
                    Either::Left((Ok(_), _)) | Either::Right((Ok(_), _)) => (),
                };
                // if let Err(_) = res {
                //     return Err(Error::from(e));
                // }
            };
        }
        Ok(None) => {
            panic!("received none")
        }
        Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
            bad_request!(tls_stream);
            // break;
        }
        Err(e) => {
            tls_stream.close().await?;
            return Err(Error::from(e));
        }
    }

    Ok(())
}
