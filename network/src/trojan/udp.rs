use crate::trojan::header::{Decoder, UdpAssociate, UdpAssociateDecoder};
use crate::try_resolve;
use anyhow::anyhow;
use async_std::future::timeout;
use async_std::net::TcpStream;
use async_std::net::UdpSocket;
use async_std::sync::Mutex;
use async_tls::server::TlsStream;
use bytes::BytesMut;
use errors::{Error, Result};
use futures::future::Either;
use futures::io::{ReadHalf, WriteHalf};
use futures::FutureExt;
use futures::{AsyncReadExt, AsyncWriteExt};
use log::{debug, info};
use std::collections::HashMap;
use std::net::{Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;
use crate::trojan::resolver::Resolver;
// use async_std_resolver::AsyncStdResolver;

pub async fn udp_transfer_to_upstream(
    mut inbound: ReadHalf<TlsStream<TcpStream>>,
    addr: SocketAddr,
    outbound: Arc<UdpSocket>,
    mut buf: BytesMut,
    resolver: Arc<Resolver>,
) -> Result<u64> {
    let mut upload = 0;
    loop {
        while let Some(frame) = UdpAssociateDecoder.decode(&mut buf)? {
            let addr = try_resolve(resolver.clone(),&frame.addr).await?;
            // debug!(
            //     "=====================udp_transfer_to_upstream: {:?}========================",
            //     &frame.addr
            // );
            upload += outbound.send_to(&frame.payload, addr).await?;
        }

        let mut buf1 = vec![0u8; 65536];
        // let n = inbound.read(&mut buf1).await?;
        // let n = timeout(Duration::from_secs(60), inbound.read(&mut buf1)).await.unwrap().unwrap();
        // debug!("=====================udp_transfer_to_upstream: {:?}========================",n);
        // if n == 0 {
        //     let mut buf2 = BytesMut::with_capacity(n);
        //     buf2.extend_from_slice(&buf1[..n]);
        //     while let Some(frame) = UdpAssociateDecoder.decode_eof(&mut buf2)? {
        //         let addr = try_resolve(&frame.addr).await;
        //         upload += outbound.send_to(&frame.payload, addr).await?;
        //     }
        //     break;
        // }

        if let Ok(r) = timeout(Duration::from_secs(60), inbound.read(&mut buf1)).await {
            let n = r.unwrap();
            // debug!(
            //     "=====================udp_transfer_to_upstream: {:?}========================",
            //     n
            // );
            if n == 0 {
                let mut buf2 = BytesMut::with_capacity(n);
                buf2.extend_from_slice(&buf1[..n]);
                while let Some(frame) = UdpAssociateDecoder.decode_eof(&mut buf2)? {
                    let addr = try_resolve(resolver.clone(),&frame.addr).await?;
                    upload += outbound.send_to(&frame.payload, addr).await?;
                }
                break;
            }
        } else {
            info!("udp relay timeout for inbound side, dst :{}", addr);
            break;
        }
    }
    Ok(upload as u64)
}

pub async fn udp_transfer_to_downstream(
    udp_socket: Arc<UdpSocket>,
    udp_pairs: Arc<Mutex<HashMap<SocketAddrV6, (WriteHalf<TlsStream<TcpStream>>, u64)>>>,
) -> Result<()> {
    let mut buf = vec![0u8; 65536];
    loop {
        let (len, dst) = udp_socket.recv_from(&mut buf).await?;
        let us: Vec<u8> = UdpAssociate::new(dst, &buf[..len]).into();
        {
            let mut is_err = false;
            let mut guard = udp_pairs.lock().await;
            let dst = to_ipv6_address(&dst);
            if let Some((write_half, download)) = guard.get_mut(&dst) {
                if let Err(e) = write_half.write_all(&us).await {
                    Error::Eor(anyhow!("udp transfer to downstream error: {}", e));
                    is_err = true;
                } else {
                    *download += len as u64;
                }
            }
            if is_err {
                guard.remove(&dst);
            }
        }
    }
}

pub async fn udp_bitransfer(
    src: String,
    mut ri: ReadHalf<TlsStream<TcpStream>>,
    mut wi: WriteHalf<TlsStream<TcpStream>>,
    mut buf: BytesMut,
    resolver: Arc<Resolver>,
) -> Result<(u64, u64)> {
    let (mut upload, mut download) = (0, 0);
    let outbound = UdpSocket::bind(SocketAddr::from(SocketAddrV6::new(
        Ipv6Addr::UNSPECIFIED,
        0,
        0,
        0,
    )))
    .await?;
    // let outbound = UdpSocket::bind("127.0.0.1:0").await?;
    let client_to_server = Box::pin(async {
        loop {
            while let Some(frame) = UdpAssociateDecoder.decode(&mut buf)? {
                let addr = try_resolve(resolver.clone(),&frame.addr).await?;
                // debug!(
                //     "=====================udp_bitransfer: {:?}========================",
                //     &addr
                // );
                outbound.send_to(&frame.payload, &addr).await.unwrap();
                // debug!(
                //     "=====================udp_bitransfer sent: {:?}========================",
                //     upload
                // );
            }

            let mut buf1 = vec![0u8; 65536];

            // let n = ri.read(&mut buf1).await?;
            // let n = timeout(Duration::from_secs(60), ri.read(&mut buf1)).await.unwrap().unwrap();
            //
            // debug!("=====================udp_bitransfer: {:?}========================",n);
            // if n == 0 {
            //     let mut buf2 = BytesMut::with_capacity(n);
            //     buf2.extend_from_slice(&buf1[..n]);
            //     while let Some(frame) = UdpAssociateDecoder.decode_eof(&mut buf2)? {
            //         let addr = try_resolve(&frame.addr).await;
            //         upload += outbound.send_to(&frame.payload, addr).await?;
            //     }
            //     break;
            // }
            if let Ok(r) = timeout(Duration::from_secs(60), ri.read(&mut buf1)).await {
                let n = r.unwrap();
                // debug!(
                //     "=====================udp_bitransfer: {:?}========================",
                //     n
                // );
                if n == 0 {
                    let mut buf2 = BytesMut::with_capacity(n);
                    buf2.extend_from_slice(&buf1[..n]);
                    while let Some(frame) = UdpAssociateDecoder.decode_eof(&mut buf2)? {
                        let addr = try_resolve(resolver.clone(),&frame.addr).await?;
                        upload += outbound.send_to(&frame.payload, addr).await?;
                    }
                    break;
                }
            } else {
                info!("udp bitransfer timeout, src: {}", src);
                break;
            }
        }
        Ok(()) as Result<()>
    })
    .fuse();
    let server_to_client = Box::pin(async {
        let mut buf = vec![0u8; 65536];
        loop {
            let (len, dst) = outbound.recv_from(&mut buf).await?;
            if len == 0 {
                wi.close().await?;
                break;
            }
            let us: Vec<u8> = UdpAssociate::new(dst, &buf[..len]).into();
            wi.write_all(&us).await?;
            download += us.len();
        }
        wi.flush().await?;
        wi.close().await?;
        Ok(()) as Result<()>
    })
    .fuse();
    let res = futures::future::select(client_to_server, server_to_client).await;
    match res {
        Either::Left((Err(e), _)) => {
            debug!("udp copy to remote closed");
            Err(anyhow::anyhow!("====================UdpAssociate copy local to remote error: {:?}=================",e))?
        }
        Either::Right((Err(e), _)) => {
            debug!("udp copy to local closed");
            Err(anyhow::anyhow!("====================UdpAssociate copy remote to local error: {:?}==================",e))?
        }
        Either::Left((Ok(_), _)) | Either::Right((Ok(_), _)) => (),
    };
    Ok((0 as u64, 0 as u64))
}
#[inline]
pub fn to_ipv6_address(addr: &SocketAddr) -> SocketAddrV6 {
    match addr {
        SocketAddr::V4(ref a) => SocketAddrV6::new(a.ip().to_ipv6_mapped(), a.port(), 0, 0),
        SocketAddr::V6(ref a) => *a,
    }
}
