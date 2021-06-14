// use bytes::{Buf, BytesMut};
// // use tokio::{
// //     io::{split, AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf},
// //     net::{TcpListener, TcpStream, UdpSocket},
// //     sync::{Mutex, RwLock},
// // };
//
// // use tokio::time::{timeout, Duration};
// // use tokio_rustls::rustls::{ServerConfig, Session};
// // use tokio_rustls::{server::TlsStream as RustlsStream, TlsAcceptor};
// // use tokio_util::codec::Decoder;
//
// use super::{
//     // copy_bidirectional::copy_bidirectional,
//     header::{TrojanDecoder, UdpAssociate, UdpAssociateDecoder},
//     usermg::User,
//     Error,
//     DEFAULT_BUFFER_SIZE,
// };
// use error::Result;
// use socket2::{Domain, Socket, Type};
// use std::{
//     collections::HashMap,
//     io::{Error as IoError, Result as IoResult},
//     net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
//     sync::Arc,
// };
// // use trust_dns_resolver::TokioAsyncResolver;
//
// use once_cell::sync::Lazy;
// // use async_std::sync::{RwLock, Mutex};
// // use async_std::net::{TcpStream, UdpSocket,TcpListener};
// // use futures_lite::io::split;
// use futures_lite::io::{ReadHalf, WriteHalf};
// // use futures::io::{WriteHalf, ReadHalf};
// use rustls::{ServerConfig, Session};
// use std::time::Duration;
// // use futures_lite::AsyncWriteExt;
// use crate::trojan::header::Decoder;
// use async_tls::{server::TlsStream as AsyncTlsStream, TlsAcceptor};
// // use tokio::io::AsyncReadExt;
// use crate::trojan::resolver::resolve;
// use async_std_resolver::resolver;
// use futures::io::AsyncRead;
// use futures::{select, AsyncReadExt, AsyncWriteExt, FutureExt};
// use glommio::net::{TcpListener, TcpStream, UdpSocket};
// use glommio::timer::timeout;
// // use tokio::io::AsyncWriteExt;
// use crate::MaybeSocketAddr;
//
// type TlsStream = AsyncTlsStream<TcpStream>;
//
// static UNSPECIFIED: Lazy<SocketAddr> =
//     Lazy::new(|| SocketAddr::from(SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, 0)));
//
// /// send a bad request to `$s` and close it immediately.
// macro_rules! bad_request {
//     ($s:ident) => {
//         $s.write_all(b"HTTP/1.1 400 bad request\r\nconnection: closed\r\n\r\nbad request")
//             .await?;
//         $s.flush().await?;
//         $s.close().await?;
//     };
// }
//
// macro_rules! resolve {
//     ($addr:expr) => {
//         match $addr {
//             MaybeSocketAddr::SocketAddr(ref addr) => *addr,
//             MaybeSocketAddr::HostAndPort(host, port) => {
//                 crate::trojan::resolver::resolve(host.clone(), *port)
//                             .await
//                         // .or(trust_dns_resolver::errors::ResolveError::from(format!(
//                         //         "no addresses returned ,host: {}",
//                         //         host
//                         //     )))
//                         ?
//             }
//         }
//     };
// }
//
// pub struct Forwarder {
//     /// available users
//     users: Arc<RwLock<HashMap<Box<[u8]>, User>>>,
//     /// tokio DNS resolver
//     // resolver: Arc<TokioAsyncResolver>,
//     /// common UDP socket
//     udp_socket: Arc<UdpSocket>,
//     /// current exchanging UDP group
//     udp_pairs: Arc<Mutex<HashMap<SocketAddrV6, (WriteHalf<TlsStream>, u64)>>>,
// }
//
// impl Forwarder {
//     pub fn new(
//         users: Arc<RwLock<HashMap<Box<[u8]>, User>>>,
//         // resolver: Arc<TokioAsyncResolver>,
//         udp_socket: Arc<UdpSocket>,
//     ) -> Self {
//         // let  add = resolve("1.2.3.4",16).await.or()
//
//         Forwarder {
//             users,
//             // resolver,
//             udp_socket,
//             udp_pairs: Default::default(),
//         }
//     }
//
//     pub async fn run_server(&self, listen_addr: SocketAddr, config: ServerConfig) -> Result<()> {
//         let udp_transfer_to_downstream_fut =
//             udp_transfer_to_downstream(self.udp_socket.clone(), self.udp_pairs.clone());
//         // tokio::spawn(async {
//         //     udp_transfer_to_downstream_fut.await.unwrap();
//         //     std::process::exit(1);
//         // });
//         Local::local(async {
//             udp_transfer_to_downstream_fut.await.unwrap();
//             // loop {
//             //     println!("I'm a background task looping forever.");
//             //     Local::later().await;
//             // }
//         })
//         .detach();
//
//         let acceptor = TlsAcceptor::from(Arc::new(config));
//         // let ipv6 = to_ipv6_address(&listen_addr);
//         // let socket = Socket::new(Domain::ipv6(), Type::stream(), None)?;
//         // socket.set_only_v6(false)?;
//         // socket.set_nonblocking(true)?;
//         // socket.set_read_timeout(Some(Duration::from_secs(60)))?;
//         // socket.set_write_timeout(Some(Duration::from_secs(60)))?;
//         // socket.set_linger(Some(Duration::from_secs(10)))?;
//         // socket.bind(&ipv6.into())?;
//         // socket.listen(128)?;
//         // let listener = TcpListener::from(socket.into_tcp_listener())?;
//         let listener = TcpListener::bind(listen_addr)?;
//         while let Ok(inbound) = listener.accept().await {
//             let src = inbound.peer_addr()?;
//             info!("accepting new connection from {:?}", src);
//             let fut = transfer(
//                 src,
//                 inbound,
//                 acceptor.clone(),
//                 self.users.clone(),
//                 // self.resolver.clone(),
//                 self.udp_socket.clone(),
//                 self.udp_pairs.clone(),
//             );
//             // tokio::spawn(async move {
//             //     if let Err(err) = fut.await {
//             //         errors!("transfer errors: {:?}", err);
//             //     }
//             // });
//
//             Local::local(async {
//                 if let Err(err) = fut.await {
//                     error!("transfer errors: {:?}", err);
//                 }
//                 // loop {
//                 //     println!("I'm a background task looping forever.");
//                 //     Local::later().await;
//                 // }
//             })
//             .detach();
//             // task.await.unwrap();
//         }
//         Ok(())
//     }
// }
//
// #[inline]
// fn to_ipv6_address(addr: &SocketAddr) -> SocketAddrV6 {
//     match addr {
//         SocketAddr::V4(ref a) => SocketAddrV6::new(a.ip().to_ipv6_mapped(), a.port(), 0, 0),
//         SocketAddr::V6(ref a) => *a,
//     }
// }
// use futures_lite::io::split;
// use futures_lite::{StreamExt, AsyncWrite};
// use glommio::{GlommioError, Local};
// // use glommio::sync::RwLock;
// use async_std::sync::RwLock;
// use futures::lock::Mutex;
// // use futures_lite::{AsyncReadExt, AsyncWriteExt};
//
// async fn transfer(
//     src: SocketAddr,
//     inbound: TcpStream,
//     acceptor: TlsAcceptor,
//     users: Arc<RwLock<HashMap<Box<[u8]>, User>>>,
//     // resolver: Arc<TokioAsyncResolver>,
//     udp_socket: Arc<UdpSocket>,
//     udp_pairs: Arc<Mutex<HashMap<SocketAddrV6, (WriteHalf<TlsStream>, u64)>>>,
// ) -> Result<()> {
//
//     // let mut stream = timeout(
//     //     Duration::from_secs(5),
//     //     async move{
//     //         let stream = acceptor.accept_with(inbound, |s| {
//     //             s.set_buffer_limit(DEFAULT_BUFFER_SIZE);
//     //         }).await?;
//     //         Ok(stream)
//     //     }
//     //
//     // )
//     // .await
//     // .map_err(|_| {
//     //     info!("transfer accept errors");
//     //    GlommioError::from( IoError::new(
//     //         std::io::ErrorKind::TimedOut,
//     //         format!("inbound: {} tls handshake timeout within 5 sec", src),
//     //     ))
//     // })?;
//     let mut stream = acceptor.accept(inbound).await?;
//
//
//     let mut buf = bytes::BytesMut::with_capacity(65536);
//     buf.clear();
//     loop {
//         // let n = timeout(Duration::from_secs(5), async {
//         //     let n = stream.read(&mut buf).await?;
//         //     Ok(n)
//         // })
//         //     .await
//         //     .map_err(|_| {
//         //         info!("stream.read errors");
//         //         GlommioError::from(IoError::new(
//         //             std::io::ErrorKind::TimedOut,
//         //             format!("inbound: {} read timeout within 5 sec", src),
//         //         ))
//         //     })?;
//
//         // Use the stream like any other
//         // stream
//         //     .write_all(
//         //         &b"HTTP/1.0 200 ok\r\n\
//         // Connection: close\r\n\
//         // Content-length: 12\r\n\
//         // \r\n\
//         // Hello world!"[..],
//         //     )
//         //     .await?;
//         //
//         // stream.flush().await?;
//         // break;
//         let mut buf1 = vec![0u8; 65536];
//         let n = stream.read(&mut buf1).await?;
//         info!("stream.read {:?} bytes", n);
//         let mut buf = BytesMut::from(buf1.as_slice());
//
//         if n == 0 {
//             bad_request!(stream);
//             break;
//         }
//         match TrojanDecoder.decode(&mut buf) {
//             Ok(Some(header)) => {
//                 if !users.read().await.contains_key(&header.password) {
//                     bad_request!(stream);
//                     break;
//                 }
//                 let addr = resolve!(&header.addr);
//                 info!("resolve incoming host: {:?},got: {:?}", &header.addr, addr);
//                 // let (upload, download) =
//                 if header.udp_associate {
//                     let (read_half, write_half) = split(stream);
//                     let cached = {
//                         if addr == *UNSPECIFIED {
//                             Some(write_half)
//                         } else {
//                             let addr = to_ipv6_address(&addr);
//                             let mut udp_pairs = udp_pairs.lock().await;
//                             if udp_pairs.contains_key(&addr) {
//                                 Some(write_half)
//                             } else {
//                                 udp_pairs.insert(addr, (write_half, 0));
//                                 None
//                             }
//                         }
//                     };
//                     if let Some(write_half) = cached {
//                         udp_bitransfer(src, read_half, write_half, buf).await?
//                     } else {
//                         info!("udp_transfer_to_upstream");
//                         let upload =
//                             udp_transfer_to_upstream(read_half, addr, udp_socket, buf).await;
//                         let mut guard = udp_pairs.lock().await;
//                         let addr = to_ipv6_address(&addr);
//                         let pair = guard.remove(&addr);
//                         if let Some((mut write_half, download)) = pair {
//                             write_half.flush().await?;
//                             write_half.close().await?;
//                             // write_half.shutdown().await?;
//                             // ()
//                         } else {
//                             unreachable!()
//                         }
//                     }
//                 } else {
//                     // let outbound = TcpStream::connect(&addr).await?;
//                     // let domain_type = if addr.is_ipv4() {
//                     //     Domain::ipv4()
//                     // } else {
//                     //     Domain::ipv6()
//                     // };
//                     // let socket = Socket::new(domain_type, Type::stream(), None)?;
//                     // socket.set_read_timeout(Some(Duration::from_secs(60)))?;
//                     // socket.set_write_timeout(Some(Duration::from_secs(60)))?;
//                     // socket.set_linger(Some(Duration::from_secs(10)))?;
//                     // socket.connect_timeout(&addr.into(), Duration::from_secs(5))?;
//                     // socket.set_nonblocking(true)?;
//                     // let outbound = TcpStream::from_std(socket.into_tcp_stream())?;
//                     let outbound = TcpStream::connect(addr).await?;
//                     info!("connect to remote addr: {:?}",outbound.peer_addr().unwrap());
//                     tcp_bitransfer(stream, outbound, buf).await?
//                 };
//                 // info!(
//                 //     "src: {} <=> dst: {} ,upload: {}bytes,download: {}bytes",
//                 //     src, header.addr, upload, download
//                 // );
//                 // if let Some(user) = users.write().await.get_mut(&header.password) {
//                 //     user.upload += upload;
//                 //     user.download += download;
//                 // }
//                 break;
//             }
//             Ok(None) => {}
//             Err(e) if e.kind() == std::io::ErrorKind::InvalidInput => {
//                 bad_request!(stream);
//                 break;
//             }
//             Err(e) => {
//                 stream.close().await?;
//                 return Err(Error::from(e));
//             }
//         }
//     }
//     Ok(())
// }
//
// async fn udp_transfer_to_upstream(
//     mut inbound: ReadHalf<TlsStream>,
//     addr: SocketAddr,
//     outbound: Arc<UdpSocket>,
//     mut buf: BytesMut,
//     // resolver: Arc<TokioAsyncResolver>,
// ) -> Result<u64> {
//     let mut upload = 0;
//     loop {
//         while let Some(frame) = UdpAssociateDecoder.decode(&mut buf)? {
//             let addr = resolve!(&frame.addr);
//             upload += outbound.send_to(&frame.payload, addr).await?;
//         }
//         if let Ok(r) = timeout(Duration::from_secs(60), async {
//             let n = inbound.read(&mut buf).await?;
//             Ok(n)
//         })
//         .await
//         {
//             if r != 0 {
//                 while let Some(frame) = UdpAssociateDecoder.decode_eof(&mut buf)? {
//                     let addr = resolve!(&frame.addr);
//                     upload += outbound.send_to(&frame.payload, addr).await?;
//                 }
//                 break;
//             }
//         } else {
//             info!("udp relay timeout for inbound side, dst :{}", addr);
//             break;
//         }
//     }
//     Ok(upload as u64)
// }
//
// async fn udp_transfer_to_downstream(
//     udp_socket: Arc<UdpSocket>,
//     udp_pairs: Arc<Mutex<HashMap<SocketAddrV6, (WriteHalf<TlsStream>, u64)>>>,
// ) -> IoResult<()> {
//     let mut buf = vec![0; 2048].into_boxed_slice();
//     loop {
//         let (len, dst) = udp_socket.recv_from(&mut buf).await?;
//         let us: Vec<u8> = UdpAssociate::new(dst, &buf[..len]).into();
//         {
//             let mut is_err = false;
//             let mut guard = udp_pairs.lock().await;
//             let dst = to_ipv6_address(&dst);
//             if let Some((write_half, download)) = guard.get_mut(&dst) {
//                 if let Err(e) = write_half.write_all(&us).await {
//                     error!("udp transfer to downstream errors: {}", e);
//                     is_err = true;
//                 } else {
//                     *download += len as u64;
//                 }
//             }
//             if is_err {
//                 guard.remove(&dst);
//             }
//         }
//     }
// }
//
// /// UDP bi-directional transmission through two futures
// async fn udp_bitransfer(
//     src: SocketAddr,
//     mut ri: ReadHalf<TlsStream>,
//     mut wi: WriteHalf<TlsStream>,
//     mut buf: BytesMut,
//     // resolver: Arc<TokioAsyncResolver>,
// ) -> Result<()> {
//     let (mut upload, mut download) = (0, 0);
//     let outbound = UdpSocket::bind(SocketAddr::from(SocketAddrV6::new(
//         Ipv6Addr::UNSPECIFIED,
//         0,
//         0,
//         0,
//     )))?;
//     let mut client_to_server = Box::pin(async {
//         loop {
//             while let Some(frame) = UdpAssociateDecoder.decode(&mut buf)? {
//                 let addr = resolve!(&frame.addr);
//                 upload += outbound.send_to(&frame.payload, addr).await?;
//             }
//             if let Ok(r) = timeout(Duration::from_secs(60), async {
//                 let n = ri.read(&mut buf).await?;
//                 Ok(n)
//             })
//             .await
//             {
//                 if r != 0 {
//                     while let Some(frame) = UdpAssociateDecoder.decode_eof(&mut buf)? {
//                         let addr = resolve!(&frame.addr);
//                         upload += outbound.send_to(&frame.payload, addr).await?;
//                     }
//                     break;
//                 }
//             } else {
//                 info!("udp bitransfer timeout, src: {}", src);
//                 break;
//             }
//         }
//         Ok(()) as Result<()>
//     })
//     .fuse();
//     let mut server_to_client = Box::pin(async {
//         let mut buf = vec![0; 2048].into_boxed_slice();
//         loop {
//             let (len, dst) = outbound.recv_from(&mut buf).await?;
//             if len == 0 {
//                 wi.close().await?;
//                 // wi.shutdown().await?;
//                 break;
//             }
//             let us: Vec<u8> = UdpAssociate::new(dst, &buf[..len]).into();
//             wi.write_all(&us).await?;
//             download += us.len();
//         }
//         wi.flush().await?;
//         wi.close().await?;
//         // wi.shutdown().await?;
//         Ok(()) as Result<()>
//     })
//     .fuse();
//     let r = select! {
//         r = client_to_server =>r,
//         r = server_to_client =>r,
//     };
//     if let Err(e) = r {
//         error!("udp bitransfer errors: {} ,src: {}", e, src);
//     }
//     Ok(())
// }
// // const RELAY_BUFFER_SIZE: usize = 0x4000;
// // async fn copy_tcp<R: AsyncRead , W: AsyncWrite>(
// //     r: &mut R,
// //     w: &mut W,
// // ) -> Result<()> {
// //     let mut buf = [0u8; RELAY_BUFFER_SIZE];
// //     loop {
// //         let len = r.read(&mut buf).await?;
// //         if len == 0 {
// //             break;
// //         }
// //         w.write(&buf[..len]).await?;
// //     }
// //     Ok(())
// // }
// async fn tcp_bitransfer(
//     mut inbound: TlsStream,
//     mut outbound: TcpStream,
//     buf: BytesMut,
// ) -> Result<()> {
//     // unimplemented!()
//     let remaining = buf.remaining();
//     if remaining > 0 {
//         info!("flush: {:?}---{:?}", buf.len(),buf.chunk().len());
//         // flushing remaining buffer
//         outbound.write_all(buf.chunk()).await?;
//         outbound.flush().await?;
//     }
//     let (mut out_reader, mut out_writer) = outbound.split();
//     let (mut in_reader, mut in_writer) = inbound.split();
//
//     let mut upstream = futures::io::copy(&mut in_reader, &mut out_writer).fuse();
//     let mut downstream = futures::io::copy(&mut out_reader, &mut in_writer).fuse();
//     // let mut upstream = copy_tcp(&mut in_reader, &mut out_writer).fuse();
//     // let mut downstream = copy_tcp(&mut out_reader, &mut in_writer).fuse();
//     let r = select! {
//         r = upstream =>{
//             info!("upstream: {:?}",r);
//             r
//         },
//         r = downstream =>{
//             info!("downstream: {:?}",r);
//             r
//         },
//     };
//     if let Err(e) = r {
//         error!("tcp bitransfer errors: {}", e);
//     }
//     // let (upload, download) = copy_bidirectional(&mut inbound, &mut outbound).await?;
//     // Ok((upload + remaining as u64, download))
//     Ok(())
// }
