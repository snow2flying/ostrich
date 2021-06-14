// // Example on how to use the Hyper server in !Send mode.
// // The clients are harder, see https://github.com/hyperium/hyper/issues/2341 for details
// //
// // Essentially what we do is we wrap our types around the Tokio traits. The
// // !Send limitation makes it harder to deal with high level hyper primitives but
// // it works in the end.
//     use futures_lite::{AsyncRead, AsyncWrite, Future};
//     use hyper::service::service_fn;
//     use std::{
//         net::SocketAddr,
//         pin::Pin,
//         task::{Context, Poll},
//     };
//     use hyper::{server::conn::Http, Body, Request, Response, Method, StatusCode};
//     use std::{io, rc::Rc};
// use std::convert::Infallible;
// use glommio::net::{TcpListener, TcpStream};
// use glommio::sync::Semaphore;
// use glommio::{Local, enclose, Task};
//
// #[derive(Clone)]
//     struct HyperExecutor;
//
//     impl<F> hyper::rt::Executor<F> for HyperExecutor
//         where
//             F: Future + 'static,
//             F::Output: 'static,
//     {
//         fn execute(&self, fut: F) {
//             Task::local(fut).detach();
//         }
//     }
//
//     struct HyperStream(pub TcpStream);
//     impl tokio::io::AsyncRead for HyperStream {
//         fn poll_read(
//             mut self: Pin<&mut Self>,
//             cx: &mut Context,
//             buf: &mut [u8],
//         ) -> Poll<io::Result<usize>> {
//             Pin::new(&mut self.0).poll_read(cx, buf)
//         }
//     }
//
//     impl tokio::io::AsyncWrite for HyperStream {
//         fn poll_write(
//             mut self: Pin<&mut Self>,
//             cx: &mut Context,
//             buf: &[u8],
//         ) -> Poll<io::Result<usize>> {
//             Pin::new(&mut self.0).poll_write(cx, buf)
//         }
//
//         fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
//             Pin::new(&mut self.0).poll_flush(cx)
//         }
//
//         fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
//             Pin::new(&mut self.0).poll_close(cx)
//         }
//     }
//
//     pub async fn serve_http<S, F, R, A>(
//         addr: A,
//         service: S,
//         max_connections: usize,
//     ) -> io::Result<()>
//         where
//             S: FnMut(Request<Body>) -> F + 'static + Copy,
//             F: Future<Output = Result<Response<Body>, R>> + 'static,
//             R: std::error::Error + 'static + Send + Sync,
//             A: Into<SocketAddr>,
//     {
//         let listener = TcpListener::bind(addr.into())?;
//         let conn_control = Rc::new(Semaphore::new(max_connections as _));
//         loop {
//             match listener.accept().await {
//                 Err(x) => {
//                     return Err(x.into());
//                 }
//                 Ok(stream) => {
//                     let addr = stream.local_addr().unwrap();
//                     Local::local(enclose!{(conn_control) async move {
//                         let _permit = conn_control.acquire_permit(1).await;
//                         if let Err(x) = Http::new().with_executor(HyperExecutor).serve_connection(HyperStream(stream), service_fn(service)).await {
//                             panic!("Stream from {:?} failed with error {:?}", addr, x);
//                         }
//                     }}).detach();
//                 }
//             }
//         }
//     }
//
//
// pub async fn hyper_demo(req: Request<Body>) -> Result<Response<Body>, Infallible> {
//     match (req.method(), req.uri().path()) {
//         (&Method::GET, "/hello") => Ok(Response::new(Body::from("world"))),
//         (&Method::GET, "/world") => Ok(Response::new(Body::from("hello"))),
//         _ => Ok(Response::builder()
//             .status(StatusCode::NOT_FOUND)
//             .body(Body::from("notfound"))
//             .unwrap()),
//     }
// }
use std::future::Future;
use std::io;
use std::io::ErrorKind;
use std::io::Result;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use async_std::io::{Read, Write};
use async_std::net::{TcpListener, TcpStream};
use async_std::stream::Stream;
use async_std::task;
use async_tls::{TlsAcceptor, TlsConnector};
use async_tls::client::TlsStream as ClientTlsStream;
use async_tls::server::TlsStream as ServerTlsStream;
use hyper::client::connect::{Connected, Connection};
use hyper::service::Service;
use rustls::ClientConfig;
// use tonic::transport::Uri;
use hyper::Uri;
use futures_lite::future::ready;
use tokio::io::ReadBuf;
use futures_lite::AsyncRead;

#[derive(Clone)]
pub struct HyperExecutor;

impl<F> hyper::rt::Executor<F> for HyperExecutor
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static,
{
    fn execute(&self, fut: F) {
        task::spawn(fut);
    }
}

pub struct HyperListener {
    pub tls_acceptor: TlsAcceptor,
    pub tcp_listener: TcpListener,
}

impl hyper::server::accept::Accept for HyperListener {
    type Conn = HyperStream<ServerTlsStream<TcpStream>>;
    type Error = io::Error;

    fn poll_accept(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
    ) -> Poll<Option<Result<Self::Conn>>> {
        let stream = task::ready!(Pin::new(&mut self.tcp_listener.incoming()).poll_next(cx)).unwrap()?;
        println!("accept");
        let stream = task::ready!(Pin::new(&mut self.tls_acceptor.accept(stream)).poll(cx));

        match stream {
            Err(err) => Poll::Ready(Some(Err(err))),

            Ok(stream) => Poll::Ready(Some(Ok(HyperStream(stream))))
        }
    }
}

pub struct HyperStream<T>(pub T);

impl<T> tokio::io::AsyncRead for HyperStream<T>
    where T: AsyncRead + Unpin + Send
{
    fn poll_read(mut self: Pin<&mut Self>, cx: &mut Context<'_>,  buf: &mut ReadBuf<'_>,) -> Poll<Result<()>> {
        // Pin::new(&mut self.0).poll_read(cx, buf.initialize_unfilled())
        match Pin::new(&mut self.0).poll_read(cx, buf.initialize_unfilled()) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(e)) => Poll::Ready(Err(e)),
            Poll::Ready(Ok(n)) => {
                buf.advance(n);
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl<T> tokio::io::AsyncWrite for HyperStream<T>
    where T: Write + Unpin + Send
{
    fn poll_write(mut self: Pin<&mut Self>, cx: &mut Context<'_>, buf: &[u8]) -> Poll<Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Result<()>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}

impl Connection for HyperStream<ClientTlsStream<TcpStream>> {
    fn connected(&self) -> Connected {
        Connected::new()
    }
}

/*pub struct HyperServerStream(pub ServerTlsStream<TcpStream>);

impl tokio::io::AsyncRead for HyperServerStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for HyperServerStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}

pub struct HyperClientStream(pub ClientTlsStream<TcpStream>);

impl tokio::io::AsyncRead for HyperClientStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_read(cx, buf)
    }
}

impl tokio::io::AsyncWrite for HyperClientStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.0).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<io::Result<()>> {
        Pin::new(&mut self.0).poll_close(cx)
    }
}

impl Connection for HyperClientStream {
    fn connected(&self) -> Connected {
        let connected = Connected::new();

        if let Ok(remote_addr) = self.0.get_ref().peer_addr() {
            connected.extra(remote_addr)
        } else {
            connected
        }
    }
}*/

#[derive(Clone)]
pub struct HyperConnector {
    tls_connector: TlsConnector,
}
impl Unpin for HyperConnector {}

impl Service<Uri> for HyperConnector {
    type Response = HyperStream<ClientTlsStream<TcpStream>>;
    type Error = std::io::Error;
    type Future = Pin<Box<dyn Future<Output=io::Result<Self::Response>>>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Uri) -> Self::Future {
        match req.authority() {
            None => Box::pin(ready(Err(io::Error::new(ErrorKind::AddrNotAvailable, format!("{} is invalid", req)).into()))),

            Some(authority) => {
                let host = authority.host().to_string();
                let authority = authority.to_string();

                let tls_connector = self.tls_connector.clone();

                Box::pin(async move {
                    let stream = TcpStream::connect(authority).await?;

                    let tls_stream = tls_connector.connect(host, stream).await?;

                    Ok(HyperStream(tls_stream))
                })
            }
        }
    }
}

impl From<ClientConfig> for HyperConnector {
    fn from(cfg: ClientConfig) -> Self {
        Self {
            tls_connector: TlsConnector::from(Arc::new(cfg))
        }
    }
}
