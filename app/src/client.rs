use std::io::Error as IoError;
use std::net::SocketAddr;
use std::sync::Arc;

use log::debug;

use event_listener::Event;
use futures_lite::future::zip;

use fluvio_future::net::{TcpListener, TcpStream};
use fluvio_future::tls::{TlsAcceptor, TlsConnector, TlsError};
use futures_lite::AsyncWriteExt;
use futures_util::stream::StreamExt;

// use flv_tls_proxy::ProxyBuilder;
use async_std::task;
use futures_util::AsyncReadExt;
use std::io;

const PROXY: &str = "127.0.0.1:18000";
const ITER: u16 = 10;
const CA_PATH: &str = "certs/certs/ca.crt";
fn main() -> io::Result<()> {
    env_logger::init();
    let connector = TlsConnector::builder()
        .unwrap()
        .with_hostname_vertification_disabled()
        .unwrap()
        .with_certificate_vertification_disabled()
        .unwrap()
        // .with_ca_from_pem_file(CA_PATH).unwrap()
        .build();

    let client_ft = async {
        debug!("client: sleep to give server chance to come up");

        debug!("client: trying to connect");
        let tcp_stream = TcpStream::connect(PROXY.to_owned())
            .await
            .expect("connection fail");
        let mut tls_stream = connector
            .connect("localhost", tcp_stream)
            .await
            .expect("tls failed");

        debug!("client: got connection. waiting");
        let last = std::time::Instant::now();
        // do loop for const
        let (mut tls_reader, mut tls_writer) = tls_stream.split();

        loop {
            std::thread::sleep(std::time::Duration::from_secs(3));
            let now = std::time::Instant::now();
            let i = now.duration_since(last).as_secs();
            let message = format!("message {}", i);
            debug!("client: loop sending test message: {}", message);
            let bytes = message.as_bytes();
            tls_writer.write_all(bytes).await.expect("send failed");
            let mut buf: Vec<u8> = vec![0; 1024];
            let n = tls_reader.read(&mut buf).await.expect("read");
            if n == 0 {
                debug!("connection closed");
                break;
            }
            debug!("client: loop received reply back bytes: {}", n);
            let mut str_bytes = vec![];
            for item in buf.into_iter().take(n) {
                str_bytes.push(item);
            }
            let reply_message = String::from_utf8(str_bytes).expect("utf8");
            debug!("client: loop received reply message: {}", reply_message);
        }

        debug!("client done");
        // event.notify(1);
        Ok(()) as Result<(), IoError>
    };
    task::block_on(async {
        client_ft.await.unwrap();

        Ok(())
    })
}
