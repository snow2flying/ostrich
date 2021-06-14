use async_trait::async_trait;
// use fluvio_future::net::TcpStream;
use async_std::net::TcpStream;
// use fluvio_future::tls::DefaultServerTlsStream;
use async_tls::server::TlsStream as DefaultServerTlsStream;

/// Abstracts logic to authenticate incoming stream and forward authoization context to target
#[async_trait]
pub trait Authenticator: Send + Sync {
    async fn authenticate(
        &self,
        incoming_tls_stream: &DefaultServerTlsStream<TcpStream>,
        target_tcp_stream: &TcpStream,
    ) -> Result<bool, std::io::Error>;
}

/// Null implementation where authenticate always returns true
pub(crate) struct NullAuthenticator;

#[async_trait]
impl Authenticator for NullAuthenticator {
    async fn authenticate(
        &self,
        _: &DefaultServerTlsStream<TcpStream>,
        _: &TcpStream,
    ) -> Result<bool, std::io::Error> {
        Ok(true)
    }
}
