/*use http_client::hyper::HyperClient as Client;
use glommio::{LocalExecutorBuilder, Local};
use http_client::{Request, HttpClient};
use http_client::http_types::Method;

fn main() {
    // let mut handles = vec![];

    let handle0 = LocalExecutorBuilder::new()
        .spawn(|| async move {
            Local::local(async {
                let client = Client::new();

                let req = Request::new(Method::Get, "http://hyper.rs");

                client.send(req).await.unwrap();

                dbg!(client);
            })
                .detach();
        })
        .unwrap();

    handle0.join().unwrap();
}*/
use futures::prelude::*;
use hyper::{Body,Server, body::to_bytes, Uri, Request, Response, Method, StatusCode};
use network::http;
use network::http::{HyperConnector, HyperExecutor, HyperStream};
use rustls::ClientConfig;
use std::{env, fs, io, sync};
use rustls::internal::pemfile;
use async_std::net::TcpListener;
use async_tls::TlsAcceptor;
use hyper::service::{service_fn, make_service_fn};
use network::http::HyperListener;
use hyper::server::conn::Http;

// https://github.com/async-rs/async-std-hyper
pub mod compat {
    use async_std::prelude::*;
    use async_std::task;

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
}


fn error(err: String) -> io::Error {
    io::Error::new(io::ErrorKind::Other, err)
}
// Load public certificate from file.
fn load_certs(filename: &str) -> io::Result<Vec<rustls::Certificate>> {
    // Open certificate file.
    let certfile = fs::File::open(filename).unwrap();
        // .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(certfile);

    // Load and return certificate.
    pemfile::certs(&mut reader).map_err(|_| error("failed to load certificate".into()))
}

// Load private key from file.
fn load_private_key(filename: &str) -> io::Result<rustls::PrivateKey> {
    // Open keyfile.
    let keyfile = fs::File::open(filename)
        .map_err(|e| error(format!("failed to open {}: {}", filename, e)))?;
    let mut reader = io::BufReader::new(keyfile);

    // Load and return a single private key.
    let keys = pemfile::rsa_private_keys(&mut reader)
        .map_err(|_| error("failed to load private key".into()))?;
    if keys.len() != 1 {
        return Err(error("expected a single private key".into()));
    }
    Ok(keys[0].clone())
}


fn main() -> io::Result<()> {
    // let mut config = ClientConfig::new();
    // config.root_store = match rustls_native_certs::load_native_certs() {
    //     Ok(store) => store,
    //     Err((Some(store), err)) => {
    //         store
    //     }
    //     Err((None, err)) => Err(err).expect("cannot access native cert store"),
    // };
    // if config.root_store.is_empty() {
    //     panic!("no CA certificates found");
    // }
    // let connector = HyperConnector::from(config);
    //
    // let client: hyper::Client<HyperConnector> = hyper::client::Client::builder()
    //     .executor(compat::HyperExecutor)
    //     .build(connector);
    // First parameter is port number (optional, defaults to 1337)
    let port = match env::args().nth(1) {
        Some(ref p) => p.to_owned(),
        None => "1337".to_owned(),
    };
    let addr = format!("0.0.0.0:{}", port);

    // Build TLS configuration.
    let tls_cfg = {
        // Load public certificate.
        let certs = load_certs("/usr/cert/fullchain.cer").unwrap();
        // Load private key.
        let key = load_private_key("/usr/cert/private.key").unwrap();
        // Do not use client certificate authentication.
        let mut cfg = rustls::ServerConfig::new(rustls::NoClientAuth::new());
        // Select a certificate to use.
        cfg.set_single_cert(certs, key).unwrap();
            // .map_err(|e| error(format!("{}", e)))?;
        // Configure ALPN to accept HTTP/2, HTTP/1.1 in that order.
        // cfg.set_protocols(&[b"h2".to_vec(), b"http/1.1".to_vec()]);
        cfg.set_protocols(&[b"http/1.1".to_vec()]);
        sync::Arc::new(cfg)
    };



    // for i in 0.. {
    //     println!("{}", i);
        async_std::task::block_on(async {
    //         let res = client
    //             .get(Uri::from_static("https://hyper.rs"))
    //             .await?;
    //         println!("Status:\n{}", res.status());
    //         println!("Headers:\n{:#?}", res.headers());
    //
    //         let body: Body = res.into_body();
    //         let body = to_bytes(body)
    //             .await?;
    //         println!("Body:\n{}", String::from_utf8_lossy(&body));
    //     // async_std::task::spawn(res.into_body().into_future());
    // // }




            // Create a TCP listener via tokio.
            let tcp = TcpListener::bind(&addr).await.unwrap();
            let tls_acceptor = TlsAcceptor::from(tls_cfg);
            // Prepare a long-running future stream to accept and serve clients.
            // let incoming_tls_stream = stream! {
            //     loop {
            //         let (socket, _) = tcp.accept().await?;
            //         let stream = tls_acceptor.accept(socket).map_err(|e| {
            //             println!("[!] Voluntary server halt due to client-connection error...");
            //             // Errors could be handled here, instead of server aborting.
            //             // Ok(None)
            //             error(format!("TLS Error: {:?}", e))
            //         });
            //         yield stream.await;
            //     }
            // };
            loop {
                match tcp.accept().await {
                    Err(x) => {
                        return Err(x.into());
                    }
                    Ok((stream,addr)) => {
                        // let addr = stream.local_addr().unwrap();
                                let tls_stream = tls_acceptor.accept(stream).await.unwrap();

                        let listener = HyperStream(tls_stream);


                        async_std::task::spawn(async{
                            Http::new().with_executor(HyperExecutor).serve_connection(listener, service_fn(echo)).await.unwrap()
                        }
                        );
                    }
                }
            }


/*            let service = make_service_fn(|_| async { Ok::<_, io::Error>(service_fn(echo)) });
            let server = Server::builder(HyperListener {
                tls_acceptor,

                tcp_listener: tcp
            })
                .serve(service);

            // Run the future, keep going until an error occurs.
            println!("Starting to serve on https://{}.", addr);
            server.await.unwrap();*/
    })
}
// Custom echo service, handling two different routes and a
// catch-all 404 responder.
async fn echo(req: Request<Body>) -> Result<Response<Body>, hyper::Error> {
    let mut response = Response::new(Body::empty());
    match (req.method(), req.uri().path()) {
        // Help route.
        (&Method::GET, "/") => {
            *response.body_mut() = Body::from("Try POST /echo\n");
        }
        // Echo service route.
        (&Method::POST, "/echo") => {
            *response.body_mut() = req.into_body();
        }
        // Catch-all 404.
        _ => {
            *response.status_mut() = StatusCode::NOT_FOUND;
        }
    };
    Ok(response)
}
