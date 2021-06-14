#![feature(maybe_uninit_ref)]
use app::config::{set_config, CONFIG};
use app::{build_cmd_response, create_cmd_user, Address, Mode, Node, ProxyBuilder};
use async_std::net::{TcpListener, TcpStream};
use async_std::task;
use async_tls::{TlsAcceptor, TlsConnector};
use bytes::BytesMut;
use clap::{App, Arg};
use command::frame::Frame;
use errors::{Error, Result};
use event_listener::Event;
use futures::TryStreamExt;
use futures_lite::future::zip;
use futures_lite::AsyncReadExt;
use futures_lite::AsyncWriteExt;
use futures_util::stream::StreamExt;
use glommio::net::UdpSocket;
use glommio::timer::sleep;
use glommio::{Local, Task};
use log::debug;
use log::info;
use network::trojan::{load_certs, load_keys};
use num_cpus;
use rustls::{
    AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient, NoClientAuth,
    RootCertStore, ServerConfig,
};
use service::db::create_db;
use service::db::model::{EntityId, ProvideAuthn};
use service::{
    api::state::State, db, db::migration::migrate, register::hyper::hyper_compat::serve_register,
};
use std::collections::VecDeque;
use std::io;
use std::io::Error as IoError;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

fn main() -> Result<()> {
    env_logger::init();
    let matches = App::new("trojan-rs")
        .version("0.1.0")
        .arg(
            Arg::new("config")
                .short('c')
                .long("config")
                .value_name("CONFIG")
                .about("Specify the config file")
                .takes_value(true)
                .required(true),
        )
        .get_matches();

    let config_path = matches.value_of("config").unwrap();
    unsafe {
        set_config(config_path)?;
    }
    let local: (&str, u16) = unsafe {
        let addr = CONFIG.assume_init_ref().local_addr.as_ref();
        let port = CONFIG.assume_init_ref().local_port;
        (addr, port)
    };

    let addr = IpAddr::from_str(unsafe { CONFIG.assume_init_ref() }.local_addr.as_ref()).unwrap();
    let local_addr = SocketAddr::new(addr, local.1);

    let cert = unsafe { CONFIG.assume_init_ref() }
        .ssl
        .server()
        .unwrap()
        .cert
        .as_ref();
    let key = unsafe { CONFIG.assume_init_ref() }
        .ssl
        .server()
        .unwrap()
        .key
        .as_ref();
    let certs = load_certs(&cert)?;
    let key = load_keys(&key)?;
    let verifier =
    //     if let Some(auth) = auth {
    //     let roots = load_certs(&auth)?;
    //     let mut client_auth_roots = RootCertStore::empty();
    //     for root in roots {
    //         client_auth_roots.add(&root).unwrap();
    //     }
    //     if require_auth {
    //         AllowAnyAuthenticatedClient::new(client_auth_roots)
    //     } else {
    //         AllowAnyAnonymousOrAuthenticatedClient::new(client_auth_roots)
    //     }
    // } else {
    //     NoClientAuth::new()
    // };
        NoClientAuth::new();
    let mut config = ServerConfig::new(verifier);
    config
        .set_single_cert(certs, key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    let tls_acceptor = TlsAcceptor::from(Arc::new(config));

    let remote: (&str, u16) = unsafe {
        let addr = CONFIG.assume_init_ref().remote_addr.as_ref();
        let port = CONFIG.assume_init_ref().remote_port;
        (addr, port)
    };
    let mut mode = Mode::Client;
    unsafe {
        if CONFIG.assume_init_ref().remote_addr.is_empty() {
            println!("server mode");
            mode = Mode::Server
        } else {
            println!("client mode");
        }
    }
    /*    let server_ft = async move {
            let listener = TcpListener::bind("0.0.0.0:80")
                .await
                .expect("listener failed");
            debug!("server: successfully binding. waiting for incoming");
            while let Some(Ok(mut tcp_stream)) = listener.incoming().next().await {
                task::spawn(async move {
                    loop {
                        let mut buf: Vec<u8> = vec![0; 1024];
                        let n = tcp_stream.read(&mut buf).await.expect("read");
                        if n == 0 {
                            debug!("close connection: {}", tcp_stream.peer_addr().unwrap());
                            break;
                        }
                        debug!("server: loop received reply back bytes: {}", n);
                        let mut str_bytes = vec![];
                        for item in buf.into_iter().take(n) {
                            str_bytes.push(item);
                        }
                        let message = String::from_utf8(str_bytes).expect("utf8");
                        debug!("server: loop received message: {}", message);
                        let resply = format!("{} reply", message);
                        let reply_bytes = resply.as_bytes();
                        debug!("sever: send back reply: {}", resply);
                        tcp_stream
                            .write_all(reply_bytes)
                            .await
                            .expect("send failed");
                    }
                });
            }
            debug!("server done");
            Ok(()) as Result<()>
        };
    */
    // let proxy = ProxyBuilder::new(local_addr, tls_acceptor);
    // task::block_on(async {
    //     task::spawn(async {
    //         server_ft.await.unwrap();
    //     });
    //     proxy.start().await;
    //     Ok(())
    // });

    // glommio::LocalExecutorBuilder::new()
    //     .name("ostrich")
    //     .make()?
    //     .run(async move {

    // let task = Task::local( async {
    //     let migration_url = "/home/damo/rust/network/proxy/flv-tls-proxy/migrations/users.sql";
    //     let db_url = "sqlite:/home/damo/rust/network/proxy/flv-tls-proxy/db/todos.db";
    //     // migrate(migration_url, db_url).await.unwrap();
    //
    //     let db = db::sqlite::connect(&db_url).await.unwrap();
    //     let state = Arc::new(State::new(db));
    //     let socket = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080);
    //     serve_register(socket, 1_000, state).await;
    //
    // } ).detach();
    // task.await;
    let mut handles = Vec::new();

    let handle = glommio::LocalExecutorBuilder::new()
        .pin_to_cpu(0)
        // .name(format!("ostrich-proxy-worker-{}", i).as_str())
        .spawn(move || async move {
            let mut tasks = Vec::new();
            match mode {
                Mode::Server => {
                    let migration_url =
                        "/home/damo/rust/network/proxy/flv-tls-proxy/migrations/users.sql";
                    // let db_url = "sqlite:/home/damo/rust/network/proxy/flv-tls-proxy/db/ostrich.db";
                    let db_url = "sqlite:/home/damo/rust/network/proxy/flv-tls-proxy/db/ostrich.db";

                    // let test_url = "sqlite:/home/damo/rust/network/proxy/flv-tls-proxy/db/sqlite.db";
                    // migrate(migration_url, db_url).await.unwrap();
                    create_db(&db_url).await.unwrap();
                    println!("after create db");
                    let db = db::sqlite::connect(&db_url)
                        .await
                        .map_err(|e| println!("db connection error: {:?}", e))
                        .unwrap();
                    println!("after connect db");
                    let mut migrate = db.clone().acquire().await.unwrap();
                    println!("before migration");
                    sqlx::query(
                        r#"
CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    token TEXT UNIQUE NOT NULL,
    role INT NOT NULL,
    created_at DATETIME  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
)
                        "#,
                    )
                    // .bind(updated.user_id)
                    // .bind(&updated.token)
                    // .bind(updated.role)
                    .execute(&mut migrate)
                    .await
                    .unwrap();
                    println!("after migration");

                    println!("Im there ");
                    // Local::later().await;
                    let register_db = db.clone();

                    let register_task = Local::local(async move {
                        let state = Arc::new(State::new(register_db));
                        let socket = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), 8080);
                        serve_register(socket, 1_000, state).await;
                    })
                    .detach();

                    let cmd_task = Local::local(async move {
                        let socket = UdpSocket::bind("127.0.0.1:12771").unwrap();
                        let mut buf = vec![0u8; 1024];

                        println!("Listening on {}", socket.local_addr().unwrap());

                        loop {
                            let (n, peer) = socket.recv_from(&mut buf).await.unwrap();

                            let mut data = BytesMut::new();
                            data.extend_from_slice(&buf[..n]);

                            match Frame::get_frame_type(&data.as_ref()) {
                                Frame::CreateUserRequest => {
                                    println!("CreateUserRequest");
                                    let mut cmd_db = db.acquire().await.unwrap();

                                    Frame::unpack_msg_frame(&mut data).unwrap();
                                    //
                                    println!(
                                        "{:?}",
                                        String::from_utf8(data.to_ascii_lowercase().to_vec())
                                    );
                                    let token =
                                        String::from_utf8(data.to_ascii_lowercase().to_vec())
                                            .unwrap();
                                    // cmd_db.create_user(token,1 as EntityId).await.unwrap();

                                    let ret = create_cmd_user(cmd_db, token, 1 as EntityId).await;
                                    let mut resp = BytesMut::new();
                                    build_cmd_response(ret, &mut resp).unwrap();

                                    let sent = socket.send_to(resp.as_ref(), &peer).await.unwrap();
                                    println!("Sent {} out of {} bytes to {}", sent, n, peer);
                                }
                                Frame::CreateUserResponse => {}
                                Frame::UnKnown => {}
                            }
                        }
                    })
                    .detach();

                    tasks.push(register_task);
                    tasks.push(cmd_task);
                }
                Mode::Client => {
                    // let addr0 =
                    //     IpAddr::from_str(unsafe { CONFIG.assume_init_ref() }.remote_addr.as_ref())
                    //         .unwrap();
                    let remote_addr = format!("{}:{}", remote.0, remote.1);

                    Local::local(async move {
                        loop {
                            let addr = Address {
                                ip: remote.0.to_string(),
                                port: remote.1,
                            };
                            // let mut list = Vec::with_capacity(1);
                            let total = 50;
                            let node = Node {
                                addr,
                                count: 0,
                                total,
                                last_update: chrono::Utc::now().timestamp(),
                            };

                            let body = serde_json::to_vec(&node)
                                .map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))
                                .unwrap();
                            // Create a request.
                            match surf::post(&remote_addr).body(body).await {
                                Ok(mut resp) => {
                                    info!("reportingS internal{}", resp.status());
                                }
                                Err(e) => {
                                    info!("{:?}", e)
                                }
                            }
                            sleep(Duration::from_secs(3 * 60)).await;
                        }
                    })
                    .detach();
                }
            }
            use futures::future::join_all;
            join_all(tasks).await;
        })
        .unwrap();

    handles.push(handle);
    let cpus = num_cpus::get();
    // let cpus = 1;
    let (n, m): (usize, usize) = match cpus > 1 {
        true => (1, cpus),
        false => (0, cpus),
    };

    /*    (n..m)
    .map(|i| {
        let tls_acceptor = tls_acceptor.clone();
        let proxy = ProxyBuilder::new(local_addr, tls_acceptor.clone());
        let j = i;
        let handle = glommio::LocalExecutorBuilder::new()
            .name(format!("ostrich-proxy-worker-{}", i).as_str())
            .pin_to_cpu(i)
            .spawn(move || async move {
                println!("Im here: {:?}", j);
                proxy.start(j).await;
            })
            .unwrap();
        handles.push(handle);
    })
    .collect::<Vec<_>>();*/
    println!("handles len {}", handles.len());
    handles
        .into_iter()
        .for_each(|handle| handle.join().unwrap());
    // });
    // Ok::<(), Error>(())

    Ok(())
}
