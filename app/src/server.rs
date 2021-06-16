#![warn(unused_must_use)]
#![feature(maybe_uninit_ref)]
use app::config::{set_config, CONFIG};
use app::{build_cmd_response, create_cmd_user, Address, Node, ProxyBuilder};
use async_tls::TlsAcceptor;
use bytes::BytesMut;
use clap::{App, Arg};
use command::frame::Frame;
use errors::{Error, Result};
use glommio::net::UdpSocket;
use glommio::Local;
use log::{info, warn};
use network::trojan::{load_certs, load_keys};
use num_cpus;
use rustls::{
    // AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient,
    NoClientAuth,
    // RootCertStore,
    ServerConfig,
};
use service::db::create_db;
use service::db::model::EntityId;
use service::{api::state::State, db, register::hyper::hyper_compat::serve_register};
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4, IpAddr, SocketAddr};
use std::sync::Arc;
use std::str::FromStr;
use glommio::timer::{sleep, Timer};
use std::time::Duration;

const REGISTER_PORT: u16 = 8080;
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
    let config = set_config(config_path)?;
    let local: (&str, u16) = {
        let addr = config.local_addr.as_ref();
        let port = config.local_port;
        (addr, port)
    };

    let addr = IpAddr::from_str( config.local_addr.as_ref()).unwrap();
    let local_addr = SocketAddr::new(addr, local.1);

    let cert = config
        .ssl
        .server()
        .unwrap()
        .cert
        .as_ref();
    let key = config
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
    let mut tls_config = ServerConfig::new(verifier);
    tls_config
        .set_single_cert(certs, key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;

    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let remote_addr = config.remote_addr.clone();
    let remote_port = config.remote_port;
    // let remote: (&str, u16) = (remote_addr, remote_port);
    let db_path = config.mysql.unwrap().server_addr;

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

    let available_sites = vec![
        "https://api.ipify.org?format=json",
        "https://myexternalip.com/json",
    ];
    use serde_json::Value;

    // let handle =
        glommio::LocalExecutorBuilder::new()
        // .pin_to_cpu(0)
        .make()?
        // .name(format!("ostrich-proxy-worker-{}", i).as_str())
        // .spawn(move || async move {
            .run(async move {
            // let mut handles = Arc::new(Vec::new());
                let mut handles = Vec::new();
            let mut public_ip = String::new();
            for i in 0..available_sites.len() {
                match surf::get(&available_sites[i]).await {
                    Ok(mut resp) => {
                        info!("reporting internal {}", resp.status());

                        let body: Value = resp.body_json().await.unwrap();
                        public_ip = body["ip"].as_str().unwrap().to_string();
                        break;
                        // return  Ok(ip)
                    }
                    Err(e) => {
                        info!("{:?}", e);
                        // Err(e)
                    }
                }
            }
            info!("public ip {:?}", public_ip);
            let remote_addr = if remote_addr.is_empty()
                || remote_addr == "127.0.0.1"
                || remote_addr == "localhost"
                || remote_addr == public_ip.as_str()
            {
                println!("server mode");
                format!("http://{}:{}{}", "127.0.0.1", REGISTER_PORT,"/ostrich/api/server/update")
            } else {
                println!("client mode");
                format!("http://{}:{}{}", remote_addr, remote_port,"/ostrich/api/server/update")
            };
            println!("remote_addr: {}",&remote_addr);
            // let mut tasks = Vec::new();

            // let migration_url = "/home/damo/rust/network/proxy/flv-tls-proxy/migrations/users.sql";
            // let db_url = "sqlite:/home/damo/rust/network/proxy/flv-tls-proxy/db/ostrich.db";
            // let db_url = "sqlite:/home/damo/rust/network/proxy/ostrich/db/ostrich.db";

            // let test_url = "sqlite:/home/damo/rust/network/proxy/flv-tls-proxy/db/sqlite.db";
            // migrate(migration_url, db_url).await.unwrap();
            create_db(&db_path).await.unwrap();
            println!("after create db");
            let db = db::sqlite::connect(&db_path)
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

            let register_task =glommio::LocalExecutorBuilder::new()
                .pin_to_cpu(0)
                // .name(format!("ostrich-proxy-worker-{}", i).as_str())
                .spawn(move || async move {
                    // Local::local(async move {
                        let state = Arc::new(State::new(register_db));
                        let socket = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), REGISTER_PORT);
                        serve_register(socket, 1_000, state).await;
                    // })
                    //     .detach();

                }).unwrap();


            // let register_task = Local::local(async move {
            //     let state = Arc::new(State::new(register_db));
            //     let socket = SocketAddrV4::new(Ipv4Addr::new(127, 0, 0, 1), REGISTER_PORT);
            //     serve_register(socket, 1_000, state).await;
            // })
            // .detach();

            let cmd_task = glommio::LocalExecutorBuilder::new()
                .pin_to_cpu(0)
                // .name(format!("ostrich-proxy-worker-{}", i).as_str())
                .spawn(move || async move {
                    // Local::local(async move {
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
                                    let  cmd_db = db.acquire().await.unwrap();

                                    Frame::unpack_msg_frame(&mut data).unwrap();
                                    //
                                    println!(
                                        "{:?}",
                                        String::from_utf8(data.to_ascii_lowercase().to_vec())
                                    );
                                    let token =
                                        String::from_utf8(data.to_ascii_lowercase().to_vec()).unwrap();
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
                    // })
                        // .detach();
                }).unwrap();
            let report_task = glommio::LocalExecutorBuilder::new()
                .pin_to_cpu(0)
                // .name(format!("ostrich-proxy-worker-{}", i).as_str())
                .spawn(move || async move {
                    // Local::local(async move {
                        loop {
                            // Timer::new(Duration::from_secs(10)).await;
                            std::thread::sleep(Duration::from_secs(5));
                            let addr = Address {
                                ip: public_ip.to_string(),
                                port: local_addr.port(),
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
                                Ok( resp) => {
                                    info!("reportingS internal{}", resp.status());
                                }
                                Err(e) => {
                                    info!("{:?}", e)
                                }
                            }
                        }
                    // })
                    //     .detach();
                }).unwrap();


            // tasks.push(register_task);
            handles.push(register_task);
            handles.push(cmd_task);
            handles.push(report_task);


            let cpus = num_cpus::get();
            // let cpus = 1;
            let (n, m): (usize, usize) = match cpus > 1 {
                true => (1, cpus),
                false => (0, cpus),
            };

            (n..m)
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
                .collect::<Vec<_>>();
            println!("handles len {}", handles.len());
            handles.into_iter().for_each(|handle| {
                handle.join().map_err(|e| {
                    warn!("{:?}", e);
                }).unwrap()
            });


            use futures::future::join_all;
            // join_all(tasks).await;
        });
        // .unwrap();


    // });
    // Ok::<(), Error>(())

    Ok(())
}
