#![warn(unused_must_use)]
#![feature(maybe_uninit_ref)]
use app::config::set_config;
use app::{build_cmd_response, create_cmd_user, Address, LogLevel, Node, ProxyBuilder};
use app::{log_cleanup, log_init, DNS_CHCAE_TIMEOUT};
use async_std::sync::Mutex;
use async_tls::TlsAcceptor;
use bytes::BytesMut;
use clap::{App, Arg};
use command::frame::Frame;
use errors::{Error, Result};
use glommio::net::UdpSocket;
use glommio::timer::{sleep, timeout, Timer};
use glommio::Local;
use log::{info, warn};
use lru_time_cache::LruCache;
use network::trojan::{load_certs, load_keys};
use num_cpus;
use rustls::{
    // AllowAnyAnonymousOrAuthenticatedClient, AllowAnyAuthenticatedClient,
    NoClientAuth,
    // RootCertStore,
    ServerConfig,
};
use service::api::users::NODE_EXPIRE;
use service::db::create_db;
use service::db::model::EntityId;
use service::{api::state::State, db, register::hyper::hyper_compat::serve_register};
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4};
use std::ops::Sub;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;

const REGISTER_PORT: u16 = 8080;
fn main() -> Result<()> {
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
    // cleanup_log("./logs".as_ref())?;

    log_init(config.log_level)?;
    let local: (&str, u16) = {
        let addr = config.local_addr.as_ref();
        let port = config.local_port;
        (addr, port)
    };

    let addr = IpAddr::from_str(config.local_addr.as_ref()).unwrap();
    let local_addr = SocketAddr::new(addr, local.1);

    let cert = config.ssl.server().unwrap().cert.as_ref();
    let key = config.ssl.server().unwrap().key.as_ref();
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
    let db_path = format!("sqlite:{}", config.mysql.unwrap().server_addr);
    let available_sites = vec![
        "https://api.ipify.org?format=json",
        "https://myexternalip.com/json",
    ];
    use serde_json::Value;
    let mut handles = Vec::new();
    let handle = glommio::LocalExecutorBuilder::new()
        .spawn(move || async move {
            // .make()?
            // .run(async move {
            // let mut handles = Arc::new(Vec::new());
            // let mut handles = Vec::new();
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
                info!("server mode");
                format!(
                    "http://{}:{}{}",
                    "127.0.0.1", REGISTER_PORT, "/ostrich/api/server/update"
                )
            } else {
                info!("client mode");
                format!(
                    "http://{}:{}{}",
                    remote_addr, remote_port, "/ostrich/api/server/update"
                )
            };
            info!("remote_addr: {}", &remote_addr);
            // let mut tasks = Vec::new();

            create_db(&db_path).await.unwrap();
            info!("after create db");
            let db = db::sqlite::connect(&db_path)
                .await
                .map_err(|e| info!("db connection error: {:?}", e))
                .unwrap();
            info!("after connect db");
            let mut migrate = db.clone().acquire().await.unwrap();
            info!("before migration");
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
            .execute(&mut migrate)
            .await
            .unwrap();
            let register_db = db.clone();

            // ************************************************************************************************************************** //
            /*
            let register_task = glommio::LocalExecutorBuilder::new()
                .pin_to_cpu(0)
                // .name(format!("ostrich-proxy-worker-{}", i).as_str())
                .spawn(move || async move {
                    // Local::local(async move {
                    let state = Arc::new(State::new(register_db));
                    let socket = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), REGISTER_PORT);
                    serve_register(socket, 1_000, state).await;
                    // })
                    //     .detach();
                })
                .unwrap();

            let cmd_task = glommio::LocalExecutorBuilder::new()
                .pin_to_cpu(0)
                .spawn(move || async move {
                    // Local::local(async move {
                    let socket = UdpSocket::bind("127.0.0.1:12771").unwrap();
                    let mut buf = vec![0u8; 1024];

                    info!("Listening on {}", socket.local_addr().unwrap());

                    loop {
                        let (n, peer) = socket.recv_from(&mut buf).await.unwrap();

                        let mut data = BytesMut::new();
                        data.extend_from_slice(&buf[..n]);

                        match Frame::get_frame_type(&data.as_ref()) {
                            Frame::CreateUserRequest => {
                                info!("CreateUserRequest");
                                let cmd_db = db.acquire().await.unwrap();

                                Frame::unpack_msg_frame(&mut data).unwrap();
                                //
                                info!(
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
                                info!("Sent {} out of {} bytes to {}", sent, n, peer);
                            }
                            Frame::CreateUserResponse => {}
                            Frame::UnKnown => {}
                        }
                    }
                    // })
                    // .detach();
                })
                .unwrap();
            let report_task = glommio::LocalExecutorBuilder::new()
                .pin_to_cpu(0)
                // .name(format!("ostrich-proxy-worker-{}", i).as_str())
                .spawn(move || async move {
                    // Local::local(async move {
                    loop {
                        // Timer::new(Duration::from_secs(10)).await;
                        async_std::task::sleep(Duration::from_secs(10)).await;

                        // std::thread::sleep(Duration::from_secs(5));

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
                        use async_std::prelude::FutureExt;
                        match surf::post(&remote_addr)
                            .body(body)
                            .timeout(Duration::from_secs(60))
                            .await
                        {
                            Ok(resp) => {
                                info!("reporting internal")
                                // info!("reportingS internal {}", resp.status());
                            }
                            Err(e) => {
                                info!("{:?}", e)
                            }
                        }
                    }
                    // })
                    //     .detach();
                })
                .unwrap();
            let log_task = glommio::LocalExecutorBuilder::new()
                .pin_to_cpu(0)
                // .name(format!("ostrich-proxy-worker-{}", i).as_str())
                .spawn(move || async move {
                    // Local::local(async move {
                    loop {
                        // Timer::new(Duration::from_secs(10)).await;
                        // std::thread::sleep(Duration::from_secs(5));
                        // Timer::new(Duration::from_secs(10)).await;
                        // sleep(Duration::from_millis(100)).await;
                        async_std::task::sleep(Duration::from_secs(3 * 60)).await;
                        cleanup_log("./logs".as_ref()).unwrap();
                        // async_std::task::sleep()
                        // timeout(Duration::from_secs(60), async{
                        //     println!("timer");
                        //     Ok(())
                        //
                        // }).await;
                        // Timer::new(Duration::from_millis(100)).await;
                        // sleep(Duration::from_secs(10)).await;
                        println!("timer");
                    }
                    // })
                    //     .detach();
                })
                .unwrap();*/
            // *********************************************************************************************************** //
            let report_task = Local::local(async move {
                loop {
                    // Timer::new(Duration::from_secs(10)).await;
                    async_std::task::sleep(Duration::from_secs(3 * 60)).await;

                    // std::thread::sleep(Duration::from_secs(5));

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
                    use async_std::prelude::FutureExt;
                    match surf::post(&remote_addr)
                        .body(body)
                        .timeout(Duration::from_secs(60))
                        .await
                    {
                        Ok(resp) => {
                            info!("reporting internal")
                            // info!("reportingS internal {}", resp.status());
                        }
                        Err(e) => {
                            info!("{:?}", e)
                        }
                    }
                }
            })
            .detach();

            let log_task = Local::local(async move {
                loop {
                    // Timer::new(Duration::from_secs(10)).await;
                    // std::thread::sleep(Duration::from_secs(5));
                    // Timer::new(Duration::from_secs(10)).await;
                    // sleep(Duration::from_millis(100)).await;
                    async_std::task::sleep(Duration::from_secs(3 * 60)).await;
                    log_cleanup("./logs".as_ref()).unwrap();
                    // async_std::task::sleep()
                    // timeout(Duration::from_secs(60), async{
                    //     println!("timer");
                    //     Ok(())
                    //
                    // }).await;
                    // Timer::new(Duration::from_millis(100)).await;
                    // sleep(Duration::from_secs(10)).await;
                    println!("timer");
                }
            })
            .detach();
            let state = Arc::new(State::new(register_db));
            let cleanup_state = state.clone();
            let register_task = Local::local(async move {
                let socket = SocketAddrV4::new(Ipv4Addr::new(0, 0, 0, 0), REGISTER_PORT);
                serve_register(socket, state).await;
            })
            .detach();

            let cleanup_task = Local::local(async move {
                loop {
                    async_std::task::sleep(Duration::from_secs(5 * 60)).await;
                    let mut nodes = cleanup_state.server.lock().await;
                    let now = chrono::Utc::now().timestamp();
                    let len = nodes.len();

                    if len == 0 {
                        println!("node cache is empty");
                        drop(nodes);
                        continue;
                    }
                    println!("node cache before cleanup: {}", len);
                    for _i in 0..len {
                        let node = nodes.pop_front();
                        if node.is_none() {
                            break;
                        }
                        let node = node.unwrap();
                        if now.sub(node.last_update) < NODE_EXPIRE {
                            nodes.push_back(node);
                        }
                    }
                    println!("node cache after cleanup: {}", nodes.len());
                    drop(nodes);
                }
            })
            .detach();

            let cmd_task = Local::local(async move {
                let socket = UdpSocket::bind("127.0.0.1:12771").unwrap();
                let mut buf = vec![0u8; 1024];

                info!("Listening on {}", socket.local_addr().unwrap());

                loop {
                    let (n, peer) = socket.recv_from(&mut buf).await.unwrap();

                    let mut data = BytesMut::new();
                    data.extend_from_slice(&buf[..n]);

                    match Frame::get_frame_type(&data.as_ref()) {
                        Frame::CreateUserRequest => {
                            info!("CreateUserRequest");
                            let cmd_db = db.acquire().await.unwrap();

                            Frame::unpack_msg_frame(&mut data).unwrap();
                            //
                            info!(
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
                            info!("Sent {} out of {} bytes to {}", sent, n, peer);
                        }
                        Frame::CreateUserResponse => {}
                        Frame::UnKnown => {}
                    }
                }
            })
            .detach();
            let mut tasks = Vec::new();
            tasks.push(register_task);
            tasks.push(cmd_task);
            tasks.push(report_task);
            tasks.push(log_task);
            tasks.push(cleanup_task);
            use futures::future::join_all;
            join_all(tasks).await;
            // tasks.push(register_task);
            // handles.push(register_task);
            // handles.push(cmd_task);
            // handles.push(report_task);
            // handles.push(log_task);

            /*             let cpus = num_cpus::get();
             // let cpus = 1;
             let (n, m): (usize, usize) = match cpus > 1 {
                 true => (1, cpus),
                 false => (0, cpus),
             };

                         (n..m)
             .map(|i| {
                 let tls_acceptor = tls_acceptor.clone();
                 let proxy = ProxyBuilder::new(local_addr, tls_acceptor.clone()).await;
                 let j = i;
                 let handle = glommio::LocalExecutorBuilder::new()
                     .name(format!("ostrich-proxy-worker-{}", i).as_str())
                     .pin_to_cpu(i)
                     .spawn(move || async move {
                         info!("Im here: {:?}", j);
                         proxy.start(j).await;
                     })
                     .unwrap();
                 handles.push(handle);
             })
             .collect::<Vec<_>>();

            for i in n..m {
                 let tls_acceptor = tls_acceptor.clone();
                 let proxy = ProxyBuilder::new(local_addr, tls_acceptor.clone()).await;
                 let j = i;
                 let handle = glommio::LocalExecutorBuilder::new()
                     .name(format!("ostrich-proxy-worker-{}", i).as_str())
                     .pin_to_cpu(i)
                     .spawn(move || async move {
                         info!("Im here: {:?}", j);
                         proxy.start(j).await;
                     })
                     .unwrap();
                 handles.push(handle);
             }

             info!("handles len {}", handles.len());
             handles.into_iter().for_each(|handle| {
                 handle
                     .join()
                     .map_err(|e| {
                         warn!("{:?}", e);
                     })
                     .unwrap()*/
            // });

            // });
        })
        .unwrap();
    handles.push(handle);
    let cpus = num_cpus::get();
    // let cpus = 1;
    let (n, m): (usize, usize) = match cpus > 1 {
        true => (1, cpus),
        false => (0, cpus),
    };
    for i in n..m {
        let tls_acceptor = tls_acceptor.clone();

        let j = i;
        let handle = glommio::LocalExecutorBuilder::new()
            .name(format!("ostrich-proxy-worker-{}", i).as_str())
            .pin_to_cpu(i)
            .spawn(move || async move {
                let cache = Arc::new(Mutex::new(LruCache::with_expiry_duration(
                    Duration::from_secs(DNS_CHCAE_TIMEOUT),
                )));
                let cleanup_cache = cache.clone();
                let (cleanup_task, cleanup_abortable) = futures::future::abortable(async move {
                    loop {
                        async_std::task::sleep(Duration::from_secs(5 * 60)).await;
                        println!("dns cache cleanup");
                        let mut cleanup_cache = cleanup_cache.lock().await;
                        // cleanup expired cache. iter() will remove expired elements
                        println!("before cleanup: {}", cleanup_cache.len());
                        let _ = cleanup_cache.iter();
                        println!("after cleanup: {}", cleanup_cache.len());
                    }
                });
                async_std::task::spawn(async {
                    cleanup_task.await;
                });
                let proxy =
                    ProxyBuilder::new(local_addr, tls_acceptor.clone(), cleanup_abortable, cache)
                        .await;
                info!("Im here: {:?}", j);
                proxy.start(j).await;
            })
            .unwrap();
        handles.push(handle);
    }

    info!("handles len {}", handles.len());
    handles.into_iter().for_each(|handle| {
        handle
            .join()
            .map_err(|e| {
                warn!("{:?}", e);
            })
            .unwrap();
        // });
        // Ok::<(), Error>(())
    });
    Ok(())
}
