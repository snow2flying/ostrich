use async_std::future::timeout;
use async_std::net::UdpSocket;
use async_std::task;
use bytes::BytesMut;
use clap::{crate_version, FromArgMatches, IntoApp};

use std::time::Duration;
use command::{build_cmd,opt::Opt};
use service::register::handler::{ResponseBody, ResponseEntity};
use command::frame::Frame;
use comfy_table::Table;

fn main() -> std::io::Result<()> {
    let matches = Opt::into_app().version(crate_version!()).get_matches();

    task::block_on(async {
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let mut data = BytesMut::default();
        build_cmd(Opt::from_arg_matches(&matches), &mut data).await;
        // let test = String::from_utf8(data.to_vec()).unwrap();
        // Frame::unpack_msg_frame( &mut data).unwrap();
        //
        // println!("{:?}",String::from_utf8(data.to_ascii_lowercase().to_vec()));

        // build_cmd().await;
        //
        // let msg = "hello world";
        // println!("<- {}", msg);
        // // socket.send_to(msg.as_bytes(), "127.0.0.1:8080").await?;
        timeout(
            Duration::from_secs(60),
            socket.send_to(data.as_ref(), "127.0.0.1:12771"),
        )
        .await;
        //
        let mut buf = vec![0u8; 10240];
        let (n, _) = timeout(Duration::from_secs(60), socket.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        let mut data = BytesMut::new();
        data.extend_from_slice(&buf[..n]);
        let mut table = Table::new();

        match Frame::get_frame_type(&data.as_ref()){
            Frame::CreateUserRequest => {

            }
            Frame::CreateUserResponse =>{
                Frame::unpack_msg_frame( &mut data).unwrap();
                let resp: ResponseBody<ResponseEntity> = serde_json::from_slice(data.as_ref()).unwrap();
                let t = resp.ret;
                if t.is_some(){
                    match t.unwrap() {
                        ResponseEntity::User(user) => {
                            table
                                .set_header(vec!["Status", "Msg", "UserName"])
                                .add_row(vec![
                                    resp.code.to_string(),
                                    resp.msg,
                                    user.token,
                                ]);
                                // .add_row(vec![
                                //     "This is another text",
                                //     "Now\nadd some\nmulti line stuff",
                                //     "This is awesome",
                                // ]);

                            println!("{}", table);
                        }
                        ResponseEntity::Server(_) => {}
                        ResponseEntity::Status => {}
                    }
                }else{
                    table
                        .set_header(vec!["Status", "Msg"])
                        .add_row(vec![
                            resp.code.to_string(),
                            resp.msg
                        ]);
                    println!("{}", table);
                }

            }
            _ => {
                println!("unmatched msg")
            }
        }
        // println!("-> {:?}\n", buf.to_ascii_lowercase().as_slice());
        // let resp: ResponseBody<ResponseEntity> = serde_json::from_slice(buf.as_slice()).unwrap();
        // println!("-> {:?}\n", resp.msg);
        std::process::exit(1);
    })

    // no special handling here
    //     Opt::from_arg_matches(&matches) {
    //
    //     std::process::exit(1);
    // }
}
