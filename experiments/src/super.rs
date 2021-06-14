use glommio::{LocalExecutorBuilder, Local};
use network::{print_n2n_version, quick_super_node_start};
use std::os::raw::c_int;

fn main() {
    let mut handles = vec![];

    let handle0 = LocalExecutorBuilder::new()
        .spawn(|| async move {
            Local::local(async {
                let port = 7777;
                unsafe { print_n2n_version(); }
                unsafe { quick_super_node_start(port as c_int);}
            })
                .detach();
        })
        .unwrap();

    handles.push(handle0);


    // let handle1 = LocalExecutorBuilder::new()
    //     .spawn(|| async move {
    //         serve_http(([0, 0, 0, 0], 8000), hyper_demo, 1)
    //             .await
    //             .unwrap();
    //     })
    //     .unwrap();
    // handles.push(handle1);
    handles.into_iter().for_each(|handle| {
        handle.join().unwrap();
    })
}