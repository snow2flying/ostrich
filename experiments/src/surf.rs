use glommio::{LocalExecutorBuilder, Local};
use std::io::Result;



fn main()-> Result<()> {


    let handle0 = LocalExecutorBuilder::new()
        .spawn(||  async move {
            // Local::local(async {
                let mut res = surf::get("https://httpbin.org/get").await.unwrap();
                dbg!(res.body_string().await.unwrap());
            // })
            //     .detach();
        })
        .unwrap();

    handle0.join().unwrap();
    Ok(())
}