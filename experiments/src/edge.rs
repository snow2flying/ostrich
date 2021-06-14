use std::future::Future;
use std::task::{Poll, Context};
use std::pin::Pin;
use glommio::{LocalExecutorBuilder,enclose, Latency, Shares, Local, Task};

struct LocalSet{}

impl Future for LocalSet {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {
        // Register the waker before starting to work
        // self.context.shared.waker.register_by_ref(cx.waker());
        //
        // if self.with(|| self.tick()) {
        //     // If `tick` returns true, we need to notify the local future again:
        //     // there are still tasks remaining in the run queue.
        //     cx.waker().wake_by_ref();
        //     Poll::Pending
        // } else if self.context.tasks.borrow().owned.is_empty() {
            // If the scheduler has no remaining futures, we're done!
            println!("done");
            cx.waker().wake_by_ref();
            Poll::Pending
        // } else {
        //     // There are still futures in the local set, but we've polled all the
        //     // futures in the run queue. Therefore, we can just return Pending
        //     // since the remaining futures will be woken from somewhere else.
        //     Poll::Pending
        // }
    }
}

// loop {
// match future::poll_fn(|cx| writer.fill(cx, &mut io)).await {
// Ok(0) => return (Ok(()), io),
// Ok(_) => {}
// Err(err) => return (Err(err), io),
// }
// }


// let waker = waker_fn(|| {});
// let cx = &mut Context::from_waker(&waker);

// type JoinHandle<R> = Pin<Box<dyn Future<Output = R> + Send>>;

// use futures::channel::oneshot;


use pin_project_lite::pin_project;
use futures_lite::Stream;
use glommio::channels::shared_channel;
use futures::SinkExt;
use futures::channel::mpsc;
use glommio::timer::Timer;

use std::io::Result;
use std::thread::Thread;
use std::thread;
use std::time::Duration;


pin_project! {
    #[doc(hidden)]
    // #[allow(missing_debug_implementations)]
    // #[cfg(feature = "unstable")]
    // #[cfg_attr(feature = "docs", doc(cfg(unstable)))]
    pub struct CountFuture<S> {
        #[pin]
        stream: S,
        count: usize,

        current: usize,
    }
}

impl<S> CountFuture<S> {
    pub(crate) fn new(stream: S,count: usize) -> Self {
        Self { stream, count,current: 0 }
    }
}

impl<S> Future for CountFuture<S>
    where
        S: Stream<Item=usize>,
{
    type Output = usize;

    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let this = self.project();
        let next = futures_core::ready!(this.stream.poll_next(cx));
        println!("{:?}",next.is_some());
        match next {
            Some(c) => {
                cx.waker().wake_by_ref();
                println!("{:?}",this.count);
                *this.count -= 1usize;

                println!("cn: {:?}, ct: {:?}",c as usize,this.count);
                // if *this.count == 0usize{
                //     return Poll::Ready(*this.count)
                // }
                Poll::Pending
            }
            // None =>{
            //     println!("CountFuture end");
            //     Poll::Ready(*this.count)
            //
            // }
            None =>{
                println!("CountFuture end");
                Poll::Ready(*this.count)
            }
        }
    }
}

/*fn main(){
    let local  = LocalSet{};
    let local_ex = LocalExecutorBuilder::new()
        .pin_to_cpu(0)
        .spawn( move || async move {
                local.await;
            })
        .unwrap();
    local_ex.join().unwrap();
}*/
use network::{print_n2n_version, quick_edge_start};
use libc::{c_char};
use std::ffi::CString;
// use network::http::{serve_http, hyper_demo};
use std::rc::Rc;

struct EdgeConf{
    pub secret: *const c_char,
    pub supernode_addr: *const c_char,
    pub community_name: *const c_char,
    // pub tun_name: *const c_char,
    pub edge_addr: *const c_char,
    // pub netmask: *const c_char,
    pub mac: *const c_char,
}

// Issue curl -X GET http://127.0.0.1:8000/hello or curl -X GET http://127.0.0.1:8000/world to
// see it in action


fn main() {

    let mut handles = vec![];

    let handle0 = LocalExecutorBuilder::new()
        .spawn(|| async move {
            Local::local(async {
                let secret = CString::new("mysecretpass").expect("cannot convert source_text to c string");
                let supernode_addr = CString::new("149.28.12.210:7777").expect("cannot convert source_text to c string");
                let community_name = CString::new("mynetwork").expect("cannot convert source_text to c string");
                // let tun_name = CString::new("tun7").expect("cannot convert source_text to c string");
                let edge_addr = CString::new("10.0.0.7").expect("cannot convert source_text to c string");
                // let netmask = CString::new("255.255.255.0").expect("cannot convert source_text to c string");
                let mac = CString::new("DE:AD:BE:EF:01:10").expect("cannot convert source_text to c string");

                // int quick_edge_start(const char *secret,const char *supernode_addr,const char *community_name,
                // const char *tun_name,const char *edge_addr,const char *netmask,const char *mac);

                let conf = EdgeConf{
                    secret:secret.as_ptr(),
                    supernode_addr: supernode_addr.as_ptr(),
                    community_name: community_name.as_ptr(),
                    // tun_name: tun_name.as_ptr(),
                    edge_addr: edge_addr.as_ptr(),
                    // netmask: netmask.as_ptr(),
                    mac: mac.as_ptr()
                };

                unsafe { print_n2n_version(); }
                unsafe { quick_edge_start(conf.secret,conf.supernode_addr,conf.community_name,conf.edge_addr,conf.mac); }

            })
                .detach();
        })
        .unwrap();

    handles.push(handle0);



    // let handle1 = LocalExecutorBuilder::new()
    //     .spawn(|| async move {
    //          serve_http(([0, 0, 0, 0], 8000), hyper_demo, 1)
    //             .await
    //             .unwrap();
    //     })
    //     .unwrap();
    // handles.push(handle1);
    // handles.into_iter().for_each(|handle| {
    //     handle.join().unwrap();
    // })



/*    let capacity = num_cpus::get();
    // let (mut sender, receiver) = shared_channel::new_bounded(capacity);

    let (mut sender, receiver) = mpsc::channel(capacity);
    let mut handles = Vec::with_capacity(capacity);

    // for i in 0..capacity.clone() {
    //     let mut sender = sender.clone();
    //     let handle = std::thread::spawn(move || {
    //         let builder = LocalExecutorBuilder::new().pin_to_cpu(i);
    //         let local_ex = builder.name(i.to_string().as_str()).make().expect("failed to spawn local executor");
    //         local_ex.run(async {
    //             // Timer::new(std::time::Duration::from_millis(10)).await;
    //
    //             loop {
    //
    //             }
    //         });
    //     });
    //     handles.push(handle);
    // }




    for i in 1..capacity.clone() {
        let mut sender = sender.clone();
        let handle = LocalExecutorBuilder::new()
            .pin_to_cpu(i)
            .spawn(move || async move {
                sender.send(i).await.unwrap();
                println!("Hello {:?}!", i);
                for n in 0..10000{
                    use sha2::{Sha256, Sha512, Digest};

// create a Sha256 object
                    let mut hasher = Sha256::new();

// write input message
                    hasher.update(b"hello world");

// read hash digest and consume hasher
                    let _result = hasher.finalize();
                }
            })
            .unwrap();
        handles.push(handle);
    }

    for handle in handles{
        handle.join().unwrap()
    }
    drop(sender);

    let c = capacity.clone();
    let local_ex = LocalExecutorBuilder::new()
        .pin_to_cpu(0)
        .spawn(move || async move {

            Task::<Result<()>>::local(async move {
                loop {
                    thread::sleep(Duration::from_millis(1000));
                    println!("detach");
                }

                Ok(())
            })
                .detach();



            let cf = CountFuture::new(receiver,c);
            let size = cf.await;
            println!("cost to run task no task queue: {:#?}", size);
        })
        .unwrap();
    local_ex.join().unwrap();*/


}

/*#[derive(Debug)]
pub struct Interval {
    delay: Timer,

    interval: Duration,
}

impl Stream for Interval {
    type Item = ();

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        if Pin::new(&mut self.delay).poll(cx).is_pending() {
            return Poll::Pending;
        }
        let interval = self.interval;
        let _ = std::mem::replace(&mut self.delay, timer_after(interval));
        Poll::Ready(Some(()))
    }
}

*/

// extern crate futures;
//
// use super::interval::Interval;
// use futures::prelude::*;
//
// pub struct IntervalStream {
//     interval: Interval,
//     last: usize,
// }
//
// impl IntervalStream {
//     pub fn new(interval: Interval) -> IntervalStream {
//         let last = interval.get_counter();
//         IntervalStream { interval, last }
//     }
// }
//
// impl Stream for IntervalStream {
//     type Item = usize;
//     type Error = ();
//
//     fn poll(&mut self) -> Poll<Option<Self::Item>, Self::Error> {
//         let curr = self.interval.get_counter();
//         if curr == self.last {
//             let task = futures::task::current();
//             self.interval.set_task(task);
//             Ok(Async::NotReady)
//         } else {
//             self.last = curr;
//             Ok(Async::Ready(Some(curr)))
//         }
//     }
// }

struct Proof{}

/*impl Future for Proof {
    type Output = ();

    fn poll(self: Pin<&mut Self>, cx: &mut std::task::Context<'_>) -> Poll<Self::Output> {

        let n = 1;

        let local_ex = LocalExecutorBuilder::new()
            .pin_to_cpu(1)
            .spawn(|| async move {


                // let runs: u32 = 10_000_000;
                let tq1 = Local::create_task_queue(Shares::Static(1000), Latency::NotImportant, "tq1");
                // let t = Instant::now();
                // for _ in 0..runs {
                let mut local = LocalSet{};
                Local::local_into(async {
                    local.poll(cx);
                }, tq1).unwrap().await;
                // }
                // println!("cost to run task in task queue: {:#?}", t.elapsed() / runs);
            })
            .unwrap();

            local_ex.join().unwrap();

            // if n == 0{
            //     Poll::Pending
            // }

            Poll::Ready(())

    }
}
*/



/*fn main() {
    println!("cpu: {:#?}",num_cpus::get());
    println!("cpu_phys: {:#?}",num_cpus::get_physical());
    println!("min:{:?}",std::cmp::min(1,2));



    println!("Hello, world!");

}*/
// use futures::future::join_all;
// use glommio::prelude::*;
// use std::io::Result;
//
// async fn hello() {
//     let mut tasks = vec![];
//     for t in 0..5 {
//         tasks.push(Local::local(async move {
//             println!("{}: Hello {} ...", Local::id(), t);
//             Local::later().await;
//             println!("{}: ... {} World!", Local::id(), t);
//         }));
//     }
//     join_all(tasks).await;
// }
//
// fn main() -> Result<()> {
//     // There are two ways to create an executor, demonstrated in this example.
//     //
//     // We can create it in the current thread, and run it separately later...
//     let ex = LocalExecutorBuilder::new().pin_to_cpu(0).make()?;
//
//     // Or we can spawn a new thread with an executor inside.
//     let builder = LocalExecutorBuilder::new().pin_to_cpu(1);
//     let handle = builder.name("hello").spawn(|| async move {
//         hello().await;
//     })?;
//
//     // If you create the executor manually, you have to run it like so.
//     //
//     // spawn_new() is the preferred way to create an executor!
//     ex.run(async move {
//         hello().await;
//     });
//
//     // The newly spawned executor runs on a thread, so we need to join on
//     // its handle so we can wait for it to finish
//     handle.join().unwrap();
//     Ok(())
// }


// use glommio::{timer::Timer, LocalExecutor, LocalExecutorBuilder};
// use std::thread::Thread;
// use std::thread;
// use std::time::Duration;
//
// fn main(){
//
//     for i in 1..4 {
//         let handle = std::thread::spawn(move || {
//             let builder = LocalExecutorBuilder::new().pin_to_cpu(1);
//             let local_ex = builder.make().expect("failed to spawn local executor");
//             local_ex.run(async {
//                 // Timer::new(std::time::Duration::from_millis(1)).await;
//                 println!("Hello world!");
//             });
//         });
//         handle.join().unwrap();
//     }
//
//
//     // thread::sleep(Duration::from_millis(1000));
//     // loop {
//     //     thread::sleep(Duration::from_millis(1000));
//     // }
// }
