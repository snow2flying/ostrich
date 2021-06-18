use crate::db::Db;
use async_std::sync::{Mutex, RwLock};
use serde::{Deserialize, Serialize};
use serde_repr::{Deserialize_repr, Serialize_repr};
use sqlx::pool::PoolConnection;
use sqlx::Sqlite;
use std::collections::VecDeque;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Address {
    pub ip: String,
    pub port: u16,
}
#[derive(Serialize_repr, Deserialize_repr)]
#[repr(u8)]
pub enum Mobile {
    Android = 0,
    IOS,
}

// pub enum Status{
//     Online = 0 ,
//     Offline
// }

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Node {
    pub addr: Address,
    pub count: usize,
    pub total: usize,
    #[serde(skip_serializing, skip_deserializing)]
    pub last_update: i64,
    // #[serde(skip_serializing,skip_deserializing)]
    // pub status: Status
}

impl PartialEq for Node {
    fn eq(&self, other: &Node) -> bool {
        self.addr.ip == other.addr.ip
    }
}

pub struct State<T> {
    pub(crate) db: T,
    pub server: Mutex<VecDeque<Node>>,
    // pub sq: RwLock<BTreeMap<String, usize>>,
    // pub index: AtomicUsize,
}

// impl<T> Deref for Arc<State<T>> {
//     type Target =  RwLock<Vec<Node>>;
//
//     fn deref(&self) -> &Self::Target {
//         &self.server
//     }
// }
//
// impl<T> DerefMut for Acr<State<T>> {
//     fn deref_mut(&mut self) -> &mut Self::Target {
//         &mut self.server
//     }
// }

impl<T> State<T>
where
    T: Db<Conn = PoolConnection<Sqlite>>,
{
    pub fn new(state: T) -> Self {
        Self {
            db: state,
            // sq: RwLock::new(BTreeMap::new()),
            server: Mutex::new(VecDeque::new()),
            // index: AtomicUsize::new(0),
        }
    }

    pub fn state(&self) -> &T {
        &self.db
    }

    pub fn server(&self) -> &Mutex<VecDeque<Node>> {
        &self.server
    }
}
