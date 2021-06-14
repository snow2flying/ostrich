pub mod header;
pub mod resolver;
pub mod udp;
use anyhow::anyhow;
use errors::Error;
use rustls::internal::pemfile::{certs, pkcs8_private_keys, rsa_private_keys};
use rustls::Certificate;
use rustls::PrivateKey;
use sha2::Digest;
use std::fs::File;
use std::io;
use std::io::BufReader;
use std::path::Path;

pub const DEFAULT_BUFFER_SIZE: usize = 2 * 4096;

pub fn load_certs(path: &Path) -> Result<Vec<Certificate>, Error> {
    certs(&mut BufReader::new(File::open(path)?))
        .map_err(|_| Error::Eor(anyhow!("could not find carts")))
}

#[macro_export]
macro_rules! key {
    ($e:expr,$p:ident) => {
        let reader = &mut BufReader::new(File::open($p)?);
        if let Ok(mut keys) = $e(reader) {
            if !keys.is_empty() {
                return Ok(keys.remove(0));
            }
        }
    };
}
pub fn load_keys(path: &Path) -> io::Result<PrivateKey> {
    key!(pkcs8_private_keys, path);
    key!(rsa_private_keys, path);
    Err(io::Error::new(io::ErrorKind::InvalidInput, "invalid key"))
}
// #[macro_export]
// macro_rules! users {
//     ($users:expr) => {
//         Arc::new(RwLock::new(
//             $users
//                 .iter()
//                 .map(|u| {
//                     (
//                         hex_hash(u),
//                         User {
//                             pswd: u.to_owned(),
//                             upload: 0,
//                             download: 0,
//                         },
//                     )
//                 })
//                 .collect(),
//         ))
//     };
// }

#[macro_export]
macro_rules! ready {
    ($e:expr $(,)?) => {
        match $e {
            std::task::Poll::Ready(t) => t,
            std::task::Poll::Pending => return std::task::Poll::Pending,
        }
    };
}

#[inline]
pub fn hex_hash(content: &str) -> Box<[u8]> {
    let mut bytes = [0u8; 56];
    hex::encode_to_slice(&sha2::Sha224::digest(content.as_bytes())[..], &mut bytes)
        .unwrap_or_default();
    Box::new(bytes)
}
