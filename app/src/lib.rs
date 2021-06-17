#![feature(maybe_uninit_extra)]
#[macro_use]
extern crate log;

extern crate network;

pub mod authenticator;
pub mod config;
mod copy;
mod proxy;

pub use proxy::*;

use bytes::BytesMut;
use command::frame::Frame;
use errors::{Error, Result, ServiceError};
use serde::{Deserialize, Serialize};
use service::api::users::{User, USER_TOKEN_MAX_LEN};
use service::db::model::{EntityId, ProvideAuthn};
use service::register::handler::{ResponseBody, ResponseEntity, Role};
use sqlx::pool::PoolConnection;
use sqlx::Sqlite;

#[derive(Deserialize, Serialize, Debug, Clone)]
pub struct Address {
    pub ip: String,
    pub port: u16,
}
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

pub async fn create_cmd_user(
    mut db: PoolConnection<Sqlite>,
    token: String,
    role: EntityId,
) -> Result<ResponseEntity> {
    if token.len() > USER_TOKEN_MAX_LEN {
        return Err(Error::from(ServiceError::IllegalToken));
    }

    db.create_user(token.clone(), role as i32)
        .await
        .map_err(|_| ServiceError::TokenOccupied)?;

    let new = ResponseEntity::User(User { token, role });

    Ok(new)
}

pub fn build_cmd_response(ret: Result<ResponseEntity>, data: &mut BytesMut) -> Result<()> {
    let mut code = 200;
    let content = match ret {
        Ok(body) => {
            let resp = ResponseBody {
                code,
                msg: "Success".to_owned(),
                role: Role::User,
                ret: Some(body),
            };
            resp
        }

        Err(e) => {
            match e {
                Error::ServiceError(ServiceError::InvalidParams) => code = 400,
                Error::ServiceError(ServiceError::IllegalToken) => code = 401,
                Error::ServiceError(ServiceError::NoPermission) => code = 402,
                Error::ServiceError(ServiceError::LimitedToken) => code = 403,
                Error::ServiceError(ServiceError::IllegalAccess) => code = 404,
                Error::ServiceError(ServiceError::TokenOccupied) => code = 405,
                Error::ServiceError(ServiceError::InvalidToken) => code = 406,
                Error::ServiceError(ServiceError::InternalError) => code = 500,
                Error::ServiceError(ServiceError::DataError) => code = 500,
                _ => {
                    warn!("unknown error:{:?}", e);
                    code = 500
                } //unknown error
            }
            let resp = ResponseBody {
                code,
                msg: "Failed".to_owned(),
                role: Role::User,
                ret: None,
            };
            resp
        }
    };
    let body = serde_json::to_vec(&content).map_err(|_| ServiceError::InternalError)?;

    let frame = Frame::CreateUserResponse.pack_msg_frame(body.as_slice());

    data.reserve(frame.len());
    data.extend_from_slice(frame.as_ref());
    Ok(())
}

pub struct LogLevel {
    pub level: u8,
}
// impl From<u8> for LogLevel {
//     fn from(i: u8) -> LogLevel {
//         let level = match i {
//             0 => log::Level::Error,
//             1 => log::Level::Warn,
//             2 => log::Level::Info,
//             3 => log::Level::Debug,
//             4 => log::Level::Trace,
//             _ => log::Level::Warn,
//         };
//         level
//     }
// }
use std::{fmt, fs};
impl fmt::Display for LogLevel {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.level {
            0 => write!(f, "Error"),
            1 => write!(f, "Warn"),
            2 => write!(f, "Info"),
            3 => write!(f, "Debug"),
            4 => write!(f, "Trace"),
            _ => write!(f, "Warn"),
        }
    }
}

use flexi_logger::{
    detailed_format, opt_format, Age, Cleanup, Criterion, FileSpec, Logger, Naming, WriteMode,
};
use std::collections::HashMap;
use std::path::Path;

pub fn log_init(level: u8) -> Result<()> {
    let log_level = LogLevel { level };
    println!("log level: {:?}", log_level.to_string());
    std::env::set_var("RUST_LOG", log_level.to_string());
    // env_logger::init();
    let handle = Logger::try_with_env()
        .unwrap()
        .format(detailed_format)
        .log_to_file(FileSpec::default().use_timestamp(true).directory("./logs"))
        .write_mode(WriteMode::BufferAndFlushWith(
            10 * 1024,
            std::time::Duration::from_millis(600),
        ))
        .rotate(
            Criterion::Age(Age::Hour),
            Naming::Timestamps,
            Cleanup::KeepLogFiles(3),
        )
        .start()
        .unwrap_or_else(|e| panic!("Logger initialization failed with {:?}", e));
    Ok(())
}
// one possible implementation of walking a directory only visiting files
pub fn cleanup_log(dir: &Path) -> Result<()> {
    let mut files = HashMap::new();

    if dir.is_dir() {
        for entry in fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            println!("path: {}", path.display());
            if path.is_dir() {
                continue;
            } else {
                let metadata = fs::metadata(&path)?;
                let last_modified = metadata
                    .modified()?
                    .elapsed()
                    .map_err(|e| Error::Eor(anyhow::anyhow!("{:?}", e)))?
                    .as_secs();
                println!("last_modified: {:?}", last_modified);
                files.insert(last_modified, path);
            }
        }
        let latest = files.iter().min_by_key(|f| f.0).map(|(k, v)| *k);
        if latest.is_some() {
            let latest = latest.unwrap();
            println!("latest: {:?} files len {}", latest, files.len());
            files
                .iter()
                .filter(|(k, v)| **k != latest)
                .map(|(k, v)| {
                    println!("deleting file: {:?}", v.display());
                    std::fs::remove_file(v)
                        .map_err(|e| error!("remove file: {:?}, error: {:?}", v.display(), e));
                })
                .collect::<Vec<()>>();
        }
    }
    Ok(())
}
