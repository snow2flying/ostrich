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
use futures::Future;
use serde::{Deserialize, Serialize};
use service::api::users::{User, USER_TOKEN_MAX_LEN};
use service::db::model::{EntityId, ProvideAuthn};
use service::register::handler::{ResponseBody, ResponseEntity, Role};
use sqlx::pool::PoolConnection;
use sqlx::{Sqlite, SqliteConnection};

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
        .map_err(|e| ServiceError::TokenOccupied)?;

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
    let body = serde_json::to_vec(&content).map_err(|e| ServiceError::InternalError)?;

    let frame = Frame::CreateUserResponse.pack_msg_frame(body.as_slice());

    data.reserve(frame.len());
    data.extend_from_slice(frame.as_ref());
    Ok(())
}
