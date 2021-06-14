#[derive(Clone, PartialEq, ::prost::Message)]
pub struct User {
    #[prost(string, tag = "1")]
    pub pswd: ::prost::alloc::string::String,
    #[prost(uint64, tag = "2")]
    pub upload: u64,
    #[prost(uint64, tag = "3")]
    pub download: u64,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListUsersRequest {}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct ListUsersResponse {
    #[prost(message, optional, tag = "1")]
    pub user: ::core::option::Option<User>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetUserRequest {
    #[prost(string, tag = "1")]
    pub pswd: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GetUserResponse {
    #[prost(message, optional, tag = "1")]
    pub user: ::core::option::Option<User>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UpsertUserRequest {
    #[prost(message, optional, tag = "1")]
    pub user: ::core::option::Option<User>,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct RemoveUserRequest {
    #[prost(string, tag = "1")]
    pub pswd: ::prost::alloc::string::String,
}
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct SetUserResponse {
    #[prost(bool, tag = "1")]
    pub success: bool,
}
#[doc = r" Generated server implementations."]
pub mod user_management_server {
    #![allow(unused_variables, dead_code, missing_docs)]
    use tonic::codegen::*;
    #[doc = "Generated trait containing gRPC methods that should be implemented for use with UserManagementServer."]
    #[async_trait]
    pub trait UserManagement: Send + Sync + 'static {
        #[doc = "Server streaming response type for the ListUsers method."]
        type ListUsersStream: futures_core::Stream<Item = Result<super::ListUsersResponse, tonic::Status>>
            + Send
            + Sync
            + 'static;
        #[doc = " list all users"]
        async fn list_users(
            &self,
            request: tonic::Request<super::ListUsersRequest>,
        ) -> Result<tonic::Response<Self::ListUsersStream>, tonic::Status>;
        #[doc = " obtain specified user's info"]
        async fn get_user(
            &self,
            request: tonic::Request<super::GetUserRequest>,
        ) -> Result<tonic::Response<super::GetUserResponse>, tonic::Status>;
        #[doc = " setup exsisting users' config"]
        async fn upsert_user(
            &self,
            request: tonic::Request<super::UpsertUserRequest>,
        ) -> Result<tonic::Response<super::SetUserResponse>, tonic::Status>;
        async fn remove_user(
            &self,
            request: tonic::Request<super::RemoveUserRequest>,
        ) -> Result<tonic::Response<super::SetUserResponse>, tonic::Status>;
    }
    #[derive(Debug)]
    pub struct UserManagementServer<T: UserManagement> {
        inner: _Inner<T>,
    }
    struct _Inner<T>(Arc<T>, Option<tonic::Interceptor>);
    impl<T: UserManagement> UserManagementServer<T> {
        pub fn new(inner: T) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner, None);
            Self { inner }
        }
        pub fn with_interceptor(inner: T, interceptor: impl Into<tonic::Interceptor>) -> Self {
            let inner = Arc::new(inner);
            let inner = _Inner(inner, Some(interceptor.into()));
            Self { inner }
        }
    }
    impl<T, B> Service<http::Request<B>> for UserManagementServer<T>
    where
        T: UserManagement,
        B: HttpBody + Send + Sync + 'static,
        B::Error: Into<StdError> + Send + 'static,
    {
        type Response = http::Response<tonic::body::BoxBody>;
        type Error = Never;
        type Future = BoxFuture<Self::Response, Self::Error>;
        fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
            Poll::Ready(Ok(()))
        }
        fn call(&mut self, req: http::Request<B>) -> Self::Future {
            let inner = self.inner.clone();
            match req.uri().path() {
                "/api.UserManagement/ListUsers" => {
                    #[allow(non_camel_case_types)]
                    struct ListUsersSvc<T: UserManagement>(pub Arc<T>);
                    impl<T: UserManagement>
                        tonic::server::ServerStreamingService<super::ListUsersRequest>
                        for ListUsersSvc<T>
                    {
                        type Response = super::ListUsersResponse;
                        type ResponseStream = T::ListUsersStream;
                        type Future =
                            BoxFuture<tonic::Response<Self::ResponseStream>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::ListUsersRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).list_users(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1;
                        let inner = inner.0;
                        let method = ListUsersSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.server_streaming(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/api.UserManagement/GetUser" => {
                    #[allow(non_camel_case_types)]
                    struct GetUserSvc<T: UserManagement>(pub Arc<T>);
                    impl<T: UserManagement> tonic::server::UnaryService<super::GetUserRequest> for GetUserSvc<T> {
                        type Response = super::GetUserResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::GetUserRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).get_user(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = GetUserSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/api.UserManagement/UpsertUser" => {
                    #[allow(non_camel_case_types)]
                    struct UpsertUserSvc<T: UserManagement>(pub Arc<T>);
                    impl<T: UserManagement> tonic::server::UnaryService<super::UpsertUserRequest> for UpsertUserSvc<T> {
                        type Response = super::SetUserResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::UpsertUserRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).upsert_user(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = UpsertUserSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                "/api.UserManagement/RemoveUser" => {
                    #[allow(non_camel_case_types)]
                    struct RemoveUserSvc<T: UserManagement>(pub Arc<T>);
                    impl<T: UserManagement> tonic::server::UnaryService<super::RemoveUserRequest> for RemoveUserSvc<T> {
                        type Response = super::SetUserResponse;
                        type Future = BoxFuture<tonic::Response<Self::Response>, tonic::Status>;
                        fn call(
                            &mut self,
                            request: tonic::Request<super::RemoveUserRequest>,
                        ) -> Self::Future {
                            let inner = self.0.clone();
                            let fut = async move { (*inner).remove_user(request).await };
                            Box::pin(fut)
                        }
                    }
                    let inner = self.inner.clone();
                    let fut = async move {
                        let interceptor = inner.1.clone();
                        let inner = inner.0;
                        let method = RemoveUserSvc(inner);
                        let codec = tonic::codec::ProstCodec::default();
                        let mut grpc = if let Some(interceptor) = interceptor {
                            tonic::server::Grpc::with_interceptor(codec, interceptor)
                        } else {
                            tonic::server::Grpc::new(codec)
                        };
                        let res = grpc.unary(method, req).await;
                        Ok(res)
                    };
                    Box::pin(fut)
                }
                _ => Box::pin(async move {
                    Ok(http::Response::builder()
                        .status(200)
                        .header("grpc-status", "12")
                        .header("content-type", "application/grpc")
                        .body(tonic::body::BoxBody::empty())
                        .unwrap())
                }),
            }
        }
    }
    impl<T: UserManagement> Clone for UserManagementServer<T> {
        fn clone(&self) -> Self {
            let inner = self.inner.clone();
            Self { inner }
        }
    }
    impl<T: UserManagement> Clone for _Inner<T> {
        fn clone(&self) -> Self {
            Self(self.0.clone(), self.1.clone())
        }
    }
    impl<T: std::fmt::Debug> std::fmt::Debug for _Inner<T> {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "{:?}", self.0)
        }
    }
    impl<T: UserManagement> tonic::transport::NamedService for UserManagementServer<T> {
        const NAME: &'static str = "api.UserManagement";
    }
}
