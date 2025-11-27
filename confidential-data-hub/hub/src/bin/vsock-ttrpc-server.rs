#![allow(non_snake_case)]
use std::{
    pin::Pin,
    task::{Context, Poll},
};
mod protos;
use futures::Stream;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio_vsock::{VsockAddr, VsockListener, VsockStream, VMADDR_CID_ANY};
use tonic::transport::{server::Connected, Server};
pub mod image {
    tonic::include_proto!("image");
}
pub mod ioctl;
use anyhow::Result;
use base64::{engine::general_purpose::STANDARD, Engine};
use image::greeter_server::{Greeter, GreeterServer};
use image::{GetFileResponse, GetFileRpcRequest, RpcRequest, RpcResponse};
use ioctl::image_ioctl::ImageIoctl;
use log::error;
use protos::{
    api::*,
    api_ttrpc::{
        GetResourceServiceClient, ImagePullServiceClient, SealedSecretServiceClient,
        SecureMountServiceClient,
    },
    keyprovider::*,
    keyprovider_ttrpc::KeyProviderServiceClient,
};
use std::fs;
use std::path::{Path, PathBuf};
use tonic::{Request, Response, Status};
use ttrpc::{context, Client};
//constant
pub const SERVER_PORT: u32 = 54321;
const NANO_PER_SECOND: i64 = 1000 * 1000 * 1000;
const IMAGE_PULL_TIMEOUT: i64 = 30 * NANO_PER_SECOND;
const CDH_ADDR: &str = "unix:///run/confidential-containers/cdh.sock";
//imagepullservice
pub struct ImagePullService {
    client_image_pull: ImagePullServiceClient,
    client_unwrap_key: KeyProviderServiceClient,
    timeout_image_pull: i64,
}
impl ImagePullService {
    fn new(cdh_addr: &str, timeout: i64) -> Self {
        let inner = ttrpc::asynchronous::Client::connect(cdh_addr).expect("connect ttrpc socket");
        let client_image_pull = ImagePullServiceClient::new(inner.clone());
        let client_unwrap_key = KeyProviderServiceClient::new(inner.clone());
        let timeout_image_pull = timeout * NANO_PER_SECOND;
        ImagePullService {
            client_image_pull,
            client_unwrap_key,
            timeout_image_pull,
        }
    }
    async fn guest_pull_image(&self, image_path: &str, bundle_path: &str) -> Result<String> {
        let req = GuestImagePullRequest {
            image_url: image_path.to_string(),
            bundle_path: bundle_path.to_string(),
            ..Default::default()
        };
        print!("seding guest_pull_image request to CDH: {:?}\n", req);
        let res = self
            .client_image_pull
            .guest_pull_image(ttrpc::context::with_timeout(self.timeout_image_pull), &req)
            .await?;
        println!("CDH guest_pull_image response: {:?}\n", res.manifest_digest);
        Ok(res.manifest_digest)
    }

    async fn pull_content(&self, image_path: &str, content_path: &str) -> Result<String> {
        let req = ContentPullRequest {
            image_url: image_path.to_string(),
            content_path: content_path.to_string(),
            ..Default::default()
        };
        print!("seding pull image request to CDH: {:?}\n", req);
        let res = self
            .client_image_pull
            .pull_content(ttrpc::context::with_timeout(self.timeout_image_pull), &req)
            .await?;
        println!("CDH pull content response: {:?}\n", res.manifest_digest);
        Ok(res.manifest_digest)
    }
    //TODO pull image and decrypt+upack(dont prepare bundle))
    async fn pull_image(&self, image_path: &str, bundle_path: &str) -> Result<String> {
        let req = ImagePullRequest {
            image_url: image_path.to_string(),
            bundle_path: bundle_path.to_string(),
            ..Default::default()
        };
        print!("seding pull image request to CDH: {:?}\n", req);
        let res = self
            .client_image_pull
            .pull_image(ttrpc::context::with_timeout(self.timeout_image_pull), &req)
            .await?;
        println!("CDH pull image response: {:?}\n", res.manifest_digest);
        Ok(res.manifest_digest)
    }
    async fn unwrap_key(&self, annotation_path: &str) -> Result<String> {
        let KeyProviderKeyWrapProtocolInput =
            tokio::fs::read(annotation_path).await.expect("read file");
        let req = KeyProviderKeyWrapProtocolInput {
            KeyProviderKeyWrapProtocolInput,
            ..Default::default()
        };
        let res = self
            .client_unwrap_key
            .un_wrap_key(context::with_timeout(self.timeout_image_pull), &req)
            .await
            .expect("request to CDH");
        let res = STANDARD.encode(res.KeyProviderKeyWrapProtocolOutput);
        println!("{res}");
        Ok(res)
    }
}

pub struct MyGreeter {
    image_ioctl: ImageIoctl,
    image_pull_service: ImagePullService,
}
impl MyGreeter {
    pub fn new() -> Self {
        let image_pull_service = ImagePullService::new(CDH_ADDR, IMAGE_PULL_TIMEOUT);
        Self {
            image_ioctl: ImageIoctl::new(),
            image_pull_service,
        }
    }
}
#[tonic::async_trait]
impl Greeter for MyGreeter {
    async fn say_hello(
        &self,
        request: Request<RpcRequest>,
    ) -> Result<Response<RpcResponse>, Status> {
        let image_path = request.into_inner().content;
        println!("Get pull content request for: {}", image_path);
        let image_id = self
            .image_pull_service
            .pull_content(&image_path, "_")
            .await
            .unwrap();
        let reply = RpcResponse {
            content: format!("{}", image_id),
        };
        Ok(Response::new(reply))
    }

    async fn get_file(
        &self,
        request: Request<GetFileRpcRequest>,
    ) -> Result<Response<GetFileResponse>, Status> {
        let req = request.into_inner();
        println!(
            "Get file request: path={}, rd_addr=0x{:x}, ipa_start=0x{:x}, ipa_size={}",
            &req.file_path, &req.rd_addr, &req.ipa_start, &req.ipa_size
        );

        // 1.look at file_path,check if file exists
        if !Path::new(&req.file_path).exists() {
            error!("file {:?} not found!\n", &req.file_path);
            return Err(Status::not_found(format!(
                "File not found: {}",
                &req.file_path
            )));
        }
        // 2.load file by load_file_ioctl
        let load_file_result = self.image_ioctl.load_file(PathBuf::from(&req.file_path))?;
        // 3.map_ipa
        self.image_ioctl
            .map_ipa(req.rd_addr, req.ipa_start, load_file_result.file_size)?;
        let reply = GetFileResponse {
            size: load_file_result.file_size,
        };

        Ok(Response::new(reply))
    }
}

#[derive(Debug)]
struct VsockConn(VsockStream);
impl Connected for VsockConn {
    type ConnectInfo = ();
    fn connect_info(&self) -> Self::ConnectInfo {}
}
impl AsyncRead for VsockConn {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, buf)
    }
}
impl AsyncWrite for VsockConn {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}
struct VsockIncoming {
    inner: VsockListener,
}

impl VsockIncoming {
    fn new(inner: VsockListener) -> Self {
        Self { inner }
    }
}

impl Stream for VsockIncoming {
    type Item = std::io::Result<VsockConn>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let inner = self.get_mut();
        match futures::ready!(inner.inner.poll_accept(cx)) {
            Ok((stream, _addr)) => Poll::Ready(Some(Ok(VsockConn(stream)))),
            Err(e) => Poll::Ready(Some(Err(e))),
        }
    }
}
#[tokio::main]
async fn main() {
    let server_addr = VsockAddr::new(VMADDR_CID_ANY, SERVER_PORT);
    let listener = VsockListener::bind(server_addr).unwrap();
    let incoming = VsockIncoming::new(listener);
    let greeter = MyGreeter::new();
    Server::builder()
        .add_service(GreeterServer::new(greeter))
        .serve_with_incoming(incoming)
        .await
        .expect("server crash");
}
