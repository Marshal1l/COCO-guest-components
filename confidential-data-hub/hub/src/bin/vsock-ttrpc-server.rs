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
use anyhow::Result;
use image::greeter_server::{Greeter, GreeterServer};
use image::{PrepareRootfsRequest, PrepareRootfsResponse};
use image_rs::shared_rootfs::{
    build_rootfs_image, rootfs_image_format_candidates, BuildRootfsImageOptions, RootfsImageFormat,
};
use log::error;
use protos::{api::*, api_ttrpc::ImagePullServiceClient};
use std::fs;
use std::path::PathBuf;
use std::time::{SystemTime, UNIX_EPOCH};
use tonic::{Request, Response, Status};
//constant
pub const SERVER_PORT: u32 = 54321;
const NANO_PER_SECOND: i64 = 1000 * 1000 * 1000;
const IMAGE_PULL_TIMEOUT_SECS: i64 = 180;
const CDH_ADDR: &str = "unix:///run/confidential-containers/cdh.sock";
const SHARED_ROOTFS_DIR: &str = "/tmp/run/image-rs/shared-rootfs";
//imagepullservice
pub struct ImagePullService {
    client_image_pull: ImagePullServiceClient,
    timeout_image_pull_ns: i64,
}
impl ImagePullService {
    fn new(cdh_addr: &str, timeout_secs: i64) -> Self {
        let inner = ttrpc::asynchronous::Client::connect(cdh_addr).expect("connect ttrpc socket");
        let client_image_pull = ImagePullServiceClient::new(inner.clone());
        let timeout_image_pull_ns = timeout_secs
            .checked_mul(NANO_PER_SECOND)
            .expect("image pull timeout overflows i64 nanoseconds");
        ImagePullService {
            client_image_pull,
            timeout_image_pull_ns,
        }
    }

    async fn pull_image(&self, image_path: &str, bundle_path: &str) -> Result<String> {
        let req = ImagePullRequest {
            image_url: image_path.to_string(),
            bundle_path: bundle_path.to_string(),
            ..Default::default()
        };
        println!(
            "sending pull image request to CDH: {:?}, timeout={}s",
            req,
            self.timeout_image_pull_ns / NANO_PER_SECOND
        );
        let res = self
            .client_image_pull
            .pull_image(ttrpc::context::with_timeout(self.timeout_image_pull_ns), &req)
            .await?;
        println!("CDH pull image response: {:?}\n", res.manifest_digest);
        Ok(res.manifest_digest)
    }
}

pub struct MyGreeter {
    image_pull_service: ImagePullService,
}
impl MyGreeter {
    pub fn new() -> Self {
        let image_pull_service = ImagePullService::new(CDH_ADDR, IMAGE_PULL_TIMEOUT_SECS);
        Self { image_pull_service }
    }
}
#[tonic::async_trait]
impl Greeter for MyGreeter {
    async fn prepare_rootfs(
        &self,
        request: Request<PrepareRootfsRequest>,
    ) -> Result<Response<PrepareRootfsResponse>, Status> {
        let req = request.into_inner();
        let image_ref = req.image_ref;
        println!("Prepare shared rootfs request for: {}", image_ref);

        let safe_ref = sanitize_path_component(&image_ref);
        let request_id = now_millis();
        let bundle_path = PathBuf::from(SHARED_ROOTFS_DIR)
            .join("bundles")
            .join(format!("{}-{}", safe_ref, request_id));
        let images_dir = PathBuf::from(SHARED_ROOTFS_DIR).join("images");

        fs::create_dir_all(&bundle_path).map_err(|err| {
            Status::internal(format!(
                "failed to create shared rootfs bundle dir {}: {:#}",
                bundle_path.display(),
                err
            ))
        })?;
        fs::create_dir_all(&images_dir).map_err(|err| {
            Status::internal(format!(
                "failed to create shared rootfs image dir {}: {:#}",
                images_dir.display(),
                err
            ))
        })?;

        let image_id = self
            .image_pull_service
            .pull_image(&image_ref, &bundle_path.display().to_string())
            .await
            .map_err(|err| {
                error!("pull_image failed for {}: {:#}", image_ref, err);
                Status::internal(format!("pull_image failed for {}: {:#}", image_ref, err))
            })?;

        let safe_image_id = sanitize_path_component(&image_id);
        let rootfs_dir = bundle_path.join("rootfs");
        if !rootfs_dir.is_dir() {
            return Err(Status::internal(format!(
                "bundle rootfs does not exist after pull_image: {}",
                rootfs_dir.display()
            )));
        }

        let rootfs_info =
            prepare_shared_rootfs_image(&rootfs_dir, &images_dir, &safe_image_id, &image_ref)?;
        let share =
            image_rs::coco_image_share::create_from_file(&rootfs_info.path).map_err(|err| {
                error!(
                    "failed to create RMM rootfs share for {}: {:#}",
                    rootfs_info.path.display(),
                    err
                );
                Status::internal(format!(
                    "failed to create RMM rootfs share for {}: {:#}",
                    rootfs_info.path.display(),
                    err
                ))
            })?;
        println!(
            "Created RMM rootfs share: path={}, share_id={}, source_rd=0x{:x}, size={}, pages={}",
            rootfs_info.path.display(),
            share.share_id,
            share.source_rd_addr,
            share.image_size,
            share.page_count
        );

        let config_json = fs::read(bundle_path.join("config.json")).unwrap_or_default();
        let reply = PrepareRootfsResponse {
            image_id,
            fs_type: rootfs_info.format.as_fs_type().to_string(),
            image_size: rootfs_info.size,
            block_size: 4096,
            rootfs_digest: rootfs_info.sha256,
            oci_config_json: config_json,
            source_rd_addr: share.source_rd_addr,
            share_id: share.share_id,
            page_count: share.page_count,
        };

        println!(
            "Prepared RMM shared rootfs: image_ref={}, share_id={}, source_rd=0x{:x}, size={}, pages={}, digest={}",
            image_ref,
            reply.share_id,
            reply.source_rd_addr,
            reply.image_size,
            reply.page_count,
            reply.rootfs_digest
        );
        Ok(Response::new(reply))
    }
}

fn prepare_shared_rootfs_image(
    rootfs_dir: &std::path::Path,
    images_dir: &std::path::Path,
    safe_image_id: &str,
    image_ref: &str,
) -> Result<image_rs::shared_rootfs::RootfsImageInfo, Status> {
    let mut failures = Vec::new();
    for rootfs_format in rootfs_image_format_candidates() {
        let rootfs_image_path =
            images_dir.join(format!("{}.{}", safe_image_id, rootfs_format.as_fs_type()));

        if rootfs_image_path.exists() {
            let size = fs::metadata(&rootfs_image_path)
                .map_err(|err| {
                    Status::internal(format!(
                        "failed to stat cached rootfs image {}: {:#}",
                        rootfs_image_path.display(),
                        err
                    ))
                })?
                .len();
            let sha256 =
                image_rs::shared_rootfs::sha256_file(&rootfs_image_path).map_err(|err| {
                    Status::internal(format!(
                        "failed to hash cached rootfs image {}: {:#}",
                        rootfs_image_path.display(),
                        err
                    ))
                })?;
            return Ok(image_rs::shared_rootfs::RootfsImageInfo {
                path: rootfs_image_path,
                format: rootfs_format,
                size,
                sha256,
            });
        }

        let options = build_options_for_format(rootfs_format, rootfs_dir, &rootfs_image_path);
        match build_rootfs_image(&options) {
            Ok(info) => return Ok(info),
            Err(err) => {
                error!(
                    "failed to build {} shared rootfs for {}: {:#}",
                    rootfs_format.as_fs_type(),
                    image_ref,
                    err
                );
                failures.push(format!("{}: {:#}", rootfs_format.as_fs_type(), err));
            }
        }
    }

    Err(Status::internal(format!(
        "failed to build shared rootfs for {}; attempted formats: {}",
        image_ref,
        failures.join("; ")
    )))
}

fn build_options_for_format(
    format: RootfsImageFormat,
    rootfs_dir: &std::path::Path,
    rootfs_image_path: &std::path::Path,
) -> BuildRootfsImageOptions {
    match format {
        RootfsImageFormat::Erofs => BuildRootfsImageOptions::erofs(rootfs_dir, rootfs_image_path),
        RootfsImageFormat::Squashfs => {
            BuildRootfsImageOptions::squashfs(rootfs_dir, rootfs_image_path)
        }
        RootfsImageFormat::Ext4 => BuildRootfsImageOptions::ext4(rootfs_dir, rootfs_image_path),
    }
}

fn sanitize_path_component(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for ch in input.chars() {
        if ch.is_ascii_alphanumeric() || ch == '.' || ch == '-' || ch == '_' {
            out.push(ch);
        } else {
            out.push('_');
        }
    }
    if out.is_empty() {
        "image".to_string()
    } else {
        out
    }
}

fn now_millis() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0)
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
