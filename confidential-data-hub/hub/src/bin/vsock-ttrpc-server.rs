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
    prepare_shared_rootfs_cache_from_bundle, read_shared_rootfs_cache_entry,
    shared_rootfs_bundles_dir, shared_rootfs_cache_pending, shared_rootfs_images_dir,
    wait_for_shared_rootfs_cache_entry, SharedRootfsCacheEntry,
};
use log::error;
use protos::{api::*, api_ttrpc::ImagePullServiceClient};
use std::fs;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tonic::{Request, Response, Status};
//constant
pub const SERVER_PORT: u32 = 54321;
const NANO_PER_SECOND: i64 = 1000 * 1000 * 1000;
const IMAGE_PULL_TIMEOUT_SECS: i64 = 180;
const CDH_ADDR: &str = "unix:///run/confidential-containers/cdh.sock";
const PENDING_CACHE_WAIT_SECS: u64 = 12;
const PENDING_CACHE_POLL_MS: u64 = 200;
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
            .pull_image(
                ttrpc::context::with_timeout(self.timeout_image_pull_ns),
                &req,
            )
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
        let total_start = Instant::now();
        println!("Prepare shared rootfs request for: {}", image_ref);

        if let Some(entry) = lookup_cached_shared_rootfs(&image_ref, total_start)? {
            return Ok(Response::new(reply_from_cache_entry(entry)));
        }

        let safe_ref = sanitize_path_component(&image_ref);
        let request_id = now_millis();
        let bundle_path = shared_rootfs_bundles_dir().join(format!("{}-{}", safe_ref, request_id));
        let images_dir = shared_rootfs_images_dir();

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

        let pull_start = Instant::now();
        let image_id = self
            .image_pull_service
            .pull_image(&image_ref, &bundle_path.display().to_string())
            .await
            .map_err(|err| {
                error!("pull_image failed for {}: {:#}", image_ref, err);
                Status::internal(format!("pull_image failed for {}: {:#}", image_ref, err))
            })?;
        println!(
            "Image share stage pull_image completed: image_ref={}, image_id={}, elapsed_ms={}",
            image_ref,
            image_id,
            pull_start.elapsed().as_millis()
        );

        let cache_start = Instant::now();
        let entry = prepare_shared_rootfs_cache_from_bundle(&image_ref, &image_id, &bundle_path)
            .map_err(|err| {
                error!(
                    "failed to prepare shared rootfs cache for {}: {:#}",
                    image_ref, err
                );
                Status::internal(format!(
                    "failed to prepare shared rootfs cache for {}: {:#}",
                    image_ref, err
                ))
            })?;
        println!(
            "Created RMM rootfs share: path={}, share_id={}, source_rd=0x{:x}, size={}, pages={}",
            entry.rootfs_image_path.display(),
            entry.share_id,
            entry.source_rd_addr,
            entry.image_size,
            entry.page_count
        );
        println!(
            "Image share stage cache/share completed: image_ref={}, share_id={}, elapsed_ms={}, total_ms={}",
            image_ref,
            entry.share_id,
            cache_start.elapsed().as_millis(),
            total_start.elapsed().as_millis()
        );

        Ok(Response::new(reply_from_cache_entry(entry)))
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

fn lookup_cached_shared_rootfs(
    image_ref: &str,
    start: Instant,
) -> Result<Option<SharedRootfsCacheEntry>, Status> {
    match read_shared_rootfs_cache_entry(image_ref) {
        Ok(Some(entry)) => {
            println!(
                "Shared rootfs cache hit: image_ref={}, share_id={}, total_ms={}",
                image_ref,
                entry.share_id,
                start.elapsed().as_millis()
            );
            return Ok(Some(entry));
        }
        Ok(None) => {}
        Err(err) => {
            println!(
                "Shared rootfs cache miss after invalid entry: image_ref={}, error={:#}",
                image_ref, err
            );
        }
    }

    if !shared_rootfs_cache_pending(image_ref) {
        return Ok(None);
    }

    match wait_for_shared_rootfs_cache_entry(
        image_ref,
        Duration::from_secs(PENDING_CACHE_WAIT_SECS),
        Duration::from_millis(PENDING_CACHE_POLL_MS),
    ) {
        Ok(Some(entry)) => {
            println!(
                "Shared rootfs cache hit after wait: image_ref={}, share_id={}, total_ms={}",
                image_ref,
                entry.share_id,
                start.elapsed().as_millis()
            );
            Ok(Some(entry))
        }
        Ok(None) => Ok(None),
        Err(err) => Err(Status::internal(format!(
            "failed waiting for shared rootfs cache for {}: {:#}",
            image_ref, err
        ))),
    }
}

fn reply_from_cache_entry(entry: SharedRootfsCacheEntry) -> PrepareRootfsResponse {
    let reply = PrepareRootfsResponse {
        image_id: entry.image_id,
        fs_type: entry.fs_type,
        image_size: entry.image_size,
        block_size: entry.block_size,
        rootfs_digest: entry.rootfs_digest,
        oci_config_json: entry.oci_config_json,
        source_rd_addr: entry.source_rd_addr,
        share_id: entry.share_id,
        page_count: entry.page_count,
    };

    println!(
        "Created RMM rootfs share: path={}, share_id={}, source_rd=0x{:x}, size={}, pages={}",
        entry.rootfs_image_path.display(),
        reply.share_id,
        reply.source_rd_addr,
        reply.image_size,
        reply.page_count
    );
    println!(
        "Prepared RMM shared rootfs: image_ref={}, share_id={}, source_rd=0x{:x}, size={}, pages={}, digest={}",
        entry.image_ref,
        reply.share_id,
        reply.source_rd_addr,
        reply.image_size,
        reply.page_count,
        reply.rootfs_digest
    );

    reply
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
