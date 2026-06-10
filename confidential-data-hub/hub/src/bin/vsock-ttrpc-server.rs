#![allow(non_snake_case)]
use std::{
    pin::Pin,
    sync::Arc,
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
use anyhow::{Context as AnyhowContext, Result};
use image::greeter_server::{Greeter, GreeterServer};
use image::{PrepareRootfsRequest, PrepareRootfsResponse};
use image_rs::shared_rootfs::{
    prepare_shared_rootfs_cache_from_bundle, read_shared_rootfs_cache_entry,
    shared_rootfs_bundles_dir, shared_rootfs_cache_pending, shared_rootfs_images_dir,
    wait_for_shared_rootfs_cache_entry, SharedRootfsCacheEntry,
};
use log::error;
use prost::Message;
use protos::{api::*, api_ttrpc::ImagePullServiceClient};
use std::fs;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tonic::{Request, Response, Status};
//constant
pub const SERVER_PORT: u32 = 54321;
pub const FAST_SERVER_PORT: u32 = 54322;
const FAST_MAX_MESSAGE_SIZE: usize = 1024 * 1024;
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
        prepare_rootfs_response(&self.image_pull_service, req)
            .await
            .map(Response::new)
    }
}

async fn prepare_rootfs_response(
    image_pull_service: &ImagePullService,
    req: PrepareRootfsRequest,
) -> Result<PrepareRootfsResponse, Status> {
    let image_ref = req.image_ref;
    let total_start = Instant::now();
    println!("Prepare shared rootfs request for: {}", image_ref);

    if let Some(entry) = lookup_cached_shared_rootfs(&image_ref, total_start)? {
        return Ok(reply_from_cache_entry(entry));
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
    let image_id = image_pull_service
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

    Ok(reply_from_cache_entry(entry))
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
    let fast_service = ImagePullService::new(CDH_ADDR, IMAGE_PULL_TIMEOUT_SECS);

    tokio::spawn(async move {
        if let Err(err) = run_fast_vsock_server(fast_service).await {
            println!("Fast image share vsock server disabled: {:#}", err);
        }
    });

    Server::builder()
        .add_service(GreeterServer::new(greeter))
        .serve_with_incoming(incoming)
        .await
        .expect("server crash");
}

async fn run_fast_vsock_server(image_pull_service: ImagePullService) -> std::io::Result<()> {
    let server_addr = VsockAddr::new(VMADDR_CID_ANY, FAST_SERVER_PORT);
    let listener = VsockListener::bind(server_addr)?;
    let image_pull_service = Arc::new(image_pull_service);
    println!(
        "Fast image share vsock server listening on port {}",
        FAST_SERVER_PORT
    );

    loop {
        let (stream, peer_addr) = listener.accept().await?;
        println!("Fast image share connection accepted: peer={:?}", peer_addr);
        let image_pull_service = Arc::clone(&image_pull_service);
        tokio::spawn(async move {
            if let Err(err) = handle_fast_vsock_connection(stream, image_pull_service).await {
                println!("Fast image share request failed: {:#}", err);
            }
        });
    }
}

async fn handle_fast_vsock_connection(
    mut stream: VsockStream,
    image_pull_service: Arc<ImagePullService>,
) -> Result<(), anyhow::Error> {
    let read_start = Instant::now();
    let req_bytes = read_fast_frame(&mut stream)
        .await
        .context("read fast prepare_rootfs request")?;
    let request_start = Instant::now();
    let read_wait_ms = read_start.elapsed().as_millis();
    println!(
        "Fast image share stage read_request completed: bytes={}, elapsed_ms={}, connection_idle_ms={}",
        req_bytes.len(),
        read_wait_ms,
        read_wait_ms
    );

    let decode_start = Instant::now();
    let req = PrepareRootfsRequest::decode(req_bytes.as_slice())
        .context("decode fast prepare_rootfs request")?;
    println!(
        "Fast image share stage decode_request completed: image_ref={}, elapsed_ms={}",
        req.image_ref,
        decode_start.elapsed().as_millis()
    );

    let prepare_start = Instant::now();
    let reply = prepare_rootfs_response(&image_pull_service, req).await;
    match reply {
        Ok(reply) => {
            println!(
                "Fast image share stage prepare_response completed: share_id={}, elapsed_ms={}",
                reply.share_id,
                prepare_start.elapsed().as_millis()
            );
            let encode_start = Instant::now();
            let mut response = Vec::with_capacity(reply.encoded_len());
            reply
                .encode(&mut response)
                .context("encode fast prepare_rootfs response")?;
            println!(
                "Fast image share stage encode_response completed: share_id={}, bytes={}, elapsed_ms={}",
                reply.share_id,
                response.len(),
                encode_start.elapsed().as_millis()
            );
            let write_start = Instant::now();
            write_fast_status_and_frame(&mut stream, 0, &response)
                .await
                .context("write fast prepare_rootfs response")?;
            println!(
                "Fast image share stage write_response completed: share_id={}, bytes={}, elapsed_ms={}",
                reply.share_id,
                response.len(),
                write_start.elapsed().as_millis()
            );
            println!(
                "Fast image share request completed: elapsed_ms={}, connection_idle_ms={}",
                request_start.elapsed().as_millis(),
                read_wait_ms
            );
        }
        Err(status) => {
            let message = status.to_string();
            let write_start = Instant::now();
            write_fast_status_and_frame(&mut stream, 1, message.as_bytes())
                .await
                .context("write fast prepare_rootfs error")?;
            println!(
                "Fast image share request failed response sent: status={}, elapsed_ms={}, total_ms={}",
                message,
                write_start.elapsed().as_millis(),
                request_start.elapsed().as_millis()
            );
        }
    }

    Ok(())
}

async fn read_fast_frame(stream: &mut VsockStream) -> Result<Vec<u8>, anyhow::Error> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > FAST_MAX_MESSAGE_SIZE {
        anyhow::bail!(
            "fast image-share request too large: {} > {}",
            len,
            FAST_MAX_MESSAGE_SIZE
        );
    }

    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}

async fn write_fast_status_and_frame(
    stream: &mut VsockStream,
    status: u8,
    payload: &[u8],
) -> Result<(), anyhow::Error> {
    if payload.len() > FAST_MAX_MESSAGE_SIZE {
        anyhow::bail!(
            "fast image-share response too large: {} > {}",
            payload.len(),
            FAST_MAX_MESSAGE_SIZE
        );
    }
    let mut frame = Vec::with_capacity(1 + 4 + payload.len());
    frame.push(status);
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame).await?;
    Ok(())
}
