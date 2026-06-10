use anyhow::{anyhow, bail, Context, Result};
use hyper_util::rt::TokioIo;
use image::greeter_client::GreeterClient;
use log::{error, info};
use prost::Message;
use std::sync::LazyLock;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio_vsock::{VsockAddr, VsockStream};
use tonic::{
    transport::{Channel, Endpoint, Uri},
    Request,
};
use tower::service_fn;
pub mod image {
    tonic::include_proto!("image");
}
pub const SERVER_PORT: u32 = 54321;
pub const FAST_SERVER_PORT: u32 = 54322;
pub const SERVER_CID: u32 = 4;
const FAST_MAX_MESSAGE_SIZE: usize = 1024 * 1024;
static FAST_PRECONNECTED_STREAM: LazyLock<Mutex<Option<VsockStream>>> =
    LazyLock::new(|| Mutex::new(None));

pub struct VsockClient {
    client: GreeterClient<Channel>,
}
impl VsockClient {
    pub async fn new() -> Result<Self> {
        let endpoint = Endpoint::from_shared("http://[vsock]/".to_string())
            .context("failed to create vsock endpoint")?;

        let channel = endpoint
            .connect_with_connector(service_fn(|_: Uri| async {
                let addr = VsockAddr::new(SERVER_CID, SERVER_PORT);
                info!("Attempting to connect to vsock address: {:?}", addr);

                match VsockStream::connect(addr).await {
                    Ok(stream) => {
                        info!("vsock connection successful");
                        Ok::<_, std::io::Error>(TokioIo::new(stream))
                    }
                    Err(e) => {
                        error!("vsock connection failed: {:?}", e);
                        Err(e)
                    }
                }
            }))
            .await
            .context("failed to connect vsock endpoint")?;

        let client = GreeterClient::new(channel);

        Ok(Self { client })
    }

    pub async fn prepare_rootfs(
        &mut self,
        image_ref: &str,
    ) -> Result<image::PrepareRootfsResponse> {
        use image::PrepareRootfsRequest;

        let request = Request::new(PrepareRootfsRequest {
            image_ref: image_ref.to_string(),
        });

        let response = self
            .client
            .prepare_rootfs(request)
            .await
            .context("prepare_rootfs RPC failed")?;

        Ok(response.into_inner())
    }
}

pub async fn preconnect_fast_image_share() {
    let start = Instant::now();
    let addr = VsockAddr::new(SERVER_CID, FAST_SERVER_PORT);
    match VsockStream::connect(addr).await {
        Ok(stream) => {
            let mut cached = FAST_PRECONNECTED_STREAM.lock().await;
            *cached = Some(stream);
            println!(
                "Runtime fast image share preconnect completed: elapsed_ms={}",
                start.elapsed().as_millis()
            );
        }
        Err(err) => {
            println!(
                "Runtime fast image share preconnect failed: elapsed_ms={}, error={}",
                start.elapsed().as_millis(),
                err
            );
        }
    }
}

pub async fn prepare_rootfs_fast(image_ref: &str) -> Result<image::PrepareRootfsResponse> {
    let total_start = Instant::now();
    let addr = VsockAddr::new(SERVER_CID, FAST_SERVER_PORT);
    let mut stream = match take_preconnected_stream().await {
        Some(stream) => {
            println!(
                "Runtime fast image share stage use_preconnected completed: image_ref={}, elapsed_ms=0",
                image_ref
            );
            stream
        }
        None => {
            let connect_start = Instant::now();
            let stream = VsockStream::connect(addr)
                .await
                .map_err(|err| anyhow!("connect fast image-share vsock {:?}: {err}", addr))?;
            println!(
                "Runtime fast image share stage connect completed: image_ref={}, elapsed_ms={}",
                image_ref,
                connect_start.elapsed().as_millis()
            );
            stream
        }
    };

    let encode_start = Instant::now();
    let req = image::PrepareRootfsRequest {
        image_ref: image_ref.to_string(),
    };
    let mut req_buf = Vec::with_capacity(req.encoded_len());
    req.encode(&mut req_buf)
        .context("encode fast prepare_rootfs request")?;
    println!(
        "Runtime fast image share stage encode_request completed: image_ref={}, bytes={}, elapsed_ms={}",
        image_ref,
        req_buf.len(),
        encode_start.elapsed().as_millis()
    );

    let write_start = Instant::now();
    write_frame(&mut stream, &req_buf)
        .await
        .context("write fast prepare_rootfs request")?;
    println!(
        "Runtime fast image share stage write_request completed: image_ref={}, bytes={}, elapsed_ms={}",
        image_ref,
        req_buf.len(),
        write_start.elapsed().as_millis()
    );

    let read_start = Instant::now();
    let status = read_status(&mut stream)
        .await
        .context("read fast prepare_rootfs status")?;
    let body = read_frame(&mut stream)
        .await
        .context("read fast prepare_rootfs response")?;
    println!(
        "Runtime fast image share stage read_response completed: image_ref={}, status={}, bytes={}, elapsed_ms={}",
        image_ref,
        status,
        body.len(),
        read_start.elapsed().as_millis()
    );
    if status != 0 {
        let message = String::from_utf8_lossy(&body);
        bail!("fast prepare_rootfs failed: {message}");
    }

    let decode_start = Instant::now();
    let response = image::PrepareRootfsResponse::decode(body.as_slice())
        .context("decode fast prepare_rootfs response")?;
    println!(
        "Runtime fast image share stage decode_response completed: image_ref={}, share_id={}, elapsed_ms={}, total_ms={}",
        image_ref,
        response.share_id,
        decode_start.elapsed().as_millis(),
        total_start.elapsed().as_millis()
    );
    Ok(response)
}

async fn take_preconnected_stream() -> Option<VsockStream> {
    FAST_PRECONNECTED_STREAM.lock().await.take()
}

async fn write_frame(stream: &mut VsockStream, payload: &[u8]) -> Result<()> {
    if payload.len() > FAST_MAX_MESSAGE_SIZE {
        bail!(
            "fast image-share payload too large: {} > {}",
            payload.len(),
            FAST_MAX_MESSAGE_SIZE
        );
    }
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame).await?;
    Ok(())
}

async fn read_status(stream: &mut VsockStream) -> Result<u8> {
    let mut status = [0u8; 1];
    stream.read_exact(&mut status).await?;
    Ok(status[0])
}

async fn read_frame(stream: &mut VsockStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > FAST_MAX_MESSAGE_SIZE {
        bail!(
            "fast image-share response too large: {} > {}",
            len,
            FAST_MAX_MESSAGE_SIZE
        );
    }

    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    Ok(payload)
}
