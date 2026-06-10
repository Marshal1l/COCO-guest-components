use anyhow::{anyhow, bail, Context, Result};
use hyper_util::rt::TokioIo;
use image::greeter_client::GreeterClient;
use log::{error, info};
use prost::Message;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
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

pub async fn prepare_rootfs_fast(image_ref: &str) -> Result<image::PrepareRootfsResponse> {
    let addr = VsockAddr::new(SERVER_CID, FAST_SERVER_PORT);
    let mut stream = VsockStream::connect(addr)
        .await
        .map_err(|err| anyhow!("connect fast image-share vsock {:?}: {err}", addr))?;

    let req = image::PrepareRootfsRequest {
        image_ref: image_ref.to_string(),
    };
    let mut req_buf = Vec::with_capacity(req.encoded_len());
    req.encode(&mut req_buf)
        .context("encode fast prepare_rootfs request")?;
    write_frame(&mut stream, &req_buf)
        .await
        .context("write fast prepare_rootfs request")?;

    let status = read_status(&mut stream)
        .await
        .context("read fast prepare_rootfs status")?;
    let body = read_frame(&mut stream)
        .await
        .context("read fast prepare_rootfs response")?;
    if status != 0 {
        let message = String::from_utf8_lossy(&body);
        bail!("fast prepare_rootfs failed: {message}");
    }

    image::PrepareRootfsResponse::decode(body.as_slice())
        .context("decode fast prepare_rootfs response")
}

async fn write_frame(stream: &mut VsockStream, payload: &[u8]) -> Result<()> {
    if payload.len() > FAST_MAX_MESSAGE_SIZE {
        bail!(
            "fast image-share payload too large: {} > {}",
            payload.len(),
            FAST_MAX_MESSAGE_SIZE
        );
    }
    stream
        .write_all(&(payload.len() as u32).to_be_bytes())
        .await?;
    stream.write_all(payload).await?;
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
