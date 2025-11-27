use anyhow::{Context, Result};
use hyper_util::rt::TokioIo;
use image::greeter_client::GreeterClient;
use log::{error, info};
use std::path::{Path, PathBuf};
use tokio_vsock::{VsockAddr, VsockStream};
use tonic::{
    transport::{Channel, Endpoint, Uri},
    Request, Response,
};
use tower::service_fn;
mod image_ioctl;
use image_ioctl::ImageIoctl;
use image_ioctl::RdIpaSizeData;
pub mod image {
    tonic::include_proto!("image");
}

pub const SERVER_PORT: u32 = 54321;
pub const SERVER_CID: u32 = 4;
pub struct VsockClient {
    client: GreeterClient<Channel>,
    image_ioctl: ImageIoctl,
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
        let image_ioctl = ImageIoctl::new();

        Ok(Self {
            client,
            image_ioctl,
        })
    }

    pub async fn say_hello(&mut self, content: &str) -> Result<String> {
        use image::RpcRequest;
        let request = Request::new(RpcRequest {
            content: content.to_string(),
        });

        let response = self
            .client
            .say_hello(request)
            .await
            .context("say_hello RPC failed")?;

        Ok(response.into_inner().content)
    }

    pub async fn get_file(
        &mut self,
        dst_file_path: PathBuf,
        src_file_path: PathBuf,
    ) -> Result<String> {
        use image::GetFileRpcRequest;

        let rd_ipa_size_data = self
            .image_ioctl
            .get_rd_ipa()
            .context("failed to get rd_ipa_size")?;

        let request = Request::new(GetFileRpcRequest {
            rd_addr: rd_ipa_size_data.rd_addr,
            ipa_start: rd_ipa_size_data.ipa_start,
            ipa_size: rd_ipa_size_data.ipa_size,
            file_path: src_file_path.display().to_string(),
        });

        let response = self
            .client
            .get_file(request)
            .await
            .context("get_file RPC failed")?;

        let file_size = response.into_inner().size;

        if file_size > 0 {
            self.image_ioctl
                .write_file(dst_file_path.clone(), file_size)
                .context("ioctl write_file failed")?;
        } else {
            anyhow::bail!("get_file: received invalid file_size (0)");
        }

        Ok(format!(
            "Successfully fetched file ({} bytes) to {:?}",
            file_size, dst_file_path
        ))
    }
}
