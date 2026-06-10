use anyhow::{Context, Result};
use hyper_util::rt::TokioIo;
use image::greeter_client::GreeterClient;
use log::{error, info};
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
pub const SERVER_CID: u32 = 4;
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
