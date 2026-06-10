// Copyright (c) 2022 Intel Corporation
//
// SPDX-License-Identifier: Apache-2.0
use crate::auth::Auth;
use crate::bundle::{create_runtime_config, BUNDLE_ROOTFS};
use crate::coco_image_share::SharedImage;
use crate::config::{ImageConfig, CONFIGURATION_FILE_NAME, DEFAULT_WORK_DIR};
use crate::decoder::Compression;
use crate::layer_store::LayerStore;
use crate::meta_store::{MetaStore, METAFILE};
use crate::pull::PullClient;
use crate::shared_rootfs::{
    build_rootfs_image, mount_shared_rootfs_image, BuildRootfsImageOptions,
    MountSharedRootfsOptions, RootfsImageFormat, RootfsImageInfo,
};
use crate::signature::SignatureValidator;
use crate::snapshots::{SnapshotType, Snapshotter};
use anyhow::anyhow;
use anyhow::{bail, Context, Result};
use log::error;
use log::info;
use oci_client::manifest::{OciDescriptor, OciImageManifest};
use oci_client::secrets::RegistryAuth;
use oci_client::Reference;
use oci_spec::image::{ImageConfiguration, Os};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Instant;
use tokio::sync::RwLock;
//vsock client
use crate::vsock_ttrpc_client::VsockClient;

const RUNTIME_SHARED_ROOTFS_BLOCK_DEVICE: &str = "/dev/cocoimg0";

//
#[cfg(feature = "snapshot-unionfs")]
use crate::snapshots::occlum::unionfs::Unionfs;
#[cfg(feature = "snapshot-overlayfs")]
use crate::snapshots::overlay::OverlayFs;

#[cfg(feature = "nydus")]
use crate::nydus::{service, utils};

/// The metadata info for container image layer.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct LayerMeta {
    /// Image layer compression algorithm type.
    pub decoder: Compression,

    /// Whether image layer is encrypted.
    pub encrypted: bool,

    /// The compressed digest of image layer.
    pub compressed_digest: String,

    /// The uncompressed digest of image layer.
    pub uncompressed_digest: String,

    /// The image layer storage path.
    pub store_path: String,
}

/// The metadata info for container image.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ImageMeta {
    /// The digest of the image configuration.
    pub id: String,

    /// The digest of the image.
    pub digest: String,

    /// The reference string for the image
    pub reference: String,

    /// The image configuration.
    pub image_config: ImageConfiguration,

    /// Whether image is signed.
    pub signed: bool,

    /// The metadata of image layers.
    pub layer_metas: Vec<LayerMeta>,
}
/// The`image-rs` client will support OCI image
/// pulling, image signing verfication, image layer
/// decryption/unpack/store and management.
pub struct ImageClient {
    /// The registry auths to authenticate to private registries
    pub(crate) registry_auth: Option<Auth>,

    /// The image pull security module
    /// it is used to filter image pull requests against a
    /// policy
    pub(crate) signature_validator: Option<SignatureValidator>,

    /// The metadata database for `image-rs` client.
    pub(crate) meta_store: Arc<RwLock<MetaStore>>,

    /// The supported snapshots for `image-rs` client.
    pub(crate) snapshots: HashMap<SnapshotType, Box<dyn Snapshotter>>,

    /// The config
    pub config: ImageConfig,

    /// The image layer store
    pub(crate) layer_store: LayerStore,
}

impl Default for ImageClient {
    // construct a default instance of `ImageClient`
    fn default() -> ImageClient {
        let work_dir = Path::new(DEFAULT_WORK_DIR);
        ImageClient::new(work_dir.to_path_buf())
    }
}

impl ImageClient {
    //tool
    pub fn create_parent_dirs(&self, file_path: &str) -> Result<String> {
        let path = Path::new(file_path);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
            return Ok("create dir".to_string());
        }
        return Err(anyhow!("Failed to create dir"));
    }
    ///Initialize metadata database and supported snapshots.
    pub fn init_snapshots(
        work_dir: &Path,
        _meta_store: &MetaStore,
    ) -> HashMap<SnapshotType, Box<dyn Snapshotter>> {
        let mut snapshots = HashMap::new();

        #[cfg(feature = "snapshot-overlayfs")]
        {
            let data_dir = work_dir.join(SnapshotType::Overlay.to_string());
            let overlayfs = OverlayFs::new(data_dir);
            snapshots.insert(
                SnapshotType::Overlay,
                Box::new(overlayfs) as Box<dyn Snapshotter>,
            );
        }
        #[cfg(feature = "snapshot-unionfs")]
        {
            let occlum_unionfs_index = _meta_store
                .snapshot_db
                .get(&SnapshotType::OcclumUnionfs.to_string())
                .unwrap_or(&0);
            let occlum_unionfs = Unionfs {
                data_dir: work_dir.join(SnapshotType::OcclumUnionfs.to_string()),
                index: std::sync::atomic::AtomicUsize::new(*occlum_unionfs_index),
            };
            snapshots.insert(
                SnapshotType::OcclumUnionfs,
                Box::new(occlum_unionfs) as Box<dyn Snapshotter>,
            );
        }
        snapshots
    }

    /// Create an ImageClient instance with specific work directory.
    pub fn new(work_dir: PathBuf) -> Self {
        let config = ImageConfig::try_from(work_dir.join(CONFIGURATION_FILE_NAME).as_path())
            .unwrap_or_else(|_| ImageConfig::new(work_dir.clone()));
        let meta_store = MetaStore::try_from(work_dir.join(METAFILE).as_path()).unwrap_or_default();
        let layer_store = LayerStore::new(work_dir).unwrap_or_else(|e| {
            error!("failed to construct layer store: {e:?}");
            LayerStore::default()
        });
        let snapshots = Self::init_snapshots(&config.work_dir, &meta_store);

        Self {
            meta_store: Arc::new(RwLock::new(meta_store)),
            snapshots,
            registry_auth: None,
            signature_validator: None,
            config,
            layer_store,
        }
    }
    pub async fn guest_pull_image(
        &mut self,
        image_url: &str,
        bundle_dir: &Path,
        _auth_info: &Option<&str>,
        _decrypt_config: &Option<&str>,
    ) -> Result<String> {
        self.guest_mount_shared_rootfs(image_url, bundle_dir)
            .await
            .context("failed to mount shared rootfs from image CVM")
    }

    pub async fn guest_mount_shared_rootfs(
        &mut self,
        image_url: &str,
        bundle_dir: &Path,
    ) -> Result<String> {
        let mut vsock_client = VsockClient::new().await?;
        let prepare_start = Instant::now();
        let prepared = vsock_client
            .prepare_rootfs(image_url)
            .await
            .context("failed to prepare shared rootfs in image CVM")?;
        info!(
            "Runtime shared rootfs stage prepare_rootfs_rpc completed: image_ref={}, share_id={}, elapsed_ms={}",
            image_url,
            prepared.share_id,
            prepare_start.elapsed().as_millis()
        );

        fs::create_dir_all(bundle_dir)
            .with_context(|| format!("failed to create bundle dir {}", bundle_dir.display()))?;

        write_runtime_config_from_image_cvm(bundle_dir, &prepared.oci_config_json)?;

        if prepared.share_id == 0 || prepared.source_rd_addr == 0 {
            bail!(
                "image CVM did not return an RMM rootfs share descriptor for {}",
                image_url
            );
        }

        let shared_image = SharedImage {
            share_id: prepared.share_id,
            source_rd_addr: prepared.source_rd_addr,
            image_size: prepared.image_size,
            page_count: prepared.page_count,
        };
        let mount_start = Instant::now();
        mount_prepared_shared_rootfs_fast_path(shared_image, bundle_dir, &prepared.fs_type)?;
        info!(
            "Runtime shared rootfs stage mount_fast_path completed: share_id={}, source_rd=0x{:x}, size={}, pages={}, elapsed_ms={}",
            prepared.share_id, prepared.source_rd_addr, prepared.image_size, prepared.page_count
            , mount_start.elapsed().as_millis()
        );

        Ok(prepared.image_id)
    }

    pub async fn pull_content(
        &mut self,
        image_url: &str,
        content_dir: &Path,
        auth_info: &Option<&str>,
        decrypt_config: &Option<&str>,
    ) -> Result<String> {
        self.pull_image(image_url, content_dir, auth_info, decrypt_config)
            .await
            .context("failed to pull image content as OCI bundle")
    }
    /// pull_image pulls an image with optional auth info and decrypt config
    /// and store the pulled data under user defined work_dir/layers.
    /// It will return the image ID with prepeared bundle: a rootfs directory,
    /// and config.json will be ready in the bundle_dir passed by user.
    ///
    /// If at least one of `security_validate` and `auth` in self.config is
    /// enabled, `auth_info` **must** be given. There will establish a SecureChannel
    /// due to the given `decrypt_config` which contains information about
    /// `wrapped_aa_kbc_params`.
    /// When `auth_info` parameter is given and `auth` in self.config is also enabled,
    /// this function will only try to get auth from `auth_info`, and if fails then
    /// then returns an error.
    pub async fn pull_image(
        &mut self,
        image_url: &str,
        bundle_dir: &Path,
        auth_info: &Option<&str>,
        decrypt_config: &Option<&str>,
    ) -> Result<String> {
        let reference = Reference::try_from(image_url)?;

        // Try to find a valid registry auth. Logic order
        // 1. the input parameter
        // 2. from self.registry_auth
        // 3. use Anonymous auth
        let auth = match auth_info {
            Some(input_auth) => match input_auth.split_once(':') {
                Some((username, password)) => {
                    RegistryAuth::Basic(username.to_string(), password.to_string())
                }
                None => bail!("Invalid authentication info ({:?})", auth_info),
            },
            None => match &self.registry_auth {
                Some(registry_auth) => registry_auth.credential_for_reference(&reference).await?,
                None => {
                    info!("Use Anonymous image registry auth");
                    RegistryAuth::Anonymous
                }
            },
        };

        let mut client = PullClient::new(
            reference,
            self.layer_store.clone(),
            &auth,
            self.config.max_concurrent_layer_downloads_per_image,
            self.config.skip_proxy_ips.as_deref(),
            self.config.image_pull_proxy.as_deref(),
            self.config.extra_root_certificates.clone(),
        )?;
        let (image_manifest, image_digest, image_config) = client.pull_manifest().await?;
        info!("Image manifest: {:?}\n", image_manifest);
        let id = image_manifest.config.digest.clone();

        let snapshot = match self.snapshots.get_mut(&self.config.default_snapshot) {
            Some(s) => s,
            _ => {
                bail!(
                    "default snapshot {} not found",
                    &self.config.default_snapshot
                );
            }
        };

        #[cfg(feature = "nydus")]
        if utils::is_nydus_image(&image_manifest) {
            {
                let m = self.meta_store.read().await;
                if let Some(image_data) = &m.image_db.get(&id) {
                    return service::create_nydus_bundle(image_data, bundle_dir, snapshot);
                }
            }

            #[cfg(feature = "signature")]
            if let Some(signature_validator) = &self.signature_validator {
                signature_validator
                    .check_image_signature(image_url, &image_digest, &auth)
                    .await
                    .context("image security validation failed")?;
            }

            let (mut image_data, _, _) = create_image_meta(
                &id,
                image_url,
                &image_manifest,
                &image_digest,
                &image_config,
            )?;

            return self
                .do_pull_image_with_nydus(
                    &mut client,
                    &mut image_data,
                    &image_manifest,
                    decrypt_config,
                    bundle_dir,
                )
                .await;
        }

        // If image has already been populated, just create the bundle.
        {
            let m: tokio::sync::RwLockReadGuard<'_, MetaStore> = self.meta_store.read().await;
            if let Some(image_data) = &m.image_db.get(&id) {
                return create_bundle(image_data, bundle_dir, snapshot);
            }
        }

        #[cfg(feature = "signature")]
        if let Some(signature_validator) = &self.signature_validator {
            signature_validator
                .check_image_signature(image_url, &image_digest, &auth)
                .await
                .context("image security validation failed")?;
        }

        let (mut image_data, unique_layers, unique_diff_ids) = create_image_meta(
            &id,
            image_url,
            &image_manifest,
            &image_digest,
            &image_config,
        )?;
        info!("create_image_meta!\n");
        let unique_layers_len = unique_layers.len();
        let layer_metas = client
            .async_pull_layers(
                unique_layers,
                &unique_diff_ids,
                decrypt_config,
                self.meta_store.clone(),
            )
            .await?;
        info!("async_pull_layers!\n");
        image_data.layer_metas = layer_metas;
        let layer_db: HashMap<String, LayerMeta> = image_data
            .layer_metas
            .iter()
            .map(|layer| (layer.compressed_digest.clone(), layer.clone()))
            .collect();

        self.meta_store.write().await.layer_db.extend(layer_db);
        if unique_layers_len != image_data.layer_metas.len() {
            bail!(
                " {} layers failed to pull",
                unique_layers_len - image_data.layer_metas.len()
            );
        }

        let image_id = create_bundle(&image_data, bundle_dir, snapshot)?;
        info!("create_bundle!\n");
        self.meta_store
            .write()
            .await
            .image_db
            .insert(image_data.id.clone(), image_data.clone());

        let meta_file = self
            .config
            .work_dir
            .join(METAFILE)
            .to_string_lossy()
            .to_string();
        self.meta_store
            .write()
            .await
            .write_to_file(&meta_file)
            .context("update meta store failed")?;
        Ok(image_id)
    }

    pub async fn prepare_shared_rootfs_image(
        &mut self,
        image_url: &str,
        bundle_dir: &Path,
        output_image: &Path,
        auth_info: &Option<&str>,
        decrypt_config: &Option<&str>,
    ) -> Result<RootfsImageInfo> {
        self.pull_image(image_url, bundle_dir, auth_info, decrypt_config)
            .await
            .context("failed to prepare bundle for shared rootfs image")?;

        let rootfs_dir = bundle_dir.join(BUNDLE_ROOTFS);
        if !rootfs_dir.is_dir() {
            bail!("bundle rootfs does not exist: {}", rootfs_dir.display());
        }

        let options = BuildRootfsImageOptions {
            rootfs_dir,
            output_image: output_image.to_path_buf(),
            format: RootfsImageFormat::Squashfs,
            image_size_mb: 64,
            squashfs_compressor: "gzip".to_string(),
        };
        build_rootfs_image(&options).context("failed to build shared rootfs image")
    }

    #[cfg(feature = "nydus")]
    async fn do_pull_image_with_nydus(
        &mut self,
        client: &mut PullClient<'_>,
        image_data: &mut ImageMeta,
        image_manifest: &OciImageManifest,
        decrypt_config: &Option<&str>,
        bundle_dir: &Path,
    ) -> Result<String> {
        let diff_ids = image_data.image_config.rootfs().diff_ids();
        let bootstrap_id = if !diff_ids.is_empty() {
            diff_ids[diff_ids.len() - 1].to_string()
        } else {
            bail!("Failed to get bootstrap id, diff_ids is empty");
        };

        let bootstrap = utils::get_nydus_bootstrap_desc(image_manifest)
            .ok_or_else(|| anyhow::anyhow!("Faild to get bootstrap oci descriptor"))?;
        let layer_metas = client
            .pull_bootstrap(
                bootstrap,
                bootstrap_id.to_string(),
                decrypt_config,
                self.meta_store.clone(),
            )
            .await?;
        image_data.layer_metas = vec![layer_metas];
        let layer_db: HashMap<String, LayerMeta> = image_data
            .layer_metas
            .iter()
            .map(|layer| (layer.compressed_digest.clone(), layer.clone()))
            .collect();

        self.meta_store.write().await.layer_db.extend(layer_db);

        if image_data.layer_metas.is_empty() {
            bail!("Failed to pull the bootstrap");
        }

        let reference = Reference::try_from(image_data.reference.clone())?;
        let nydus_config = self
            .config
            .get_nydus_config()
            .expect("Nydus configuration not found");
        let work_dir = self.config.work_dir.clone();
        let snapshot = match self.snapshots.get_mut(&self.config.default_snapshot) {
            Some(s) => s,
            _ => {
                bail!(
                    "default snapshot {} not found",
                    &self.config.default_snapshot
                );
            }
        };
        let image_id = service::start_nydus_service(
            image_data,
            reference,
            nydus_config,
            &work_dir,
            bundle_dir,
            snapshot,
        )
        .await?;

        self.meta_store
            .write()
            .await
            .image_db
            .insert(image_data.id.clone(), image_data.clone());

        Ok(image_id)
    }
}

fn write_runtime_config_from_image_cvm(bundle_dir: &Path, config_json: &[u8]) -> Result<()> {
    if config_json.is_empty() {
        return Ok(());
    }

    let config_path = bundle_dir.join("config.json");
    fs::write(&config_path, config_json)
        .with_context(|| format!("failed to write {}", config_path.display()))
}

fn mount_prepared_shared_rootfs_fast_path(
    shared_image: SharedImage,
    bundle_dir: &Path,
    fs_type: &str,
) -> Result<()> {
    if shared_image.image_size == 0 {
        bail!("image CVM prepared an empty RMM shared rootfs image");
    }

    let _ = crate::coco_image_share::destroy_device();
    crate::coco_image_share::create_device(shared_image)
        .context("failed to create /dev/cocoimg0 for RMM shared rootfs")?;
    preflight_shared_rootfs_block_device(Path::new(RUNTIME_SHARED_ROOTFS_BLOCK_DEVICE), fs_type)
        .context("failed to preflight /dev/cocoimg0 for RMM shared rootfs")?;

    let mut mount_options =
        MountSharedRootfsOptions::new(Path::new(RUNTIME_SHARED_ROOTFS_BLOCK_DEVICE), bundle_dir);
    mount_options.fs_type = Some(fs_type.to_string());
    mount_options.direct_block_device = true;
    mount_shared_rootfs_image(&mount_options)
        .context("failed to mount RMM shared rootfs block device")?;

    Ok(())
}

fn preflight_shared_rootfs_block_device(path: &Path, fs_type: &str) -> Result<()> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut buf = vec![0u8; 4096];

    file.read_exact(&mut buf)
        .with_context(|| format!("failed to read first 4096 bytes from {}", path.display()))?;
    match fs_type {
        "erofs" if u32::from_le_bytes(buf[1024..1028].try_into().unwrap()) != 0xE0F5E1E2 => {
            bail!(
                "{} has invalid EROFS magic at offset 1024: {:02x?}",
                path.display(),
                &buf[1024..1028]
            );
        }
        "squashfs" if &buf[0..4] != b"hsqs" => {
            bail!(
                "{} has invalid SquashFS magic at offset 0: {:02x?}",
                path.display(),
                &buf[0..4]
            );
        }
        _ => {}
    }
    Ok(())
}

/// Create image meta object with the image info
/// Return the image meta object, oci descriptors of the unique layers, and unique diff ids.
fn create_image_meta(
    id: &str,
    image_url: &str,
    image_manifest: &OciImageManifest,
    image_digest: &str,
    image_config: &str,
) -> Result<(ImageMeta, Vec<OciDescriptor>, Vec<String>)> {
    let image_data = ImageMeta {
        id: id.to_string(),
        digest: image_digest.to_string(),
        reference: image_url.to_string(),
        image_config: ImageConfiguration::from_reader(image_config.as_bytes())?,
        ..Default::default()
    };

    let diff_ids = image_data.image_config.rootfs().diff_ids();
    //check if image_config rootfs diffids num=image_manifest layers num
    if diff_ids.len() != image_manifest.layers.len() {
        bail!("Pulled number of layers mismatch with image config diff_ids");
    }

    // Note that an image's `diff_ids` may always refer to plaintext layer
    // digests. For two encryption layers encrypted from a same plaintext
    // layer, the `LayersData.Digest` of the image manifest might be different
    // because the symmetric key to encrypt is different, thus the cipher text
    // is different. Interestingly in such case the `diff_ids` of the both
    // layers are the same in the config.json.
    // Another note is that the order of layers in the image config and the
    // image manifest will always be the same, so it is safe to use a same
    // index to lookup or mark a layer.
    let mut unique_layers = Vec::new();
    let mut unique_diff_ids = Vec::new();

    let mut digests = BTreeSet::new();

    for (i, diff_id) in diff_ids.iter().enumerate() {
        if digests.contains(&image_manifest.layers[i].digest) {
            continue;
        }

        digests.insert(&image_manifest.layers[i].digest);
        unique_layers.push(image_manifest.layers[i].clone());
        unique_diff_ids.push(diff_id.to_string());
    }

    Ok((image_data, unique_layers, unique_diff_ids))
}

fn create_bundle(
    image_data: &ImageMeta,
    bundle_dir: &Path,
    snapshot: &mut Box<dyn Snapshotter>,
) -> Result<String> {
    let layer_path = image_data
        .layer_metas
        .iter()
        .rev()
        .map(|l| l.store_path.as_str())
        .collect::<Vec<&str>>();
    snapshot.mount(&layer_path, &bundle_dir.join(BUNDLE_ROOTFS))?;

    let image_config = image_data.image_config.clone();
    if image_config.os() != &Os::Linux {
        bail!("unsupport OS image {:?}", image_config.os());
    }

    create_runtime_config(&image_config, bundle_dir)?;
    let image_id = image_data.id.clone();
    Ok(image_id)
}

#[cfg(not(target_arch = "s390x"))]
#[cfg(feature = "snapshot-overlayfs")]
#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use test_utils::assert_retry;

    #[tokio::test]
    async fn test_pull_image() {
        let work_dir = tempfile::tempdir().unwrap();

        // TODO test with more OCI image registries and fix broken registries.
        let oci_images = [
            // image with duplicated layers
            "gcr.io/k8s-staging-cloud-provider-ibm/ibm-vpc-block-csi-driver:master",
            // Alibaba Container Registry
            "registry.cn-hangzhou.aliyuncs.com/acs/busybox:v1.29.2",
            // Amazon Elastic Container Registry
            // "public.ecr.aws/docker/library/hello-world:linux"

            // Azure Container Registry
            "mcr.microsoft.com/hello-world",
            // Docker container Registry
            "docker.io/busybox",
            // Google Container Registry
            "gcr.io/google-containers/busybox:1.27.2",
            // JFrog Container Registry
            // "releases-docker.jfrog.io/reg2/busybox:1.33.1"
        ];

        let mut image_client = ImageClient::new(work_dir.path().to_path_buf());
        for image in oci_images.iter() {
            let bundle_dir = tempfile::tempdir().unwrap();

            assert_retry!(
                5,
                1,
                image_client,
                pull_image,
                image,
                bundle_dir.path(),
                &None,
                &None
            );
        }

        assert_eq!(
            image_client.meta_store.read().await.image_db.len(),
            oci_images.len()
        );
    }

    #[cfg(feature = "nydus")]
    #[tokio::test]
    async fn test_nydus_image() {
        let work_dir = tempfile::tempdir().unwrap();

        let nydus_images = [
            "eci-nydus-registry.cn-hangzhou.cr.aliyuncs.com/v6/java:latest-test_nydus",
            //"eci-nydus-registry.cn-hangzhou.cr.aliyuncs.com/test/ubuntu:latest_nydus",
            //"eci-nydus-registry.cn-hangzhou.cr.aliyuncs.com/test/python:latest_nydus",
        ];

        let mut image_client = ImageClient::new(work_dir.path().to_path_buf());

        for image in nydus_images.iter() {
            let bundle_dir = tempfile::tempdir().unwrap();

            assert_retry!(
                5,
                1,
                image_client,
                pull_image,
                image,
                bundle_dir.path(),
                &None,
                &None
            );
        }

        assert_eq!(
            image_client.meta_store.read().await.image_db.len(),
            nydus_images.len()
        );
    }

    #[tokio::test]
    async fn test_image_reuse() {
        let work_dir = tempfile::tempdir().unwrap();

        let image = "mcr.microsoft.com/hello-world";

        let mut image_client = ImageClient::new(work_dir.path().to_path_buf());

        let bundle1_dir = tempfile::tempdir().unwrap();
        if let Err(e) = image_client
            .pull_image(image, bundle1_dir.path(), &None, &None)
            .await
        {
            panic!("failed to download image: {}", e);
        }

        // Pull image again.
        let bundle2_dir = tempfile::tempdir().unwrap();
        if let Err(e) = image_client
            .pull_image(image, bundle2_dir.path(), &None, &None)
            .await
        {
            panic!("failed to download image: {}", e);
        }

        // Assert that config is written out.
        assert!(bundle1_dir.path().join("config.json").exists());
        assert!(bundle2_dir.path().join("config.json").exists());

        // Assert that rootfs is populated.
        assert!(bundle1_dir.path().join("rootfs").join("hello").exists());
        assert!(bundle2_dir.path().join("rootfs").join("hello").exists());

        // Assert that image is pulled only once.
        assert_eq!(image_client.meta_store.read().await.image_db.len(), 1);
    }

    #[tokio::test]
    async fn test_meta_store_reuse() {
        let work_dir = tempfile::tempdir().unwrap();

        let image = "mcr.microsoft.com/hello-world";

        let mut image_client = ImageClient::new(work_dir.path().to_path_buf());

        let bundle_dir = tempfile::tempdir().unwrap();
        if let Err(e) = image_client
            .pull_image(image, bundle_dir.path(), &None, &None)
            .await
        {
            panic!("failed to download image: {}", e);
        }

        // Create a second temporary directory for the second image client
        let work_dir_2 = tempfile::tempdir().unwrap();
        fs::create_dir_all(work_dir_2.path()).unwrap();

        // Lock the meta store and write its data to a file in the second work directory
        // This allows the second image client to reuse the meta store and layers from the first image client
        let store = image_client.meta_store.read().await;
        let meta_store_path = work_dir_2.path().to_str().unwrap().to_owned() + "/meta_store.json";
        store.write_to_file(&meta_store_path).unwrap();

        // Initialize the second image client with the second temporary directory
        let mut image_client_2 = ImageClient::new(work_dir_2.path().to_path_buf());

        let bundle_dir_2 = tempfile::tempdir().unwrap();
        if let Err(e) = image_client_2
            .pull_image(image, bundle_dir_2.path(), &None, &None)
            .await
        {
            panic!("failed to download image: {}", e);
        }

        // Verify that the "layers" directory does not exist in the second work directory
        // This confirms that the second image client reused the meta store and layers from the first image client
        assert!(!work_dir_2.path().join("layers").exists());
    }
}
