// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{anyhow, bail, Context, Result};
use log::info;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::env;
use std::fs::{self, File};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};
use walkdir::WalkDir;

const ONE_MIB: u64 = 1024 * 1024;
const EXT4_MIN_HEADROOM_MB: u64 = 8;
const EXT4_MIN_IMAGE_SIZE_MB: u64 = 16;
const SHARED_ROOTFS_DIR_ENV: &str = "COCO_SHARED_ROOTFS_DIR";
const DEFAULT_SHARED_ROOTFS_DIR: &str = "/tmp/run/image-rs/shared-rootfs";
const SHARED_ROOTFS_CACHE_DIR: &str = "cache";
const SHARED_ROOTFS_IMAGES_DIR: &str = "images";
const SHARED_ROOTFS_BUNDLES_DIR: &str = "bundles";
const CACHE_FILE_SUFFIX: &str = "json";
const PENDING_FILE_SUFFIX: &str = "pending";
const BUNDLE_ROOTFS_DIR: &str = "rootfs";
const BUNDLE_CONFIG_JSON: &str = "config.json";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootfsImageFormat {
    Erofs,
    Squashfs,
    Ext4,
}

impl RootfsImageFormat {
    pub fn as_fs_type(self) -> &'static str {
        match self {
            RootfsImageFormat::Erofs => "erofs",
            RootfsImageFormat::Squashfs => "squashfs",
            RootfsImageFormat::Ext4 => "ext4",
        }
    }
}

#[derive(Clone, Debug)]
pub struct BuildRootfsImageOptions {
    pub rootfs_dir: PathBuf,
    pub output_image: PathBuf,
    pub format: RootfsImageFormat,
    pub image_size_mb: u64,
    pub squashfs_compressor: String,
}

impl BuildRootfsImageOptions {
    pub fn erofs(rootfs_dir: impl Into<PathBuf>, output_image: impl Into<PathBuf>) -> Self {
        Self {
            rootfs_dir: rootfs_dir.into(),
            output_image: output_image.into(),
            format: RootfsImageFormat::Erofs,
            image_size_mb: 0,
            squashfs_compressor: "gzip".to_string(),
        }
    }

    pub fn squashfs(rootfs_dir: impl Into<PathBuf>, output_image: impl Into<PathBuf>) -> Self {
        Self {
            rootfs_dir: rootfs_dir.into(),
            output_image: output_image.into(),
            format: RootfsImageFormat::Squashfs,
            image_size_mb: 64,
            squashfs_compressor: "gzip".to_string(),
        }
    }

    pub fn ext4(rootfs_dir: impl Into<PathBuf>, output_image: impl Into<PathBuf>) -> Self {
        Self {
            rootfs_dir: rootfs_dir.into(),
            output_image: output_image.into(),
            format: RootfsImageFormat::Ext4,
            image_size_mb: EXT4_MIN_IMAGE_SIZE_MB,
            squashfs_compressor: "gzip".to_string(),
        }
    }
}

pub fn rootfs_image_format_candidates() -> Vec<RootfsImageFormat> {
    let mut formats = Vec::new();

    if command_available("mkfs.erofs") {
        formats.push(RootfsImageFormat::Erofs);
    }
    if command_available("mksquashfs") {
        formats.push(RootfsImageFormat::Squashfs);
    }

    formats.push(RootfsImageFormat::Ext4);
    formats
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RootfsImageInfo {
    pub path: PathBuf,
    pub format: RootfsImageFormat,
    pub size: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SharedRootfsCacheEntry {
    pub image_ref: String,
    pub image_id: String,
    pub fs_type: String,
    pub image_size: u64,
    pub block_size: u64,
    pub rootfs_digest: String,
    pub oci_config_json: Vec<u8>,
    pub source_rd_addr: u64,
    pub share_id: u64,
    pub page_count: u64,
    pub rootfs_image_path: PathBuf,
}

#[derive(Clone, Debug)]
pub struct MountSharedRootfsOptions {
    pub image_path: PathBuf,
    pub work_dir: PathBuf,
    pub fs_type: Option<String>,
    pub direct_block_device: bool,
}

impl MountSharedRootfsOptions {
    pub fn new(image_path: impl Into<PathBuf>, work_dir: impl Into<PathBuf>) -> Self {
        Self {
            image_path: image_path.into(),
            work_dir: work_dir.into(),
            fs_type: None,
            direct_block_device: false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MountedSharedRootfs {
    pub loop_device: String,
    pub lower_dir: PathBuf,
    pub upper_dir: PathBuf,
    pub overlay_work_dir: PathBuf,
    pub rootfs_dir: PathBuf,
}

pub fn build_rootfs_image(options: &BuildRootfsImageOptions) -> Result<RootfsImageInfo> {
    if !options.rootfs_dir.is_dir() {
        bail!(
            "rootfs source directory does not exist: {}",
            options.rootfs_dir.display()
        );
    }

    if let Some(parent) = options.output_image.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    if options.output_image.exists() {
        fs::remove_file(&options.output_image).with_context(|| {
            format!(
                "failed to remove old rootfs image {}",
                options.output_image.display()
            )
        })?;
    }

    match options.format {
        RootfsImageFormat::Erofs => build_erofs_image(options)?,
        RootfsImageFormat::Squashfs => build_squashfs_image(options)?,
        RootfsImageFormat::Ext4 => build_ext4_image(options)?,
    }

    let size = fs::metadata(&options.output_image)
        .with_context(|| format!("failed to stat {}", options.output_image.display()))?
        .len();
    let sha256 = sha256_file(&options.output_image)?;

    Ok(RootfsImageInfo {
        path: options.output_image.clone(),
        format: options.format,
        size,
        sha256,
    })
}

pub fn shared_rootfs_dir() -> PathBuf {
    env::var_os(SHARED_ROOTFS_DIR_ENV)
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(DEFAULT_SHARED_ROOTFS_DIR))
}

pub fn shared_rootfs_images_dir() -> PathBuf {
    shared_rootfs_dir().join(SHARED_ROOTFS_IMAGES_DIR)
}

pub fn shared_rootfs_bundles_dir() -> PathBuf {
    shared_rootfs_dir().join(SHARED_ROOTFS_BUNDLES_DIR)
}

pub fn sanitize_path_component(input: &str) -> String {
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

pub fn read_shared_rootfs_cache_entry(key: &str) -> Result<Option<SharedRootfsCacheEntry>> {
    let path = cache_path(key, CACHE_FILE_SUFFIX);
    let data = match fs::read(&path) {
        Ok(data) => data,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => return Err(err).with_context(|| format!("failed to read {}", path.display())),
    };

    let entry: SharedRootfsCacheEntry = serde_json::from_slice(&data)
        .with_context(|| format!("failed to parse {}", path.display()))?;
    validate_shared_rootfs_cache_entry(&entry)
        .with_context(|| format!("invalid shared rootfs cache entry {}", path.display()))?;

    Ok(Some(entry))
}

pub fn write_shared_rootfs_cache_entry(entry: &SharedRootfsCacheEntry) -> Result<()> {
    validate_shared_rootfs_cache_entry(entry)?;
    write_cache_entry_for_key(&entry.image_ref, entry)?;
    if entry.image_id != entry.image_ref {
        write_cache_entry_for_key(&entry.image_id, entry)?;
    }
    Ok(())
}

pub fn mark_shared_rootfs_cache_pending(image_ref: &str) -> Result<()> {
    let path = cache_path(image_ref, PENDING_FILE_SUFFIX);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    fs::write(&path, b"pending\n").with_context(|| format!("failed to write {}", path.display()))
}

pub fn clear_shared_rootfs_cache_pending(image_ref: &str) {
    let _ = fs::remove_file(cache_path(image_ref, PENDING_FILE_SUFFIX));
}

pub fn shared_rootfs_cache_pending(image_ref: &str) -> bool {
    cache_path(image_ref, PENDING_FILE_SUFFIX).is_file()
}

pub fn wait_for_shared_rootfs_cache_entry(
    image_ref: &str,
    timeout: Duration,
    poll_interval: Duration,
) -> Result<Option<SharedRootfsCacheEntry>> {
    let start = Instant::now();

    loop {
        if let Some(entry) = read_shared_rootfs_cache_entry(image_ref)? {
            return Ok(Some(entry));
        }
        if !shared_rootfs_cache_pending(image_ref) {
            return Ok(None);
        }
        if start.elapsed() >= timeout {
            return Ok(None);
        }
        thread::sleep(poll_interval);
    }
}

pub fn prepare_shared_rootfs_cache_from_bundle(
    image_ref: &str,
    image_id: &str,
    bundle_dir: &Path,
) -> Result<SharedRootfsCacheEntry> {
    if let Some(entry) = read_shared_rootfs_cache_entry(image_ref)? {
        return Ok(entry);
    }
    if let Some(entry) = read_shared_rootfs_cache_entry(image_id)? {
        write_shared_rootfs_cache_entry(&entry)?;
        return Ok(entry);
    }

    mark_shared_rootfs_cache_pending(image_ref)?;
    let result = prepare_shared_rootfs_cache_from_bundle_inner(image_ref, image_id, bundle_dir);
    clear_shared_rootfs_cache_pending(image_ref);
    result
}

fn prepare_shared_rootfs_cache_from_bundle_inner(
    image_ref: &str,
    image_id: &str,
    bundle_dir: &Path,
) -> Result<SharedRootfsCacheEntry> {
    let rootfs_dir = bundle_dir.join(BUNDLE_ROOTFS_DIR);
    if !rootfs_dir.is_dir() {
        bail!("bundle rootfs does not exist: {}", rootfs_dir.display());
    }

    let images_dir = shared_rootfs_images_dir();
    fs::create_dir_all(&images_dir)
        .with_context(|| format!("failed to create {}", images_dir.display()))?;

    let safe_image_id = sanitize_path_component(image_id);
    let build_start = Instant::now();
    let rootfs_info =
        prepare_shared_rootfs_image(&rootfs_dir, &images_dir, &safe_image_id, image_ref)?;
    info!(
        "Shared rootfs stage build_image completed: image_ref={}, path={}, fs_type={}, size={}, elapsed_ms={}",
        image_ref,
        rootfs_info.path.display(),
        rootfs_info.format.as_fs_type(),
        rootfs_info.size,
        build_start.elapsed().as_millis()
    );

    let share_start = Instant::now();
    let share =
        crate::coco_image_share::create_from_file(&rootfs_info.path).with_context(|| {
            format!(
                "failed to create RMM share for {}",
                rootfs_info.path.display()
            )
        })?;
    info!(
        "Shared rootfs stage create_rmm_share completed: image_ref={}, share_id={}, source_rd=0x{:x}, pages={}, elapsed_ms={}",
        image_ref,
        share.share_id,
        share.source_rd_addr,
        share.page_count,
        share_start.elapsed().as_millis()
    );
    let config_json = fs::read(bundle_dir.join(BUNDLE_CONFIG_JSON)).unwrap_or_default();

    let entry = SharedRootfsCacheEntry {
        image_ref: image_ref.to_string(),
        image_id: image_id.to_string(),
        fs_type: rootfs_info.format.as_fs_type().to_string(),
        image_size: rootfs_info.size,
        block_size: 4096,
        rootfs_digest: rootfs_info.sha256,
        oci_config_json: config_json,
        source_rd_addr: share.source_rd_addr,
        share_id: share.share_id,
        page_count: share.page_count,
        rootfs_image_path: rootfs_info.path,
    };
    let cache_start = Instant::now();
    write_shared_rootfs_cache_entry(&entry)?;
    info!(
        "Shared rootfs stage write_cache completed: image_ref={}, share_id={}, elapsed_ms={}",
        image_ref,
        entry.share_id,
        cache_start.elapsed().as_millis()
    );

    Ok(entry)
}

pub fn prepare_shared_rootfs_image(
    rootfs_dir: &Path,
    images_dir: &Path,
    safe_image_id: &str,
    image_ref: &str,
) -> Result<RootfsImageInfo> {
    let mut failures = Vec::new();

    for rootfs_format in rootfs_image_format_candidates() {
        let rootfs_image_path =
            images_dir.join(format!("{}.{}", safe_image_id, rootfs_format.as_fs_type()));

        if rootfs_image_path.exists() {
            let size = fs::metadata(&rootfs_image_path)
                .with_context(|| format!("failed to stat {}", rootfs_image_path.display()))?
                .len();
            let sha256 = sha256_file(&rootfs_image_path)?;
            return Ok(RootfsImageInfo {
                path: rootfs_image_path,
                format: rootfs_format,
                size,
                sha256,
            });
        }

        let options = match rootfs_format {
            RootfsImageFormat::Erofs => {
                BuildRootfsImageOptions::erofs(rootfs_dir, &rootfs_image_path)
            }
            RootfsImageFormat::Squashfs => {
                BuildRootfsImageOptions::squashfs(rootfs_dir, &rootfs_image_path)
            }
            RootfsImageFormat::Ext4 => {
                BuildRootfsImageOptions::ext4(rootfs_dir, &rootfs_image_path)
            }
        };

        match build_rootfs_image(&options) {
            Ok(info) => return Ok(info),
            Err(err) => failures.push(format!("{}: {:#}", rootfs_format.as_fs_type(), err)),
        }
    }

    bail!(
        "failed to build shared rootfs for {}; attempted formats: {}",
        image_ref,
        failures.join("; ")
    )
}

fn validate_shared_rootfs_cache_entry(entry: &SharedRootfsCacheEntry) -> Result<()> {
    if entry.image_ref.is_empty() {
        bail!("shared rootfs cache entry has empty image_ref");
    }
    if entry.image_id.is_empty() {
        bail!("shared rootfs cache entry has empty image_id");
    }
    if entry.share_id == 0 || entry.source_rd_addr == 0 {
        bail!(
            "shared rootfs cache entry has invalid RMM descriptor: share_id={} source_rd=0x{:x}",
            entry.share_id,
            entry.source_rd_addr
        );
    }
    if entry.image_size == 0 || entry.page_count == 0 {
        bail!(
            "shared rootfs cache entry has invalid image size/pages: size={} pages={}",
            entry.image_size,
            entry.page_count
        );
    }
    if !entry.rootfs_image_path.is_file() {
        bail!(
            "shared rootfs image does not exist: {}",
            entry.rootfs_image_path.display()
        );
    }
    if fs::metadata(&entry.rootfs_image_path)
        .with_context(|| format!("failed to stat {}", entry.rootfs_image_path.display()))?
        .len()
        != entry.image_size
    {
        bail!(
            "shared rootfs image size changed: {}",
            entry.rootfs_image_path.display()
        );
    }

    Ok(())
}

fn write_cache_entry_for_key(key: &str, entry: &SharedRootfsCacheEntry) -> Result<()> {
    let path = cache_path(key, CACHE_FILE_SUFFIX);
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }

    let tmp_path = path.with_extension(format!("{CACHE_FILE_SUFFIX}.tmp"));
    let data = serde_json::to_vec(entry)?;
    fs::write(&tmp_path, data)
        .with_context(|| format!("failed to write {}", tmp_path.display()))?;
    fs::rename(&tmp_path, &path).with_context(|| {
        format!(
            "failed to rename {} to {}",
            tmp_path.display(),
            path.display()
        )
    })?;

    Ok(())
}

fn cache_path(key: &str, suffix: &str) -> PathBuf {
    shared_rootfs_dir()
        .join(SHARED_ROOTFS_CACHE_DIR)
        .join(format!("{}.{}", sanitize_path_component(key), suffix))
}

pub fn mount_shared_rootfs_image(
    options: &MountSharedRootfsOptions,
) -> Result<MountedSharedRootfs> {
    if !options.image_path.exists() {
        bail!(
            "shared rootfs image does not exist: {}",
            options.image_path.display()
        );
    }

    let lower_dir = options.work_dir.join("lower");
    let upper_dir = options.work_dir.join("upper");
    let overlay_work_dir = options.work_dir.join("work");
    let rootfs_dir = options.work_dir.join("rootfs");
    let state_dir = options.work_dir.join("state");

    fs::create_dir_all(&lower_dir)?;
    fs::create_dir_all(&upper_dir)?;
    fs::create_dir_all(&overlay_work_dir)?;
    fs::create_dir_all(&rootfs_dir)?;
    fs::create_dir_all(&state_dir)?;

    cleanup_shared_rootfs_mount(&options.work_dir)?;

    let mount_device = if options.direct_block_device {
        path_arg(&options.image_path)
    } else {
        let loop_device = run_command_capture(
            "losetup",
            &[
                "--find",
                "--show",
                "--read-only",
                path_arg(&options.image_path).as_str(),
            ],
        )?;
        fs::write(state_dir.join("loopdev"), loop_device.as_bytes())?;
        loop_device
    };

    let fs_type = options.fs_type.as_deref().unwrap_or("auto");
    if fs_type == "auto" {
        run_command(
            "mount",
            &[
                "-o",
                "ro",
                mount_device.as_str(),
                path_arg(&lower_dir).as_str(),
            ],
        )?;
    } else {
        run_command(
            "mount",
            &[
                "-t",
                fs_type,
                "-o",
                "ro",
                mount_device.as_str(),
                path_arg(&lower_dir).as_str(),
            ],
        )?;
    }

    let overlay_options = format!(
        "lowerdir={},upperdir={},workdir={}",
        lower_dir.display(),
        upper_dir.display(),
        overlay_work_dir.display()
    );
    run_command(
        "mount",
        &[
            "-t",
            "overlay",
            "overlay",
            "-o",
            overlay_options.as_str(),
            path_arg(&rootfs_dir).as_str(),
        ],
    )?;

    Ok(MountedSharedRootfs {
        loop_device: if options.direct_block_device {
            String::new()
        } else {
            mount_device
        },
        lower_dir,
        upper_dir,
        overlay_work_dir,
        rootfs_dir,
    })
}

pub fn cleanup_shared_rootfs_mount(work_dir: &Path) -> Result<()> {
    let lower_dir = work_dir.join("lower");
    let rootfs_dir = work_dir.join("rootfs");
    let state_loopdev = work_dir.join("state").join("loopdev");

    if is_mountpoint(&rootfs_dir) {
        run_command("umount", &[path_arg(&rootfs_dir).as_str()])?;
    }
    if is_mountpoint(&lower_dir) {
        run_command("umount", &[path_arg(&lower_dir).as_str()])?;
    }
    if state_loopdev.is_file() {
        let loopdev = fs::read_to_string(&state_loopdev)
            .with_context(|| format!("failed to read {}", state_loopdev.display()))?
            .trim()
            .to_string();
        if !loopdev.is_empty() {
            let _ = Command::new("losetup").arg("-d").arg(loopdev).status();
        }
        let _ = fs::remove_file(state_loopdev);
    }

    Ok(())
}

pub fn sha256_file(path: &Path) -> Result<String> {
    let mut file =
        File::open(path).with_context(|| format!("failed to open {}", path.display()))?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 64 * 1024];

    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("failed to read {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(format!("{:x}", hasher.finalize()))
}

fn build_erofs_image(options: &BuildRootfsImageOptions) -> Result<()> {
    run_command(
        "mkfs.erofs",
        &[
            path_arg(&options.output_image).as_str(),
            path_arg(&options.rootfs_dir).as_str(),
        ],
    )
}

fn build_squashfs_image(options: &BuildRootfsImageOptions) -> Result<()> {
    run_command(
        "mksquashfs",
        &[
            path_arg(&options.rootfs_dir).as_str(),
            path_arg(&options.output_image).as_str(),
            "-noappend",
            "-comp",
            options.squashfs_compressor.as_str(),
            "-all-root",
            "-no-xattrs",
        ],
    )
}

fn build_ext4_image(options: &BuildRootfsImageOptions) -> Result<()> {
    let image_size_mb = ext4_image_size_mb(options)?;
    let size = format!("{}M", image_size_mb);
    run_command(
        "truncate",
        &[
            "-s",
            size.as_str(),
            path_arg(&options.output_image).as_str(),
        ],
    )?;
    run_command(
        "mkfs.ext4",
        &[
            "-q",
            "-F",
            "-d",
            path_arg(&options.rootfs_dir).as_str(),
            path_arg(&options.output_image).as_str(),
        ],
    )
}

fn ext4_image_size_mb(options: &BuildRootfsImageOptions) -> Result<u64> {
    let content_size = estimate_rootfs_content_size(&options.rootfs_dir)?;
    let headroom = EXT4_MIN_HEADROOM_MB * ONE_MIB;
    let target_size = content_size
        .saturating_mul(3)
        .saturating_div(2)
        .saturating_add(headroom);
    let estimated_mb = target_size.saturating_add(ONE_MIB - 1) / ONE_MIB;

    Ok(options.image_size_mb.max(estimated_mb.max(1)))
}

fn estimate_rootfs_content_size(rootfs_dir: &Path) -> Result<u64> {
    let mut total = 0u64;
    for entry in WalkDir::new(rootfs_dir).follow_links(false) {
        let entry = entry.with_context(|| {
            format!(
                "failed to walk rootfs source directory {}",
                rootfs_dir.display()
            )
        })?;
        let metadata = fs::symlink_metadata(entry.path())
            .with_context(|| format!("failed to stat {}", entry.path().display()))?;

        total = total.saturating_add(4096);
        if metadata.is_file() {
            total = total.saturating_add(metadata.len());
        }
    }

    Ok(total)
}

fn is_mountpoint(path: &Path) -> bool {
    path.exists()
        && Command::new("mountpoint")
            .arg("-q")
            .arg(path)
            .status()
            .map(|status| status.success())
            .unwrap_or(false)
}

fn command_available(program: &str) -> bool {
    Command::new(program).arg("--help").output().is_ok()
}

fn run_command(program: &str, args: &[&str]) -> Result<()> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute {program}"))?;

    if output.status.success() {
        Ok(())
    } else {
        Err(command_error(program, args, &output))
    }
}

fn run_command_capture(program: &str, args: &[&str]) -> Result<String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .with_context(|| format!("failed to execute {program}"))?;

    if output.status.success() {
        Ok(String::from_utf8_lossy(&output.stdout).trim().to_string())
    } else {
        Err(command_error(program, args, &output))
    }
}

fn command_error(program: &str, args: &[&str], output: &std::process::Output) -> anyhow::Error {
    anyhow!(
        "command failed: {} {}\nstatus: {}\nstdout: {}\nstderr: {}",
        program,
        args.join(" "),
        output.status,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn path_arg(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn sha256_file_returns_expected_digest() {
        let dir = tempfile::tempdir().unwrap();
        let file_path = dir.path().join("data");
        let mut file = File::create(&file_path).unwrap();
        file.write_all(b"coco shared rootfs").unwrap();
        file.flush().unwrap();

        let digest = sha256_file(&file_path).unwrap();
        assert_eq!(
            digest,
            "a98e00324361f1ea31317e16b430f5c471c900d6bb55be8373f9e0b1e3c4dd34"
        );
    }

    #[test]
    fn rootfs_image_format_reports_fs_type() {
        assert_eq!(RootfsImageFormat::Erofs.as_fs_type(), "erofs");
        assert_eq!(RootfsImageFormat::Squashfs.as_fs_type(), "squashfs");
        assert_eq!(RootfsImageFormat::Ext4.as_fs_type(), "ext4");
    }

    #[test]
    fn rootfs_image_format_candidates_keep_ext4_fallback() {
        assert!(rootfs_image_format_candidates().contains(&RootfsImageFormat::Ext4));
    }

    #[test]
    fn build_squashfs_image_when_tool_is_available() {
        if !command_available("mksquashfs") {
            eprintln!("skip squashfs build test: mksquashfs is not installed");
            return;
        }

        let dir = tempfile::tempdir().unwrap();
        let rootfs_dir = dir.path().join("rootfs");
        fs::create_dir(&rootfs_dir).unwrap();
        fs::write(rootfs_dir.join("hello.txt"), b"hello from image cvm\n").unwrap();

        let output_image = dir.path().join("rootfs.squashfs");
        let options = BuildRootfsImageOptions::squashfs(&rootfs_dir, &output_image);
        let info = build_rootfs_image(&options).unwrap();

        assert_eq!(info.path, output_image);
        assert_eq!(info.format, RootfsImageFormat::Squashfs);
        assert!(info.size > 0);
        assert_eq!(info.sha256.len(), 64);
    }

    #[test]
    fn ext4_image_size_keeps_requested_minimum() {
        let dir = tempfile::tempdir().unwrap();
        let options = BuildRootfsImageOptions {
            rootfs_dir: dir.path().to_path_buf(),
            output_image: dir.path().join("rootfs.ext4"),
            format: RootfsImageFormat::Ext4,
            image_size_mb: 16,
            squashfs_compressor: "gzip".to_string(),
        };

        assert_eq!(ext4_image_size_mb(&options).unwrap(), 16);
    }
}
