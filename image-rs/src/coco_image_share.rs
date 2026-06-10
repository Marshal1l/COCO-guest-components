// Copyright (c) 2026
//
// SPDX-License-Identifier: Apache-2.0

use anyhow::{bail, Context, Result};
use std::fs::{File, OpenOptions};
use std::mem;
use std::os::fd::AsRawFd;
use std::path::Path;

const COCO_IMAGE_SHARE_DEVICE: &str = "/dev/coco-image-share";
const COCO_IMAGE_SHARE_PATH_MAX: usize = 256;
const COCO_IMAGE_SHARE_FLAG_RO: u64 = 0x1;
const IOC_NRBITS: u64 = 8;
const IOC_TYPEBITS: u64 = 8;
const IOC_SIZEBITS: u64 = 14;
const IOC_NRSHIFT: u64 = 0;
const IOC_TYPESHIFT: u64 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u64 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u64 = IOC_SIZESHIFT + IOC_SIZEBITS;
const IOC_WRITE: u64 = 1;
const IOC_READ: u64 = 2;
const COCO_IMAGE_SHARE_IOC_MAGIC: u64 = b'C' as u64;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct CocoImageShareCreateFromFile {
    path: [u8; COCO_IMAGE_SHARE_PATH_MAX],
    flags: u64,
    share_id: u64,
    source_rd_addr: u64,
    image_size: u64,
    page_count: u64,
}

impl Default for CocoImageShareCreateFromFile {
    fn default() -> Self {
        Self {
            path: [0; COCO_IMAGE_SHARE_PATH_MAX],
            flags: 0,
            share_id: 0,
            source_rd_addr: 0,
            image_size: 0,
            page_count: 0,
        }
    }
}

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
struct CocoImageShareDevice {
    share_id: u64,
    source_rd_addr: u64,
    image_size: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SharedImage {
    pub share_id: u64,
    pub source_rd_addr: u64,
    pub image_size: u64,
    pub page_count: u64,
}

type IoctlRequest = libc::Ioctl;

const fn ioc(dir: u64, nr: u64, size: u64) -> IoctlRequest {
    ((dir << IOC_DIRSHIFT)
        | (COCO_IMAGE_SHARE_IOC_MAGIC << IOC_TYPESHIFT)
        | (nr << IOC_NRSHIFT)
        | (size << IOC_SIZESHIFT)) as IoctlRequest
}

const IOCTL_CREATE_FROM_FILE: IoctlRequest = ioc(
    IOC_READ | IOC_WRITE,
    0x03,
    mem::size_of::<CocoImageShareCreateFromFile>() as u64,
);
const IOCTL_CREATE_DEVICE: IoctlRequest = ioc(
    IOC_WRITE,
    0x07,
    mem::size_of::<CocoImageShareDevice>() as u64,
);
const IOCTL_DESTROY_DEVICE: IoctlRequest = ioc(0, 0x08, 0);

fn open_control() -> Result<File> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(COCO_IMAGE_SHARE_DEVICE)
        .with_context(|| format!("failed to open {COCO_IMAGE_SHARE_DEVICE}"))
}

fn copy_path(path: &Path, dst: &mut [u8; COCO_IMAGE_SHARE_PATH_MAX]) -> Result<()> {
    let path = path
        .to_str()
        .with_context(|| format!("path is not valid UTF-8: {}", path.display()))?;
    let bytes = path.as_bytes();
    if bytes.len() >= COCO_IMAGE_SHARE_PATH_MAX {
        bail!(
            "path is too long for coco-image-share ioctl: {} bytes",
            bytes.len()
        );
    }

    dst[..bytes.len()].copy_from_slice(bytes);
    Ok(())
}

pub fn create_from_file(path: &Path) -> Result<SharedImage> {
    let ctl = open_control()?;
    let mut req = CocoImageShareCreateFromFile {
        flags: COCO_IMAGE_SHARE_FLAG_RO,
        ..Default::default()
    };
    copy_path(path, &mut req.path)?;

    let rc = unsafe { libc::ioctl(ctl.as_raw_fd(), IOCTL_CREATE_FROM_FILE, &mut req) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("COCO_IMAGE_SHARE_IOC_CREATE_FROM_FILE {}", path.display()));
    }

    Ok(SharedImage {
        share_id: req.share_id,
        source_rd_addr: req.source_rd_addr,
        image_size: req.image_size,
        page_count: req.page_count,
    })
}

pub fn create_device(image: SharedImage) -> Result<()> {
    let ctl = open_control()?;
    let mut req = CocoImageShareDevice {
        share_id: image.share_id,
        source_rd_addr: image.source_rd_addr,
        image_size: image.image_size,
    };

    let rc = unsafe { libc::ioctl(ctl.as_raw_fd(), IOCTL_CREATE_DEVICE, &mut req) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error()).context("COCO_IMAGE_SHARE_IOC_CREATE_DEVICE");
    }

    Ok(())
}

pub fn destroy_device() -> Result<()> {
    let ctl = open_control()?;
    let rc = unsafe { libc::ioctl(ctl.as_raw_fd(), IOCTL_DESTROY_DEVICE) };
    if rc < 0 {
        return Err(std::io::Error::last_os_error()).context("COCO_IMAGE_SHARE_IOC_DESTROY_DEVICE");
    }

    Ok(())
}
