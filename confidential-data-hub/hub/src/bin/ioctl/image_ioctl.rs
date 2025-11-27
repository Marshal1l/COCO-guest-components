use log::info;
use std::fs::File;
use std::iter::Map;
use std::os::fd::RawFd;
use std::os::raw::{c_int, c_ulong, c_void};
use std::os::unix::io::AsRawFd;
use std::path::PathBuf;
use std::{io, mem};
#[repr(C)]
#[derive(Debug, Default)]
pub struct RdIpaSizeData {
    pub rd_addr: u64,
    pub ipa_start: u64,
    pub ipa_size: u64,
}

#[repr(C)]
#[derive(Debug, Default)]
pub struct MapIpaSize {
    pub guest_rd_addr: u64,
    pub guest_ipa: u64,
    pub map_size: u64,
}

#[repr(C)]
#[derive(Debug)]
pub struct LoadFileData {
    pub file_path: [u8; 256],
    pub file_size: u64,
}
impl Default for LoadFileData {
    fn default() -> Self {
        Self {
            file_path: [0; 256],
            file_size: 0,
        }
    }
}
impl LoadFileData {
    pub fn set_file_path(&mut self, path: PathBuf) {
        let path_str = path.to_string_lossy().into_owned();
        let bytes = path_str.as_bytes();

        self.file_path.fill(0);

        let len = bytes.len().min(255);
        self.file_path[..len].copy_from_slice(&bytes[..len]);
        self.file_path[len] = b'\0';
    }
}
#[repr(C)]
#[derive(Debug)]
pub struct WriteFileData {
    pub file_path: [u8; 256],
    pub file_size: u64,
}
impl Default for WriteFileData {
    fn default() -> Self {
        Self {
            file_path: [0; 256],
            file_size: 0,
        }
    }
}
impl WriteFileData {
    pub fn set_file_path(&mut self, path: PathBuf) {
        let path_str = path.to_string_lossy().into_owned();
        let bytes = path_str.as_bytes();

        self.file_path.fill(0);

        let len = bytes.len().min(255);
        self.file_path[..len].copy_from_slice(&bytes[..len]);
        self.file_path[len] = b'\0';
    }
}
const IMG_MAGIC: u8 = b'i'; // 'i'
const IOCTL_NR_GET_RD_IPA: u8 = 1;
const IOCTL_NR_MAP_IPA: u8 = 2;
const IOCTL_NR_LOAD_FILE: u8 = 3;
const IOCTL_NR_WRITE_FILE: u8 = 4;
// Linux ioctl (_IOR)
const IOC_NRBITS: u8 = 8;
const IOC_TYPEBITS: u8 = 8;
const IOC_SIZEBITS: u8 = 14;
const IOC_DIRBITS: u8 = 2;

const IOC_NRSHIFT: u8 = 0;
const IOC_TYPESHIFT: u8 = IOC_NRSHIFT + IOC_NRBITS;
const IOC_SIZESHIFT: u8 = IOC_TYPESHIFT + IOC_TYPEBITS;
const IOC_DIRSHIFT: u8 = IOC_SIZESHIFT + IOC_SIZEBITS;

const IOC_NONE: u8 = 0;
const IOC_WRITE: u8 = 1;
const IOC_READ: u8 = 2;

const fn ioc(dir: u8, type_: u8, nr: u8, size: usize) -> c_ulong {
    ((dir as c_ulong) << IOC_DIRSHIFT)
        | ((type_ as c_ulong) << IOC_TYPESHIFT)
        | ((nr as c_ulong) << IOC_NRSHIFT)
        | ((size as c_ulong) << IOC_SIZESHIFT)
}

const IMG_IOCTL_GET_RD_IPA: libc::Ioctl = ioc(
    IOC_READ,
    IMG_MAGIC,
    IOCTL_NR_GET_RD_IPA,
    mem::size_of::<RdIpaSizeData>(),
) as libc::Ioctl;

const IMG_IOCTL_MAP_IPA: libc::Ioctl = ioc(
    IOC_WRITE,
    IMG_MAGIC,
    IOCTL_NR_MAP_IPA,
    mem::size_of::<MapIpaSize>(),
) as libc::Ioctl;

const IMG_IOCTL_LOAD_FILE: libc::Ioctl = ioc(
    IOC_WRITE | IOC_READ,
    IMG_MAGIC,
    IOCTL_NR_LOAD_FILE,
    mem::size_of::<LoadFileData>(),
) as libc::Ioctl;

const IMG_IOCTL_WRITE_FILE: libc::Ioctl = ioc(
    IOC_WRITE,
    IMG_MAGIC,
    IOCTL_NR_WRITE_FILE,
    mem::size_of::<WriteFileData>(),
) as libc::Ioctl;

pub struct ImageIoctl {
    file: File,
}

impl ImageIoctl {
    pub fn new() -> Self {
        let file = File::open("/dev/image-server").expect("Failed to open device");
        ImageIoctl { file }
    }
    pub fn map_ipa(
        &self,
        guest_rd_addr: u64,
        guest_ipa: u64,
        map_size: u64,
    ) -> Result<MapIpaSize, io::Error> {
        let mut data = MapIpaSize::default();
        data.guest_ipa = guest_ipa;
        data.guest_rd_addr = guest_rd_addr;
        data.map_size = map_size;
        let fd: c_int = self.file.as_raw_fd() as c_int;
        let ret = unsafe {
            libc::ioctl(
                fd,
                IMG_IOCTL_MAP_IPA,
                &mut data as *mut MapIpaSize as *mut c_void,
            )
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(data)
        }
    }
    pub fn get_rd_ipa(&self) -> Result<RdIpaSizeData, io::Error> {
        let mut data = RdIpaSizeData::default();
        let fd: c_int = self.file.as_raw_fd() as c_int;
        let ret = unsafe {
            libc::ioctl(
                fd,
                IMG_IOCTL_GET_RD_IPA,
                &mut data as *mut RdIpaSizeData as *mut c_void,
            )
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(data)
        }
    }

    pub fn load_file(&self, path: PathBuf) -> Result<LoadFileData, io::Error> {
        let mut data = LoadFileData::default();
        data.set_file_path(path);
        let fd: c_int = self.file.as_raw_fd() as c_int;
        let ret = unsafe {
            libc::ioctl(
                fd,
                IMG_IOCTL_LOAD_FILE,
                &mut data as *mut LoadFileData as *mut c_void,
            )
        };
        info!(
            "load file:{:?} for {:?} bytes\n",
            &data.file_path, &data.file_size
        );
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(data)
        }
    }

    pub fn write_file(&self, path: PathBuf, file_size: u64) -> Result<WriteFileData, io::Error> {
        let mut data = WriteFileData::default();
        data.set_file_path(path);
        data.file_size = file_size;
        let fd: c_int = self.file.as_raw_fd() as c_int;
        let ret = unsafe {
            libc::ioctl(
                fd,
                IMG_IOCTL_WRITE_FILE,
                &mut data as *mut WriteFileData as *mut c_void,
            )
        };
        if ret < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(data)
        }
    }
}
