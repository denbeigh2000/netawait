use crate::addresses::AddressParseError;
use crate::header::Header;
use route_sys::{
    if_nametoindex, in_addr, route_request, rt_metrics, rt_msghdr, setsockopt, sockaddr_in,
    socket as raw_socket, socklen_t, timeval, AF_INET, PF_ROUTE, RTA_DST, RTA_NETMASK, RTF_GATEWAY,
    RTF_UP, RTM_GET, RTM_VERSION, RTV_HOPCOUNT, SOCK_RAW, SOL_SOCKET, SO_RCVTIMEO,
};

use std::ffi::{c_void, CString};
use std::fs::File;
use std::io::{self, Read, Write};
use std::os::unix::io::FromRawFd;
use std::sync::Mutex;

#[derive(thiserror::Error, Debug)]
pub enum ReadError {
    #[error("read timed out")]
    Timeout,
    #[error("IO error: {0}")]
    IO(io::Error),

    #[error("error parsing addresses: {0}")]
    ParsingAddress(#[from] AddressParseError),
}

impl From<io::Error> for ReadError {
    fn from(value: io::Error) -> Self {
        match value.raw_os_error() {
            Some(11) | Some(35) => Self::Timeout,
            _ => Self::IO(value),
        }
    }
}

pub struct RouteSocket {
    lock: Mutex<i32>,
    buf: [u8; 2048],
    inner: File,
}

impl RouteSocket {
    pub fn new(timeout: Option<i64>) -> io::Result<Self> {
        let s = unsafe { raw_socket(PF_ROUTE as i32, SOCK_RAW as i32, 0) };
        if s < 0 {
            let err = io::Error::last_os_error();
            return Err(err);
        };

        if let Some(t) = timeout {
            let tv = timeval {
                tv_sec: t,
                tv_usec: 0,
            };

            let tv_ptr = &tv as *const _ as *const c_void;
            let tv_size = std::mem::size_of::<timeval>() as socklen_t;
            let ret =
                unsafe { setsockopt(s, SOL_SOCKET as i32, SO_RCVTIMEO as i32, tv_ptr, tv_size) };
            if ret != 0 {
                let err = io::Error::last_os_error();
                return Err(err);
            }
        }

        let inner = unsafe { File::from_raw_fd(s) };

        let lock = Mutex::new(0);
        let buf = [0u8; 2048];
        Ok(Self { buf, inner, lock })
    }

    pub fn request_default_ipv4(&mut self, interface_index: Option<u16>) -> io::Result<()> {
        let rtm_index = interface_index.unwrap_or(0);

        let raw_addr_4 = in_addr { s_addr: 0 };
        let request = route_request {
            rtm: rt_msghdr {
                rtm_msglen: std::mem::size_of::<route_request>() as u16,
                rtm_version: RTM_VERSION as u8,
                rtm_type: RTM_GET as u8,
                rtm_index,
                rtm_flags: (RTF_UP as i32) | (RTF_GATEWAY as i32),
                rtm_addrs: (RTA_DST as i32) | (RTA_NETMASK as i32),
                rtm_pid: 0,
                rtm_seq: self.get_seq(),
                rtm_errno: 0,
                rtm_use: 0,
                rtm_inits: RTV_HOPCOUNT,
                rtm_rmx: rt_metrics {
                    rmx_expire: 0,
                    rmx_locks: 0,
                    rmx_mtu: 0,
                    rmx_hopcount: 0,
                    rmx_recvpipe: 0,
                    rmx_sendpipe: 0,
                    rmx_ssthresh: 0,
                    rmx_rtt: 0,
                    rmx_rttvar: 0,
                    rmx_pksent: 0,
                    rmx_state: 0,
                    rmx_filler: [0u32; 3],
                },
            },
            dst: sockaddr_in {
                sin_len: std::mem::size_of::<sockaddr_in>() as u8,
                sin_family: AF_INET as u8,
                sin_port: 0,
                sin_addr: raw_addr_4,
                sin_zero: [0; 8],
            },
            mask: sockaddr_in {
                sin_len: std::mem::size_of::<sockaddr_in>() as u8,
                sin_family: AF_INET as u8,
                sin_port: 0,
                sin_addr: raw_addr_4,
                sin_zero: [0; 8],
            },
        };

        log::trace!("req: {:?}", request);
        let request_bytes: &[u8] = unsafe {
            let req_ptr = (&request) as *const _ as *const u8;
            std::slice::from_raw_parts(req_ptr, std::mem::size_of::<route_request>())
        };

        log::debug!("sending v4");
        self.send(request_bytes)?;
        Ok(())
    }

    fn get_seq(&mut self) -> i32 {
        let mut seq = self.lock.lock().unwrap();
        *seq += 1;
        *seq
    }

    fn send(&mut self, request_bytes: &[u8]) -> io::Result<()> {
        if let Err(e) = self.inner.write_all(request_bytes) {
            // NOTE: macos returns "No such process" when you request the
            // default route and it's not evailable.
            if e.raw_os_error() != Some(3) {
                return Err(e);
            }

            log::info!("ignoring ENSCH error (given when requesting unavailable default network)");
        }

        Ok(())
    }

    fn recv_raw(&mut self) -> Result<Option<Header>, ReadError> {
        Ok(match self.inner.read(&mut self.buf)? {
            0 => {
                log::warn!("empty read?");
                None
            }
            size => Header::from_raw(&self.buf[..size])?,
        })
    }

    pub fn recv(&mut self) -> Result<Header, ReadError> {
        loop {
            if let Some(info) = self.recv_raw()? {
                return Ok(info);
            }
        }
    }

    pub fn monitor(&mut self) -> Result<(), ReadError> {
        loop {
            match self.recv_raw()? {
                Some(i) => eprintln!("collected route: {}", i.print_self()),
                None => eprintln!(),
            }
        }
    }
}

pub fn get_ifindex(ifname: &str) -> Result<u32, io::Error> {
    let c_ifname = CString::new(ifname)?;
    match unsafe { if_nametoindex(c_ifname.as_ptr()) } {
        0 => Err(io::Error::last_os_error()),
        i => Ok(i),
    }
}
