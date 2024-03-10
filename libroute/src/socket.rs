use crate::addresses::AddressParseError;
use crate::header::Header;
use route_sys::{
    in_addr, route_request, rt_metrics, rt_msghdr, sockaddr_dl, sockaddr_in, AF_INET, RTA_DST,
    RTA_IFA, RTA_IFP, RTA_NETMASK, RTF_GATEWAY, RTF_HOST, RTF_IFSCOPE, RTF_UP, RTM_GET,
    RTM_VERSION, RTV_HOPCOUNT,
};

use nix::net::if_::if_nametoindex;
use nix::sys::socket::{self as nix_socket, AddressFamily, SockFlag, SockType};

use std::io::{self, Read, Write};
use std::mem::size_of;
use std::os::unix::net::UnixStream;

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
    seq: i32,
    buf: [u8; 2048],
    inner: UnixStream,
}

impl RouteSocket {
    pub fn new(_timeout: Option<i64>) -> io::Result<Self> {
        let s = nix_socket::socket(AddressFamily::Route, SockType::Raw, SockFlag::empty(), None)?;

        // TODO: The setsockopt approach doesn't do what we want, because we're
        // setting a timeout between events, not on how long the socket stays
        // open.

        let buf = [0u8; 2048];
        let seq = 0;
        let inner = s.into();
        Ok(Self { buf, inner, seq })
    }

    pub fn request_default_ipv4(&mut self) -> io::Result<()> {
        let raw_addr_4 = in_addr { s_addr: 0 };
        let request = route_request {
            rtm: rt_msghdr {
                rtm_msglen: size_of::<route_request>() as u16,
                rtm_version: RTM_VERSION as u8,
                rtm_type: RTM_GET as u8,
                rtm_index: 0,
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
                sin_len: size_of::<sockaddr_in>() as u8,
                sin_family: AF_INET as u8,
                sin_port: 0,
                sin_addr: raw_addr_4,
                sin_zero: [0; 8],
            },
            mask: sockaddr_in {
                sin_len: size_of::<sockaddr_in>() as u8,
                sin_family: AF_INET as u8,
                sin_port: 0,
                sin_addr: raw_addr_4,
                sin_zero: [0; 8],
            },
        };

        log::trace!("req: {:?}", request);
        let request_bytes: &[u8] = unsafe {
            let req_ptr = (&request) as *const _ as *const u8;
            std::slice::from_raw_parts(req_ptr, size_of::<route_request>())
        };

        log::debug!("sending v4");
        self.send(request_bytes)?;
        Ok(())
    }

    pub fn request_interface_info(&mut self, if_idx: u16) -> io::Result<()> {
        const ADDR_LEN: usize = size_of::<sockaddr_dl>();
        const SIZE: usize = HDR_LEN + ADDR_LEN;
        const HDR_LEN: usize = size_of::<rt_msghdr>();
        let hdr = rt_msghdr {
            rtm_msglen: SIZE as u16,
            rtm_version: RTM_VERSION as u8,
            rtm_type: RTM_GET as u8,
            rtm_index: if_idx,
            // Required to scope the request down to just the index specifiecd
            // in rtm_index
            rtm_flags: (RTF_IFSCOPE | RTF_HOST) as i32,
            rtm_addrs: (RTA_DST | RTA_IFP | RTA_IFA) as i32,
            rtm_pid: 0,
            rtm_seq: self.get_seq(),
            rtm_errno: 0,
            rtm_use: 0,
            rtm_inits: 0,
            // rtm_inits: RTV_HOPCOUNT,
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
        };
        let sockaddr = sockaddr_dl {
            sdl_len: ADDR_LEN as u8,
            sdl_family: AF_INET as u8,
            sdl_index: if_idx,
            sdl_type: 0,
            sdl_nlen: 0,
            sdl_alen: 0,
            sdl_slen: 0,
            sdl_data: [0i8; 12],
        };

        let mut buf = [0u8; SIZE];
        let (hdr_slice, addr_slice) = unsafe {
            let hdr_ptr = (&hdr) as *const _ as *const u8;
            let hdr_slice = std::slice::from_raw_parts(hdr_ptr, HDR_LEN);

            let addr_ptr = (&sockaddr) as *const _ as *const u8;
            let addr_slice = std::slice::from_raw_parts(addr_ptr, ADDR_LEN);

            (hdr_slice, addr_slice)
        };

        buf[..HDR_LEN].copy_from_slice(hdr_slice);
        buf[HDR_LEN..].copy_from_slice(addr_slice);

        log::debug!("sending if for idx {if_idx}");
        self.send(&buf)?;
        // self.send(hdr_slice)?;
        Ok(())
    }

    fn get_seq(&mut self) -> i32 {
        self.seq += 1;
        self.seq
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
            size => {
                log::trace!("received payload of size {size}");
                log::trace!("data: {:?}", &self.buf[..size]);
                Header::from_raw(&self.buf[..size])?
            }
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
    let res = if_nametoindex(ifname)?;
    Ok(res)
}
