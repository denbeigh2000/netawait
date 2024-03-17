use std::io::{self, Read, Write};
use std::mem::size_of;
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;

use nix::libc::{
    in_addr,
    rt_metrics,
    rt_msghdr,
    sockaddr_dl,
    sockaddr_in,
    uintptr_t,
    AF_INET,
    RTA_DST,
    RTA_IFA,
    RTA_IFP,
    RTA_NETMASK,
    RTF_GATEWAY,
    RTF_HOST,
    RTF_IFSCOPE,
    RTF_UP,
    RTM_GET,
    RTM_VERSION,
    RTV_HOPCOUNT,
};
use nix::net::if_::if_nametoindex;
use nix::sys::event::{EventFilter, EventFlag, FilterFlag, KEvent, Kqueue};
use nix::sys::socket::{self as nix_socket, AddressFamily, SockFlag, SockType};

use crate::addresses::AddressParseError;
use crate::header::Header;

const KEVENT_TIMEOUT_ID: uintptr_t = 61;

const ADDR_LEN: usize = size_of::<sockaddr_dl>();
const HDR_LEN: usize = size_of::<rt_msghdr>();
const INT_REQ_SIZE: usize = ADDR_LEN + HDR_LEN;

#[allow(non_camel_case_types)]
#[derive(Debug, Copy, Clone)]
#[repr(C)]
struct route_request {
    pub rtm: rt_msghdr,
    pub dst: sockaddr_in,
    pub mask: sockaddr_in,
}

fn interface_info_req(if_idx: u16, seq: i32) -> [u8; INT_REQ_SIZE] {
    let hdr = rt_msghdr {
        rtm_msglen: INT_REQ_SIZE as u16,
        rtm_version: RTM_VERSION as u8,
        rtm_type: RTM_GET as u8,
        rtm_index: if_idx,
        // Required to scope the request down to just the index specifiecd
        // in rtm_index
        rtm_flags: RTF_IFSCOPE | RTF_HOST,
        rtm_addrs: RTA_DST | RTA_IFP | RTA_IFA,
        rtm_pid: 0,
        rtm_seq: seq,
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

    let mut buf = [0u8; INT_REQ_SIZE];
    let (hdr_slice, addr_slice) = unsafe {
        let hdr_ptr = (&hdr) as *const _ as *const u8;
        let hdr_slice = std::slice::from_raw_parts(hdr_ptr, HDR_LEN);

        let addr_ptr = (&sockaddr) as *const _ as *const u8;
        let addr_slice = std::slice::from_raw_parts(addr_ptr, ADDR_LEN);

        (hdr_slice, addr_slice)
    };

    buf[..HDR_LEN].copy_from_slice(hdr_slice);
    buf[HDR_LEN..].copy_from_slice(addr_slice);

    buf
}

fn default_ipv4_request(seq: i32) -> route_request {
    let raw_addr_4 = in_addr { s_addr: 0 };
    route_request {
        rtm: rt_msghdr {
            rtm_msglen: size_of::<route_request>() as u16,
            rtm_version: RTM_VERSION as u8,
            rtm_type: RTM_GET as u8,
            rtm_index: 0,
            rtm_flags: RTF_UP | RTF_GATEWAY,
            rtm_addrs: RTA_DST | RTA_NETMASK,
            rtm_pid: 0,
            rtm_seq: seq,
            rtm_errno: 0,
            rtm_use: 0,
            rtm_inits: RTV_HOPCOUNT as u32,
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
    }
}

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

#[derive(Debug, thiserror::Error)]
pub enum RouteSocketCreateError {
    #[error("error creating kqueue: {0}")]
    CreatingKqueue(io::Error),
    #[error("error creating pf_route socket: {0})")]
    CreatingSocket(io::Error),
}

// #[derive(thiserror::Error, Debug)]
// pub enum ReadError {
//     Timeout,
//     Error(#[from] io::Error),
// }

impl From<nix::errno::Errno> for ReadError {
    fn from(value: nix::errno::Errno) -> Self {
        Self::IO(io::Error::from_raw_os_error(value as i32))
    }
}

pub struct RouteSocket {
    seq: i32,
    buf: [u8; 2048],
    kqueue: Kqueue,
    events: Vec<KEvent>,
    event_buf: Vec<KEvent>,

    raw_socket_fd: usize,
    socket: UnixStream,
}

impl RouteSocket {
    pub fn new(timeout_secs: Option<i32>) -> Result<Self, RouteSocketCreateError> {
        let socket =
            nix_socket::socket(AddressFamily::Route, SockType::Raw, SockFlag::empty(), None)
                .map_err(|e| RouteSocketCreateError::CreatingSocket(e.into()))?;

        let kqueue = Kqueue::new().map_err(|e| RouteSocketCreateError::CreatingKqueue(e.into()))?;

        let mut events = Vec::with_capacity(if timeout_secs.is_none() { 1 } else { 2 });

        if let Some(sec) = timeout_secs {
            let timeout_event = KEvent::new(
                KEVENT_TIMEOUT_ID,
                EventFilter::EVFILT_TIMER,
                EventFlag::EV_ONESHOT | EventFlag::EV_ADD | EventFlag::EV_ENABLE,
                FilterFlag::NOTE_SECONDS,
                sec as isize,
                0,
            );
            events.push(timeout_event);
        }

        let raw_socket_fd = socket
            .as_raw_fd()
            .try_into()
            .expect("socket file descriptor doesn't fit into isize");

        let read_event = KEvent::new(
            raw_socket_fd,
            EventFilter::EVFILT_READ,
            EventFlag::EV_ADD | EventFlag::EV_ENABLE,
            FilterFlag::empty(),
            0,
            0,
        );

        events.push(read_event);

        Ok(Self {
            seq: 0,
            buf: [0; 2048],

            kqueue,
            event_buf: events.clone(),
            events,

            socket: socket.into(),
            raw_socket_fd,
        })
    }

    pub fn recv(&mut self) -> Result<Header, ReadError> {
        loop {
            let res = self
                .kqueue
                .kevent(&self.events, &mut self.event_buf, None)?;

            match res {
                1..=2 => {
                    let event = self.event_buf.first().expect("i hope we've populated this");
                    match event.ident() {
                        KEVENT_TIMEOUT_ID => return Err(ReadError::Timeout),
                        id if id == self.raw_socket_fd => {
                            let n = self.socket.read(&mut self.buf)?;
                            log::trace!("read {n} bytes w kevent");

                            match Header::from_raw(&self.buf[..n])? {
                                Some(res) => return Ok(res),
                                None => continue,
                            };
                        }
                        n => panic!("unknown event from kevent {n}"),
                    }
                }
                n @ 3.. => panic!("somehow we got more elements from kevent than we put in? {n}"),
                n @ ..=0 => panic!("we got {n} elements from kevent?"),
            };
        }
    }
    pub fn request_default_ipv4(&mut self) -> io::Result<()> {
        let request = default_ipv4_request(self.get_seq());

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
        let req = interface_info_req(if_idx, self.get_seq());

        log::debug!("sending if for idx {if_idx}");
        self.send(&req)?;
        Ok(())
    }

    fn get_seq(&mut self) -> i32 {
        self.seq += 1;
        self.seq
    }

    fn send(&mut self, request_bytes: &[u8]) -> io::Result<()> {
        if let Err(e) = self.socket.write_all(request_bytes) {
            // NOTE: macos returns "No such process" when you request the
            // default route and it's not evailable.
            if e.raw_os_error() != Some(3) {
                return Err(e);
            }

            log::info!("ignoring ENSCH error (given when requesting unavailable default network)");
        }

        Ok(())
    }
}

pub fn get_ifindex(ifname: &str) -> Result<u32, io::Error> {
    let res = if_nametoindex(ifname)?;
    Ok(res)
}
