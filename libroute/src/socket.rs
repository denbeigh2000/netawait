use crate::header::RouteInfo;
use route_sys::{
    in_addr, route_request, rt_metrics, rt_msghdr, sockaddr_in, socket as raw_socket, AF_INET,
    PF_ROUTE, RTA_DST, RTA_NETMASK, RTF_GATEWAY, RTF_UP, RTM_GET, RTM_VERSION, RTV_HOPCOUNT,
    SOCK_RAW,
};

use std::default::Default;
use std::fs::File;
use std::io::{Read, Write};
use std::os::unix::io::FromRawFd;
use std::sync::Mutex;

pub struct RouteSocket {
    lock: Mutex<i32>,
    inner: File,
}

impl Default for RouteSocket {
    fn default() -> Self {
        let inner = unsafe {
            let s = raw_socket(PF_ROUTE as i32, SOCK_RAW as i32, 0);
            if s < 0 {
                let err = std::io::Error::last_os_error();
                // TODO
                panic!("{}", err);
            };

            File::from_raw_fd(s)
        };

        let lock = Mutex::new(0);
        Self { inner, lock }
    }
}

impl RouteSocket {
    pub fn request_default_ipv4(&mut self) -> Result<(), std::io::Error> {
        let raw_addr_4 = in_addr { s_addr: 0 };
        let request = route_request {
            rtm: rt_msghdr {
                rtm_msglen: std::mem::size_of::<route_request>() as u16,
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

    fn send(&mut self, request_bytes: &[u8]) -> Result<(), std::io::Error> {
        self.inner.write_all(request_bytes)
    }

    pub fn monitor(&mut self) {
        let mut buf = [0u8; 2048];
        loop {
            let size = self.inner.read(&mut buf).unwrap();
            let data = &buf.as_slice()[0..size];

            let route_info = RouteInfo::from_raw(data).unwrap();

            match route_info {
                Some(i) => eprintln!("collected route: {}", i.print_self()),
                None => eprintln!(),
            }
        }
    }
}
