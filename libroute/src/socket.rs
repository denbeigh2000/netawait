use crate::header::RouteInfo;
use route_sys::{socket as raw_socket, PF_ROUTE, SOCK_RAW};

use std::default::Default;
use std::fs::File;
use std::io::Read;
use std::os::unix::io::FromRawFd;

pub struct RouteSocket {
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

        Self { inner }
    }
}

impl RouteSocket {
    pub fn monitor(&mut self) {
        // let mut buf = unsafe { MaybeUninit::<[MaybeUninit<u8>; 2048]>::uninit().assume_init() };
        let mut buf = [0u8; 2048];
        loop {
            let size = self.inner.read(&mut buf).unwrap();
            // let (size, _) = sock.recv_from(buf.as_mut_slice()).unwrap();
            // let slice = buf.as_slice();
            // slice[..2];
            let data = &buf.as_slice()[0..size];

            let route_info = RouteInfo::from_raw(data).unwrap();

            match route_info {
                Some(i) => eprintln!("collected route: {}", i.print_self()),
                None => eprintln!(),
            }
        }
    }
}
