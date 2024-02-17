use crate::header::MessageHeader;
use route_sys::{rt_msghdr, socket as raw_socket, PF_ROUTE, SOCK_RAW};

use std::os::unix::io::FromRawFd;
use std::{fs::File, mem::MaybeUninit};

use socket2::{Domain, Socket, Type};

pub struct RouteSocket {
    inner: Socket,
}

impl RouteSocket {
    pub fn new() -> Self {
        let sock = unsafe {
            let s = raw_socket(PF_ROUTE as i32, SOCK_RAW as i32, 0);
            if s < 0 {
                let err = std::io::Error::last_os_error();
                // TODO
                panic!("{}", err);
            };

            Socket::from_raw_fd(s)
        };

        let mut buf = unsafe { MaybeUninit::<[MaybeUninit<u8>; 2048]>::uninit().assume_init() };
        // let b = &mut buf as &mut [MaybeUninit<u8>];
        let _bytes_read = sock.recv_from(buf.as_mut_slice());
        let (header, raw_msg) = unsafe {
            let hdr = buf.as_mut_ptr().cast::<rt_msghdr>();
            // Add the length of one header to the message, and cast it as an
            // arbitrary byte blob
            let msg = (hdr as *const rt_msghdr).add(1) as *mut u8;
            let header = MessageHeader::try_from(*hdr);
            (header, msg)
        };

        // let mut ptrSrc = m_rtmsg {};

        unimplemented!()
    }
}
