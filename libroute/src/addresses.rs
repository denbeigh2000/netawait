/*
* In the context of this program, these arrays (`metricnames`, `routeflags`, `ifnetflags`, and `addrnames`) are predefined strings that contain names or labels representing certain attributes or flags. These arrays are used as input values for the `s` parameter of the `bprintf` function.

When the `bprintf` function is called with one of these arrays as the `s` parameter, it will iterate through the characters in the array and selectively print characters based on the value of the `b` parameter.

For example, let's say you want to print only the characters from the `metricnames` that correspond to bits 2, 3, and 5 set in the `b` parameter. You would call the `bprintf` function like this:

```c
bprintf(fp, 0b00110100, metricnames);
```

In this case, the `b` parameter has bits 2, 3, and 5 set to 1. The `bprintf` function will print the corresponding characters ('rttvar', 'rtt', 'sendpipe') from the `metricnames` array to the specified file pointer `fp`.

Similarly, you can use the other arrays (`routeflags`, `ifnetflags`, and `addrnames`) in a similar way to selectively print characters based on the specific bits set in the `b` parameter.
*/

use route_sys::{
    sockaddr_in, sockaddr_in6, AF_INET, RTA_AUTHOR, RTA_BRD, RTA_DST, RTA_GATEWAY, RTA_GENMASK,
    RTA_IFA, RTA_IFP, RTA_NETMASK,
};

use std::{
    convert::Infallible,
    net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6},
};

pub struct AddressFlags(u32);

impl AddressFlags {
    pub fn new(flags: u32) -> Self {
        Self(flags)
    }

    pub fn has_destination(&self) -> bool {
        self.0 & RTA_DST != 0
    }

    pub fn has_gateway(&self) -> bool {
        self.0 & RTA_GATEWAY != 0
    }

    pub fn has_netmask(&self) -> bool {
        self.0 & RTA_NETMASK != 0
    }

    pub fn has_genmask(&self) -> bool {
        self.0 & RTA_GENMASK != 0
    }

    pub fn has_interface_address(&self) -> bool {
        self.0 & RTA_IFA != 0
    }

    pub fn has_interface_link(&self) -> bool {
        self.0 & RTA_IFP != 0
    }

    pub fn has_author(&self) -> bool {
        self.0 & RTA_AUTHOR != 0
    }

    pub fn has_brd(&self) -> bool {
        self.0 & RTA_BRD != 0
    }
}

unsafe fn read_sockaddr_in(data: &[u8]) -> Option<SocketAddr> {
    let sockaddr_in_ptr: *const sockaddr_in = data.as_ptr() as *const _;
    match (*sockaddr_in_ptr).sin_family as u32 {
        AF_INET => {
            let sockaddr_in_ptr: *const sockaddr_in = data.as_ptr() as *const _;
            let sockaddr_in = *sockaddr_in_ptr;

            let port = u16::from_be(sockaddr_in.sin_port);
            let s_addr = u32::from_be(sockaddr_in.sin_addr.s_addr);
            let addr = Ipv4Addr::from(s_addr.to_be_bytes());
            Some(SocketAddr::V4(SocketAddrV4::new(addr, port)))
        }
        AF_INET6 => {
            let sockaddr_in6_ptr: *const sockaddr_in6 = data.as_ptr() as *const _;
            let sockaddr_in6 = *sockaddr_in6_ptr;
            let port = u16::from_be((sockaddr_in6).sin6_port);
            let s6_addr = (sockaddr_in6).sin6_addr.__u6_addr.__u6_addr8;
            let addr = Ipv6Addr::from(s6_addr);

            let flowinfo = (sockaddr_in6).sin6_flowinfo;
            let scope_id = (sockaddr_in6).sin6_scope_id;
            Some(SocketAddr::V6(SocketAddrV6::new(
                addr, port, flowinfo, scope_id,
            )))
        }
        // TODO: logging?
        _ => None,
    }
}

pub fn parse_address(data: &[u8]) -> Result<(Option<SocketAddr>, usize), Infallible> {
    // TODO: real errors
    assert!(!data.is_empty());

    let sa_len = data[0] as usize;

    // Make sure the buffer has enough data left
    assert!(sa_len <= data.len());

    let sa_data = &data[..sa_len];
    let res = unsafe { read_sockaddr_in(sa_data) };
    Ok((res, sa_len))
}

pub fn parse_addresses(data: &[u8]) -> Vec<SocketAddr> {
    let mut offset = 0;
    let mut addrs = Vec::new();
    while offset < data.len() {
        let sa_len = data[offset] as usize;

        // Make sure the buffer has enough data left:
        if sa_len > data.len() - offset {
            // TODO: Log a warning that we received a partial address
            break;
        }

        let sa_data = &data[offset..offset + sa_len];
        if let Some(socket_addr) = unsafe { read_sockaddr_in(sa_data) } {
            addrs.push(socket_addr)
        }

        offset += sa_len;
    }

    addrs
}
