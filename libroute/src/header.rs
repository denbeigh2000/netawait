use nix::libc::{
    if_indextoname,
    rt_msghdr,
    IFNAMSIZ,
    RTM_ADD,
    RTM_CHANGE,
    RTM_DELADDR,
    RTM_DELETE,
    RTM_GET,
    RTM_GET2,
    RTM_IFINFO,
    RTM_IFINFO2,
    RTM_NEWADDR,
    RTM_OLDADD,
    RTM_OLDDEL,
};

use crate::addresses::{AddressInfo, AddressParseError, AddressSet};
use crate::link::LinkInfo;
use crate::route::RouteInfo;

#[derive(Debug)]
pub enum Header {
    Route(RouteInfo),
    Link(LinkInfo),
    Address(AddressInfo),
}

impl Header {
    pub fn index(&self) -> u16 {
        match self {
            Self::Route(r) => r.index,
            Self::Link(l) => l.index,
            Self::Address(a) => a.index,
        }
    }

    pub fn addrs(&self) -> &AddressSet {
        match self {
            Self::Route(r) => &r.addrs,
            Self::Link(l) => &l.addrs,
            Self::Address(a) => &a.addrs,
        }
    }

    pub fn print_self(&self) -> String {
        match self {
            Self::Route(r) => r.print_self(),
            Self::Link(l) => l.print_self(),
            Self::Address(a) => a.print_self(),
        }
    }

    pub(crate) fn from_raw(data: &[u8]) -> Result<Option<Self>, AddressParseError> {
        // Get the header
        let hdr_ptr: *const rt_msghdr = data.as_ptr() as *const _;
        // SAFETY: we depend on this being a byte slice received directly
        // from the kernel. The privacy of this function should allow us to
        // ensure this.
        let hdr = unsafe { *hdr_ptr };

        let sz = hdr.rtm_msglen as usize;
        let n = data.len();
        log::trace!("size={sz}, data.len()={n}");
        if sz != n {
            panic!("partial data read: size={sz}, data.len()={n}");
        }

        let seq = hdr.rtm_seq;
        let pid = hdr.rtm_pid;
        let hdr_type = hdr.rtm_type as i32;
        log::trace!("type: {hdr_type}, seq: {seq}, pid: {pid}");
        match hdr_type {
            RTM_ADD | RTM_DELETE | RTM_CHANGE | RTM_GET | RTM_GET2 | RTM_OLDADD | RTM_OLDDEL => {
                log::trace!("parsing route (type {})", hdr.rtm_type);
                RouteInfo::from_raw(data).map(|opt| opt.map(Self::Route))
            }
            RTM_IFINFO | RTM_IFINFO2 => {
                log::trace!("parsing link (type {})", hdr.rtm_type);
                LinkInfo::from_raw(data).map(|opt| opt.map(Self::Link))
            }
            RTM_NEWADDR | RTM_DELADDR => {
                log::trace!("parsing addr (type {})", hdr.rtm_type);
                AddressInfo::from_raw(data).map(|o| o.map(Self::Address))
            }
            _ => {
                log::info!("dropping event of type {}", hdr.rtm_type);
                Ok(None)
            }
        }
    }
}

pub fn interface_index_to_name(idx: u32) -> Option<String> {
    let mut ifname = [0u8; IFNAMSIZ]; // IFNAMSIZ is the length for an interface name

    // I don't understand why the `nix` crate has `if_nametoindex`
    // but not if_indextoname
    let interface_name_cstr = unsafe {
        let ptr = ifname.as_mut_ptr() as *mut i8;
        if if_indextoname(idx, ptr).is_null() {
            let e = std::io::Error::last_os_error();
            log::info!("failed to get interface name: {e}");
            return None;
        };

        std::ffi::CStr::from_ptr(ifname.as_ptr() as *const _)
    };

    let interface_name = interface_name_cstr
        .to_str()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
        // TODO: better error handling
        .unwrap()
        .to_string();

    Some(interface_name)
}
