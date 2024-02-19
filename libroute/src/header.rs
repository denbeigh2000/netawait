use route_sys::{
    if_indextoname, rt_msghdr, IFNAMSIZ, RTM_ADD, RTM_CHANGE, RTM_DELADDR, RTM_DELETE, RTM_GET,
    RTM_GET2, RTM_IFINFO, RTM_IFINFO2, RTM_NEWADDR,
};

use crate::addresses::{AddressInfo, AddressParseError};
use crate::link::LinkInfo;
use crate::route::RouteInfo;

#[derive(Debug)]
pub enum Header {
    Route(RouteInfo),
    Link(LinkInfo),
    Address(AddressInfo),
}

impl Header {
    pub fn print_self(&self) -> String {
        match self {
            Self::Route(r) => r.print_self(),
            Self::Link(l) => l.print_self(),
            Self::Address(a) => a.print_self(),
        }
    }

    pub fn from_raw(data: &[u8]) -> Result<Option<Self>, AddressParseError> {
        // Get the header
        let hdr_ptr: *const rt_msghdr = data.as_ptr() as *const _;
        let hdr = unsafe { *hdr_ptr };

        match hdr.rtm_type as u32 {
            RTM_ADD | RTM_DELETE | RTM_CHANGE | RTM_GET | RTM_GET2 => {
                log::trace!("parsing route (type {}", hdr.rtm_type);
                RouteInfo::from_raw(data).map(|opt| opt.map(Self::Route))
            }
            RTM_IFINFO | RTM_IFINFO2 => {
                log::trace!("parsing link (type {}", hdr.rtm_type);
                LinkInfo::from_raw(data).map(|opt| opt.map(Self::Link))
            }
            RTM_NEWADDR | RTM_DELADDR => {
                log::trace!("parsing addr (type {}", hdr.rtm_type);
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
    let mut ifname = [0u8; IFNAMSIZ as usize]; // IFNAMSIZ is the length for an interface name
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
