use route_sys::{
    ifa_msghdr, sockaddr_dl, sockaddr_in, sockaddr_in6, AF_INET, AF_INET6, AF_LINK, RTA_AUTHOR,
    RTA_BRD, RTA_DST, RTA_GATEWAY, RTA_GENMASK, RTA_IFA, RTA_IFP, RTA_NETMASK, RTF_BLACKHOLE,
    RTF_BROADCAST, RTF_CLONING, RTF_CONDEMNED, RTF_DEAD, RTF_DELCLONE, RTF_DONE, RTF_DYNAMIC,
    RTF_GATEWAY, RTF_HOST, RTF_IFREF, RTF_IFSCOPE, RTF_LLINFO, RTF_LOCAL, RTF_MODIFIED,
    RTF_MULTICAST, RTF_NOIFREF, RTF_PRCLONING, RTF_PROTO1, RTF_PROTO2, RTF_PROTO3, RTF_PROXY,
    RTF_REJECT, RTF_ROUTER, RTF_STATIC, RTF_UP, RTF_WASCLONED, RTF_XRESOLVE, RTM_DELADDR,
    RTM_NEWADDR,
};

use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};

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

    pub fn print_self(&self) -> String {
        format!(
            "
        has dest: {},
        has gateway: {},
        has netmask: {},
        has genmask: {},
        has ifa: {},
        has ifp: {},
        has author: {},
        has broadcast: {}
",
            self.has_destination(),
            self.has_gateway(),
            self.has_netmask(),
            self.has_genmask(),
            self.has_interface_address(),
            self.has_interface_link(),
            self.has_author(),
            self.has_brd()
        )
    }
}

pub fn socketaddr_from_slice(data: &[u8]) -> Result<(SocketAddr, usize), AddressParseError> {
    if data.is_empty() {
        return Err(AddressParseError::DataEmpty);
    }
    // TODO: SAFETY: We're trusting that this truly is an accurate
    // struct as passed from the kernel. this should probably be removed from
    // the rest of the common parsing logic.
    let sockaddr_in_ptr: *const sockaddr_in = data.as_ptr() as *const _;
    let family = unsafe { (*sockaddr_in_ptr).sin_family as u32 };
    // NOTE: we have to get this here, because otherwise we can't skip over
    // unsupported chunks when parsing
    let len = unsafe { (*sockaddr_in_ptr).sin_len as usize };
    let res = match family {
        AF_INET => {
            log::debug!("IPV4 address");
            let ptr: *const sockaddr_in = data.as_ptr() as *const _;
            let v = <_ as NetStruct<_>>::from_raw(ptr)?;
            SocketAddr::V4(v)
        }
        AF_INET6 => {
            log::debug!("IPV6 address");
            let ptr: *const sockaddr_in6 = data.as_ptr() as *const _;
            let v = <_ as NetStruct<_>>::from_raw(ptr)?;
            SocketAddr::V6(v)
        }
        _ => {
            panic!("unsupported family for IPV4/V6 socketaddr: {family}");
        }
    };

    Ok((res, len))
}

#[derive(Debug)]
pub enum SockAddr {
    V4(SocketAddrV4),
    V6(SocketAddrV6),
    Link(DataLinkAddr),
}

impl SockAddr {
    pub(crate) fn from_raw(data: &[u8]) -> Result<(Option<Self>, usize), AddressParseError> {
        if data.is_empty() {
            return Err(AddressParseError::DataEmpty);
        }
        // TODO: SAFETY: We're trusting that this truly is an accurate
        // struct as passed from the kernel. this should probably be removed from
        // the rest of the common parsing logic.
        let sockaddr_in_ptr: *const sockaddr_in = data.as_ptr() as *const _;
        let family = unsafe { (*sockaddr_in_ptr).sin_family as u32 };
        // NOTE: we have to get this here, because otherwise we can't skip over
        // unsupported chunks when parsing
        let len = unsafe { (*sockaddr_in_ptr).sin_len as usize };
        let res = match family {
            AF_INET => {
                log::debug!("IPV4 address");
                let ptr: *const sockaddr_in = data.as_ptr() as *const _;
                let v = <_ as NetStruct<_>>::from_raw(ptr)?;
                Some(SockAddr::V4(v))
            }
            AF_INET6 => {
                log::debug!("IPV6 address");
                let ptr: *const sockaddr_in6 = data.as_ptr() as *const _;
                let v = <_ as NetStruct<_>>::from_raw(ptr)?;
                Some(SockAddr::V6(v))
            }
            AF_LINK => {
                log::debug!("Data link(?) address");
                let ptr: *const sockaddr_dl = data.as_ptr() as *const _;
                let v = <_ as NetStruct<_>>::from_raw(ptr)?;
                Some(SockAddr::Link(v))
            }
            _ => {
                log::warn!("Unsupported family {}", family);
                None
            }
        };

        Ok((res, len))
    }
}

#[derive(Debug)]
pub struct DataLinkAddr {
    pub index: u16,
    // Leaving the gigantic enum of this out for now
    // pub interface_type: InterfaceType,
    pub link_layer_addr: Vec<u8>,
    pub interface_name: String,
    // Discarding link layer selector
}

impl DataLinkAddr {
    fn format_addr(&self) -> String {
        let strs: Vec<String> = self
            .link_layer_addr
            .iter()
            .map(|b| format!("{:02X}", b))
            .collect();
        strs.join(":")
    }

    pub unsafe fn from_raw(ptr: *const sockaddr_dl) -> Self {
        let addr = *ptr;

        assert!(addr.sdl_family as u32 == AF_LINK);

        let index = addr.sdl_index;
        // NOTE: convert our [i8; 12] to a [u8; 12]. This is raw data that is
        // expected to be a C string.
        let data: [u8; 12] = mem::transmute(addr.sdl_data);

        log::trace!("nlen: {}, alen: {}", addr.sdl_nlen, addr.sdl_alen);

        let ll_addr_start = addr.sdl_nlen as usize;
        let ll_addr_end = ll_addr_start + addr.sdl_alen as usize;
        let link_layer_bytes = &data[ll_addr_start..ll_addr_end];
        let link_layer_addr = Vec::from(link_layer_bytes);
        let name_slice = &data[..addr.sdl_nlen as usize];
        log::trace!("name slice: {:?}", name_slice);
        let interface_name = String::from_utf8_lossy(name_slice).to_string().clone();
        log::trace!("index: {:?}, if name: {:?}", index, interface_name);

        DataLinkAddr {
            index,
            link_layer_addr,
            interface_name,
        }
    }

    pub fn print_self(&self) -> String {
        format!(
            "
        index: {}
        link addr: {}
        if name: {}
        ",
            self.index,
            self.format_addr(),
            self.interface_name
        )
    }
}

trait NetStruct<P>
where
    Self: Sized,
{
    const EXPECTED_FAMILY: u32;
    fn family(ptr: *const P) -> u32;
    fn len(ptr: *const P) -> usize;

    fn from_raw(ptr: *const P) -> Result<Self, AddressParseError>;

    fn from_slice(data: &[u8]) -> Result<Self, AddressParseError> {
        if data.is_empty() {
            return Err(AddressParseError::DataEmpty);
        }

        let ptr: *const P = data.as_ptr() as *const _;
        if data.len() < Self::len(ptr) {
            return Err(AddressParseError::PartialData);
        }

        let family = Self::family(ptr);
        if family != Self::EXPECTED_FAMILY {
            return Err(AddressParseError::WrongFamily(
                Self::EXPECTED_FAMILY,
                family,
            ));
        }

        Self::from_raw(ptr)
    }
}

impl NetStruct<sockaddr_dl> for DataLinkAddr {
    const EXPECTED_FAMILY: u32 = AF_LINK;

    fn family(ptr: *const sockaddr_dl) -> u32 {
        unsafe { (*ptr).sdl_family }.into()
    }

    fn len(ptr: *const sockaddr_dl) -> usize {
        unsafe { (*ptr).sdl_len }.into()
    }

    fn from_raw(ptr: *const sockaddr_dl) -> Result<Self, AddressParseError> {
        Ok(unsafe { DataLinkAddr::from_raw(ptr) })
    }
}

impl NetStruct<sockaddr_in> for SocketAddrV4 {
    const EXPECTED_FAMILY: u32 = AF_INET;

    fn family(ptr: *const sockaddr_in) -> u32 {
        unsafe { (*ptr).sin_family as u32 }
    }

    fn len(ptr: *const sockaddr_in) -> usize {
        unsafe { (*ptr).sin_len as usize }
    }

    fn from_raw(ptr: *const sockaddr_in) -> Result<Self, AddressParseError> {
        let raw_addr = unsafe { *ptr };

        let port = u16::from_be(raw_addr.sin_port);
        let s_addr = u32::from_be(raw_addr.sin_addr.s_addr);
        Ok(SocketAddrV4::new(
            Ipv4Addr::from(s_addr.to_be_bytes()),
            port,
        ))
    }
}

impl NetStruct<sockaddr_in6> for SocketAddrV6 {
    const EXPECTED_FAMILY: u32 = AF_INET6;

    fn family(ptr: *const sockaddr_in6) -> u32 {
        unsafe { (*ptr).sin6_family as u32 }
    }

    fn len(ptr: *const sockaddr_in6) -> usize {
        unsafe { (*ptr).sin6_len as usize }
    }

    fn from_raw(ptr: *const sockaddr_in6) -> Result<Self, AddressParseError> {
        let raw_addr = unsafe { *ptr };
        let port = u16::from_be((raw_addr).sin6_port);
        // SAFETY: This is a union of: [u8; 16], [u16; 8], [u32; 4]
        // which are all different ways to represent the same data
        // (a 128-bit IP address). In this case, we just take the
        // underlying data and cast it as a [u8; 16]
        let raw_ip_bytes: [u8; 16] = unsafe { mem::transmute(raw_addr.sin6_addr) };
        let addr = Ipv6Addr::from(raw_ip_bytes);

        let flowinfo = raw_addr.sin6_flowinfo;
        let scope_id = raw_addr.sin6_scope_id;
        Ok(SocketAddrV6::new(addr, port, flowinfo, scope_id))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum AddressParseError {
    #[error("given slice is empty")]
    DataEmpty,
    #[error("data given is larger than slice given")]
    PartialData,
    #[error("wrong family (expected {0}, got {1})")]
    WrongFamily(u32, u32),
}

pub(crate) fn parse_address(data: &[u8]) -> Result<(Option<SockAddr>, usize), AddressParseError> {
    if data.is_empty() {
        return Err(AddressParseError::DataEmpty);
    }

    let sa_len = data[0] as usize;
    log::debug!(
        "parsing address of size {} (slice size {})",
        sa_len,
        data.len()
    );

    if sa_len == 0 {
        log::warn!("sa_len was 0, trying to read empty address?");
        return Ok((None, sa_len));
    }

    // Make sure the buffer has enough data left
    if sa_len > data.len() {
        return Err(AddressParseError::PartialData);
    }

    // TODO: SAFETY: We're trusting that this truly is an accurate
    // struct as passed from the kernel. this should probably be removed from
    // the rest of the common parsing logic.
    let (res, _) = SockAddr::from_raw(&data[..sa_len]).unwrap();
    Ok((res, sa_len))
}

#[derive(Debug)]
pub enum AddressOperation {
    Add,
    Delete,
}

#[derive(Debug)]
pub struct AddressInfoFlags(u32);

impl AddressInfoFlags {
    pub fn new(val: u32) -> Self {
        Self(val)
    }

    /* route usable */
    pub fn is_up(&self) -> bool {
        self.0 & RTF_UP != 0
    }
    /* destination is a gateway */
    pub fn is_gateway(&self) -> bool {
        self.0 & RTF_GATEWAY != 0
    }
    /* host entry (net otherwise) */
    pub fn is_host(&self) -> bool {
        self.0 & RTF_HOST != 0
    }
    /* host or net unreachable */
    pub fn is_reject(&self) -> bool {
        self.0 & RTF_REJECT != 0
    }
    /* created dynamically (by redirect) */
    pub fn is_dynamic(&self) -> bool {
        self.0 & RTF_DYNAMIC != 0
    }
    /* modified dynamically (by redirect) */
    pub fn is_modified(&self) -> bool {
        self.0 & RTF_MODIFIED != 0
    }
    /* message confirmed */
    pub fn is_done(&self) -> bool {
        self.0 & RTF_DONE != 0
    }
    /* delete cloned route */
    pub fn is_delclone(&self) -> bool {
        self.0 & RTF_DELCLONE != 0
    }
    /* generate new routes on use */
    pub fn is_cloning(&self) -> bool {
        self.0 & RTF_CLONING != 0
    }
    /* external daemon resolves name */
    pub fn is_xresolve(&self) -> bool {
        self.0 & RTF_XRESOLVE != 0
    }
    /* generated by link layer (e.g. ARP) */
    pub fn is_llinfo(&self) -> bool {
        self.0 & RTF_LLINFO != 0
    }
    /* manually added */
    pub fn is_static(&self) -> bool {
        self.0 & RTF_STATIC != 0
    }
    /* just discard pkts (during updates) */
    pub fn is_blackhole(&self) -> bool {
        self.0 & RTF_BLACKHOLE != 0
    }
    /* not eligible for RTF_IFREF */
    pub fn is_noifref(&self) -> bool {
        self.0 & RTF_NOIFREF != 0
    }
    /* protocol specific routing flag */
    pub fn is_proto2(&self) -> bool {
        self.0 & RTF_PROTO2 != 0
    }
    /* protocol specific routing flag */
    pub fn is_proto1(&self) -> bool {
        self.0 & RTF_PROTO1 != 0
    }

    /* protocol requires cloning */
    pub fn is_prcloning(&self) -> bool {
        self.0 & RTF_PRCLONING != 0
    }
    /* route generated through cloning */
    pub fn is_wascloned(&self) -> bool {
        self.0 & RTF_WASCLONED != 0
    }
    /* protocol specific routing flag */
    pub fn is_proto3(&self) -> bool {
        self.0 & RTF_PROTO3 != 0
    }
    /* route represents a local address */
    pub fn is_local(&self) -> bool {
        self.0 & RTF_LOCAL != 0
    }
    /* route represents a bcast address */
    pub fn is_broadcast(&self) -> bool {
        self.0 & RTF_BROADCAST != 0
    }
    /* route represents a mcast address */
    pub fn is_multicast(&self) -> bool {
        self.0 & RTF_MULTICAST != 0
    }
    /* has valid interface scope */
    pub fn is_ifscope(&self) -> bool {
        self.0 & RTF_IFSCOPE != 0
    }
    /* defunct; no longer modifiable */
    pub fn is_condemned(&self) -> bool {
        self.0 & RTF_CONDEMNED != 0
    }
    /* route holds a ref to interface */
    pub fn is_ifref(&self) -> bool {
        self.0 & RTF_IFREF != 0
    }
    /* proxying, no interface scope */
    pub fn is_proxy(&self) -> bool {
        self.0 & RTF_PROXY != 0
    }
    /* host is a router */
    pub fn is_router(&self) -> bool {
        self.0 & RTF_ROUTER != 0
    }
    /* Route entry is being freed */
    pub fn is_dead(&self) -> bool {
        self.0 & RTF_DEAD != 0
    }
    /* route to destination of the global internet */
    // This doesn't exist on my system? was "only" added in 2022...
    // pub fn is_global(&self) -> bool {
    //     self.0 & RTF_GLOBAL != 0
    // }
}

#[derive(Debug)]
pub struct AddressSet {
    pub destination: Option<SockAddr>,
    pub gateway: Option<SockAddr>,
    pub netmask: Option<SockAddr>,
    pub genmask: Option<SockAddr>,
    pub broadcast: Option<SockAddr>,
    pub interface_addr: Option<SockAddr>,
    pub interface_link: Option<SockAddr>,
}

#[derive(Debug)]
pub struct AddressInfo {
    pub operation: AddressOperation,
    pub index: u32,
    pub metric: i32,
    pub flags: AddressInfoFlags,
    pub addrs: AddressSet,
}

impl AddressSet {
    pub fn from_raw(data: &[u8], flags: &AddressFlags) -> Result<Self, AddressParseError> {
        log::debug!("parsing addresses, data of length {}", data.len());
        let mut offset = 0;

        // Initialize variable to store route data
        let mut info = Self {
            destination: None,
            gateway: None,
            netmask: None,
            genmask: None,
            broadcast: None,
            interface_addr: None,
            interface_link: None,
        };

        // Apparently the order of these will correpond to which are defined
        // RTA_DST
        // RTA_GATEWAY
        // RTA_NETMASK
        // RTA_GENMASK
        // RTA_IFP
        // RTA_IFA
        // RTA_AUTHOR
        // RTA_BRD
        if flags.has_destination() {
            log::debug!("parsing destination");
            let (dest, len) = parse_address(&data[offset..])?;
            log::debug!("parsed {} bytes", len);
            info.destination = dest;
            offset += len;
        }

        if flags.has_gateway() {
            log::debug!("parsing gateway");
            let (gw, len) = parse_address(&data[offset..])?;
            log::debug!("parsed {} bytes", len);
            info.gateway = gw;
            offset += len;
        }

        if flags.has_netmask() {
            log::debug!("parsing netmask");
            let (netmask, len) = parse_address(&data[offset..])?;
            info.netmask = netmask;
            log::debug!("parsed {} bytes", len);
            offset += len;
        }

        if flags.has_genmask() {
            log::debug!("parsing genmask");
            let (genmask, len) = parse_address(&data[offset..])?;
            info.genmask = genmask;
            log::debug!("parsed {} bytes", len);
            offset += len;
        }

        if flags.has_interface_link() {
            log::debug!("parsing link");
            let ptr = (data[offset..]).as_ptr() as *const _;
            let if_link = <_ as NetStruct<_>>::from_raw(ptr)?;
            let len = <DataLinkAddr as NetStruct<_>>::len(ptr);
            info.interface_link = Some(if_link);
            log::debug!("parsed {} bytes", len);
            offset += len;
        }

        if flags.has_interface_address() {
            log::debug!("parsing if address");
            let (interface_addr, len) = socketaddr_from_slice(&data[offset..])?;
            info.interface_addr = Some(interface_addr);
            log::debug!("parsed {} bytes", len);
            offset += len;
        }

        if flags.has_author() {
            log::debug!("parsing author");
            let (_, len) = parse_address(&data[offset..])?;
            log::debug!("parsed {} bytes", len);
            offset += len;
        }

        if flags.has_brd() {
            log::debug!("parsing broadcast");
            let (broadcast, _) = parse_address(&data[offset..])?;
            info.broadcast = broadcast;
        }
        Ok(info)
    }

    pub fn print_self(&self) -> String {
        format!(
            "
    destination: {:?}
    gateway: {:?}
    netmask: {:?}
    genmask: {:?}
    broadcast: {:?}
    interface_addr: {:?}
    interface_link: {:?}",
            self.destination,
            self.gateway,
            self.netmask,
            self.genmask,
            self.broadcast,
            self.interface_addr,
            self.interface_link,
        )
    }
}

impl AddressInfo {
    pub fn print_self(&self) -> String {
        format!(
            "
    operation: {:?}
    index: {}
    metric: {}
    addresses: {}

    is up: {}
    is gateway: {}
    is unreachable: {}
    is local: {}
    is broadcast: {}
    is ifref: {}
    is router: {}
",
            self.operation,
            self.index,
            self.metric,
            self.addrs.print_self(),
            self.flags.is_up(),
            self.flags.is_gateway(),
            self.flags.is_dead(),
            self.flags.is_local(),
            self.flags.is_broadcast(),
            self.flags.is_ifref(),
            self.flags.is_router(),
        )
    }

    pub fn from_raw(data: &[u8]) -> Result<Option<Self>, AddressParseError> {
        log::debug!("parsing an address message of length {}", data.len());

        // Get the header
        let hdr_ptr: *const ifa_msghdr = data.as_ptr() as *const _;
        let hdr = unsafe { *hdr_ptr };

        let flags = AddressInfoFlags::new(hdr.ifam_flags as u32);

        let op = match (hdr).ifam_type as u32 {
            RTM_NEWADDR => AddressOperation::Add,
            RTM_DELADDR => AddressOperation::Delete,
            _ => return Ok(None),
        };

        // Start of parsing sockaddr structures
        let addr_flags = AddressFlags::new(hdr.ifam_addrs as u32);
        let addrs_data = &data[std::mem::size_of::<ifa_msghdr>()..];
        let addrs = AddressSet::from_raw(addrs_data, &addr_flags)?;

        // Initialize variable to store route data
        Ok(Some(Self {
            index: hdr.ifam_index as u32,
            operation: op,
            flags,
            metric: hdr.ifam_metric,
            addrs,
        }))
    }
}
