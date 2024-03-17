use crate::addresses::{AddressFlags, AddressParseError, AddressSet};

use nix::libc::{
    rt_metrics, rt_msghdr, RTF_GATEWAY, RTF_UP, RTM_ADD, RTM_CHANGE, RTM_DELETE, RTM_GET, RTM_GET2,
};

#[derive(Clone, Debug)]
/// Type of message from kernel
/// Comments taken from source code
/// https://opensource.apple.com/source/network_cmds/network_cmds-606.40.2/route.tproj/route.c.auto.html
///
/// (Only handing the changes related to the routing table)
pub enum MessageType {
    /// Add Route
    Add,
    /// Delete Route
    Delete,
    /// Change Metrics or flags
    Change,
    /// Respond to query
    Get,
    // Undocumented
    Get2,
}

impl MessageType {
    pub fn from(value: u8) -> Option<Self> {
        match value.into() {
            RTM_ADD => Some(Self::Add),
            RTM_DELETE => Some(Self::Delete),
            RTM_CHANGE => Some(Self::Change),
            RTM_GET => Some(Self::Get),
            RTM_GET2 => Some(Self::Get2),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct RouteInfo {
    pub operation: MessageType,
    pub index: u16,
    pub flags: RoutingFlags, // parsed from rt_flags in rt_msghdr
    pub metrics: RouteMetrics,

    pub addrs: AddressSet,
}

impl RouteInfo {
    pub fn print_self(&self) -> String {
        format!(
            "
    index:          {:?}
    operation:      {:?}
    flags:          {}
    metrics:        {:?}

    addrs:          {}
",
            self.index,
            self.operation,
            self.flags,
            self.metrics,
            self.addrs.print_self(),
        )
    }

    pub(crate) fn from_raw(data: &[u8]) -> Result<Option<Self>, AddressParseError> {
        log::debug!("parsing a message of length {}", data.len());
        let hdr_ptr: *const rt_msghdr = data.as_ptr() as *const _;
        // SAFETY: We depend on this being a byte slice received directly from
        // the kernel. The privacy of this function should be enough to
        // confirm this.
        let hdr = unsafe { *hdr_ptr };

        // Validate the message type
        let op = match (hdr).rtm_type as i32 {
            RTM_ADD => MessageType::Add,
            RTM_DELETE => MessageType::Delete,
            RTM_GET => MessageType::Get,
            RTM_CHANGE => MessageType::Change,
            // I don't know what this is, but tell apple I hate them
            RTM_GET2 => MessageType::Get2,
            _ => return Ok(None),
        };

        // Start of parsing sockaddr structures
        let addr_flags = AddressFlags::new(hdr.rtm_addrs);
        log::trace!("op: {op:?}, addr_flags: {}", addr_flags);
        let addrs_data = &data[std::mem::size_of::<rt_msghdr>()..];
        log::trace!("sizeof: {:?}", std::mem::size_of::<rt_msghdr>());
        log::trace!("addrs_data: {:?}", addrs_data);

        // Initialize variable to store route data
        Ok(Some(Self {
            index: hdr.rtm_index,
            operation: op,
            flags: RoutingFlags::from_raw(hdr.rtm_flags),
            metrics: RouteMetrics::from_raw(&hdr.rtm_rmx),
            addrs: AddressSet::from_raw(addrs_data, &addr_flags)?,
        }))
    }
}

#[derive(Debug)]
pub struct RoutingFlags(i32);

impl std::fmt::Display for RoutingFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "RoutingFlags({:02b})", self.0)
    }
}

impl RoutingFlags {
    pub fn from_raw(flags: i32) -> Self {
        Self(flags)
    }

    // TODO: We may want to support more here?
    pub fn is_up(&self) -> bool {
        self.0 & (RTF_UP) != 0
    }

    pub fn has_gateway(&self) -> bool {
        self.0 & (RTF_GATEWAY) != 0
    }
}

#[derive(Debug)]
pub struct RouteMetrics {
    pub mtu: u64,
    pub hopcount: u32,
    pub expire: i32,
    pub recvpipe: u64,
    pub sendpipe: u64,
    pub ssthresh: u64,
    pub rtt: u32,
    pub rttvar: u32,
    pub packets_sent: u64,
}

impl RouteMetrics {
    pub fn from_raw(metrics: &rt_metrics) -> Self {
        Self {
            mtu: metrics.rmx_mtu as u64,
            hopcount: metrics.rmx_hopcount,
            expire: metrics.rmx_expire,
            recvpipe: metrics.rmx_recvpipe as u64,
            sendpipe: metrics.rmx_sendpipe as u64,
            ssthresh: metrics.rmx_ssthresh as u64,
            rtt: metrics.rmx_rtt,
            rttvar: metrics.rmx_rttvar,
            packets_sent: metrics.rmx_pksent as u64,
        }
    }
}
