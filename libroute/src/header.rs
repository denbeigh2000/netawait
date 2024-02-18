use std::{convert::Infallible, net::SocketAddr};

use route_sys::{
    rt_metrics, rt_msghdr, AF_INET, AF_INET6, RTF_GATEWAY, RTF_UP, RTM_ADD, RTM_CHANGE,
    RTM_DELADDR, RTM_DELETE, RTM_DELMADDR, RTM_GET, RTM_GET2, RTM_IFINFO, RTM_IFINFO2, RTM_LOCK,
    RTM_LOSING, RTM_MISS, RTM_NEWADDR, RTM_NEWMADDR, RTM_NEWMADDR2, RTM_OLDADD, RTM_OLDDEL,
    RTM_REDIRECT, RTM_RESOLVE,
};

use crate::addresses::{parse_address, AddressFlags};

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

#[derive(thiserror::Error, Debug)]
#[error("invalid message type {0}, needs to be below 21")]
pub struct MessageTypeParseError(u8);

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

#[derive(Clone)]
pub struct Metrics {
    /// MTU for this path
    pub mtu: u32,
    /// max hops expected
    pub hop_count: u32,
    /// lifetime for route, e.g. redirect
    pub expire: i32,
    /// inbound delay-bandwith product
    pub recv_pipe: u32,
    /// outbound delay-bandwith product
    pub send_pipe: u32,
    /// outbound gateway buffer limit
    pub ss_threshold: u32,
    /// estimated round trip time
    pub rtt_time: u32,
    /// estimated rtt variance
    pub rtt_variance: u32,
    /// packets sent (not in man page)
    pub packets_sent: u32,
    /// state(??) (not in man page)
    pub state: u32,
}

impl From<rt_metrics> for Metrics {
    fn from(value: rt_metrics) -> Self {
        Self {
            mtu: value.rmx_mtu,
            hop_count: value.rmx_hopcount,
            expire: value.rmx_expire,
            recv_pipe: value.rmx_recvpipe,
            send_pipe: value.rmx_sendpipe,
            ss_threshold: value.rmx_ssthresh,
            rtt_time: value.rmx_rtt,
            rtt_variance: value.rmx_rttvar,
            packets_sent: value.rmx_pksent,
            state: value.rmx_state,
        }
    }
}

#[derive(Debug)]
pub struct RouteInfo {
    pub operation: MessageType,
    pub destination: Option<SocketAddr>,
    pub gateway: Option<SocketAddr>,
    pub netmask: Option<SocketAddr>,
    pub broadcast: Option<SocketAddr>,
    pub interface_addr: Option<SocketAddr>,
    pub flags: RoutingFlags, // parsed from rt_flags in rt_msghdr
    pub metrics: RouteMetrics,
}

impl RouteInfo {
    pub fn from_raw(data: &[u8]) -> Result<Option<Self>, Infallible> {
        // Get the header
        let hdr_ptr: *const rt_msghdr = data.as_ptr() as *const _;
        let hdr = unsafe { *hdr_ptr };

        // Validate the message type

        let op = match (hdr).rtm_type as u32 {
            RTM_ADD => MessageType::Add,
            RTM_DELETE => MessageType::Delete,
            RTM_GET => MessageType::Get,
            RTM_CHANGE => MessageType::Change,
            // I don't know what this is, but tell apple I hate them
            RTM_GET2 => MessageType::Get2,
            _ => return Ok(None),
        };

        // Get the flags
        let flags = RoutingFlags::from_raw(hdr.rtm_flags);

        // Initialize variable to store route data
        let mut route_info = RouteInfo {
            operation: op,
            flags,
            metrics: RouteMetrics::from_raw(&hdr.rtm_rmx),
            destination: None,
            gateway: None,
            netmask: None,
            broadcast: None,
            interface_addr: None,
        };

        // Start of parsing sockaddr structures
        let addr_flags = AddressFlags::new(hdr.rtm_addrs as u32);
        let addrs_data = &data[std::mem::size_of::<rt_msghdr>()..];
        let mut offset = 0;

        // Apparently the order of these will correpond to which are defined
        // RTA_DST
        // RTA_GATEWAY
        // RTA_NETMASK
        // RTA_GENMASK
        // RTA_IFP
        // RTA_IFA
        // RTA_AUTHOR
        // RTA_BRD
        if addr_flags.has_destination() {
            let (dest, len) = parse_address(&addrs_data[offset..]).unwrap();
            route_info.destination = dest;
            offset += len;
        }

        if addr_flags.has_gateway() {
            let (gw, len) = parse_address(&addrs_data[offset..]).unwrap();
            route_info.gateway = gw;
            offset += len;
        }

        if addr_flags.has_netmask() {
            let (netmask, len) = parse_address(&addrs_data[offset..]).unwrap();
            route_info.netmask = netmask;
            offset += len;
        }

        if addr_flags.has_genmask() {
            let (_, len) = parse_address(&addrs_data[offset..]).unwrap();
            offset += len;
        }

        if addr_flags.has_interface_link() {
            let (_, len) = parse_address(&addrs_data[offset..]).unwrap();
            offset += len;
        }

        if addr_flags.has_interface_address() {
            let (interface_addr, len) = parse_address(&addrs_data[offset..]).unwrap();
            route_info.interface_addr = interface_addr;
            offset += len;
        }

        if addr_flags.has_author() {
            let (_, len) = parse_address(&addrs_data[offset..]).unwrap();
            offset += len;
        }

        if addr_flags.has_brd() {
            (route_info.broadcast, _) = parse_address(&addrs_data[offset..]).unwrap();
        }

        Ok(Some(route_info))
    }
}

#[derive(Debug)]
pub struct RoutingFlags(i32);

impl RoutingFlags {
    fn from_raw(flags: i32) -> Self {
        Self(flags)
    }

    fn is_up(&self) -> bool {
        self.0 & (RTF_UP as i32) != 0
    }

    fn is_gateway(&self) -> bool {
        self.0 & (RTF_GATEWAY as i32) != 0
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
