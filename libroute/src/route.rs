use crate::header::interface_index_to_name;
use std::net::SocketAddr;

use route_sys::{
    rt_metrics, rt_msghdr, RTF_GATEWAY, RTF_UP, RTM_ADD, RTM_CHANGE, RTM_DELETE, RTM_GET, RTM_GET2,
};

use crate::addresses::{parse_address, AddressFlags, AddressParseError};

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
    pub destination: Option<SocketAddr>,
    pub gateway: Option<SocketAddr>,
    pub netmask: Option<SocketAddr>,
    pub broadcast: Option<SocketAddr>,
    pub interface_addr: Option<SocketAddr>,
    pub interface_name: Option<String>,
    pub flags: RoutingFlags, // parsed from rt_flags in rt_msghdr
    pub metrics: RouteMetrics,
}

impl RouteInfo {
    pub fn print_self(&self) -> String {
        format!(
            "
    operation:      {:?},
    destination:    {:?},
    gateway:        {:?},
    netmask:        {:?},
    broadcast:      {:?},
    interface_addr: {:?},
    interface_name: {:?},
",
            self.operation,
            self.destination,
            self.gateway,
            self.netmask,
            self.broadcast,
            self.interface_addr,
            self.interface_name,
        )
    }

    pub fn from_raw(data: &[u8]) -> Result<Option<Self>, AddressParseError> {
        log::debug!("parsing a message of length {}", data.len());
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
        let interface_name = interface_index_to_name(hdr.rtm_index as u32);

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
            interface_name,
        };

        // Start of parsing sockaddr structures
        let addr_flags = AddressFlags::new(hdr.rtm_addrs as u32);
        let addrs_data = &data[std::mem::size_of::<rt_msghdr>()..];
        let mut offset = 0;
        // eprintln!("{}", addr_flags.print_self());

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
            log::debug!("parsing destination");
            let (dest, len) = parse_address(&addrs_data[offset..])?;
            log::debug!("parsed {} bytes", len);
            route_info.destination = dest;
            offset += len;
        }

        if addr_flags.has_gateway() {
            log::debug!("parsing gateway");
            let (gw, len) = parse_address(&addrs_data[offset..])?;
            log::debug!("parsed {} bytes", len);
            route_info.gateway = gw;
            offset += len;
        }

        if addr_flags.has_netmask() {
            log::debug!("parsing netmask");
            let (netmask, len) = parse_address(&addrs_data[offset..])?;
            route_info.netmask = netmask;
            log::debug!("parsed {} bytes", len);
            offset += len;
        }

        if addr_flags.has_genmask() {
            log::debug!("parsing genmask");
            let (_, len) = parse_address(&addrs_data[offset..])?;
            log::debug!("parsed {} bytes", len);
            offset += len;
        }

        if addr_flags.has_interface_link() {
            log::debug!("parsing link");
            let (_, len) = parse_address(&addrs_data[offset..])?;
            log::debug!("parsed {} bytes", len);
            offset += len;
        }

        if addr_flags.has_interface_address() {
            log::debug!("parsing if address");
            let (interface_addr, len) = parse_address(&addrs_data[offset..])?;
            route_info.interface_addr = interface_addr;
            log::debug!("parsed {} bytes", len);
            offset += len;
        }

        if addr_flags.has_author() {
            log::debug!("parsing author");
            let (_, len) = parse_address(&addrs_data[offset..])?;
            log::debug!("parsed {} bytes", len);
            offset += len;
        }

        if addr_flags.has_brd() {
            log::debug!("parsing broadcast");
            (route_info.broadcast, _) = parse_address(&addrs_data[offset..])?;
        }

        Ok(Some(route_info))
    }
}

#[derive(Debug)]
pub struct RoutingFlags(i32);

impl RoutingFlags {
    pub fn from_raw(flags: i32) -> Self {
        Self(flags)
    }

    pub fn is_up(&self) -> bool {
        self.0 & (RTF_UP as i32) != 0
    }

    pub fn has_gateway(&self) -> bool {
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
