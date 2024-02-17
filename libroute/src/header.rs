use route_sys::{
    rt_metrics, rt_msghdr, RTM_ADD, RTM_CHANGE, RTM_DELADDR, RTM_DELETE, RTM_DELMADDR, RTM_GET,
    RTM_GET2, RTM_IFINFO, RTM_IFINFO2, RTM_LOCK, RTM_LOSING, RTM_MISS, RTM_NEWADDR, RTM_NEWMADDR,
    RTM_NEWMADDR2, RTM_OLDADD, RTM_OLDDEL, RTM_REDIRECT, RTM_RESOLVE,
};

/// Type of message from kernel
/// Comments taken from source code
/// https://opensource.apple.com/source/network_cmds/network_cmds-606.40.2/route.tproj/route.c.auto.html
pub enum MessageType {
    /// Add Route
    Add,
    /// Delete Route
    Delete,
    /// Change Metrics or flags
    Change,
    /// Report Metrics
    Get,
    /// Kernel Suspects Partitioning
    Losing,
    /// Told to use different route
    Redirect,
    /// Lookup failed on this address
    Miss,
    /// fix specified metrics
    Lock,
    /// caused by SIOCADDRT
    Oldadd,
    /// caused by SIOCDELRT
    Olddel,
    /// Route created by cloning
    Resolve,
    /// address being added to iface
    Newaddr,
    /// address being removed from iface
    Deladdr,
    /// iface status change
    Ifinfo,
    /// new multicast group membership on iface
    Newmaddr,
    /// multicast group membership removed from iface
    Delmaddr,
    // Undocumented
    Ifinfo2,
    // Undocumented
    Newmaddr2,
    // Undocumented
    Get2,
}

#[derive(thiserror::Error, Debug)]
#[error("invalid message type {0}, needs to be below 21")]
pub struct MessageTypeParseError(u8);

impl TryFrom<u8> for MessageType {
    type Error = MessageTypeParseError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value.into() {
            RTM_ADD => Ok(Self::Add),
            RTM_DELETE => Ok(Self::Delete),
            RTM_CHANGE => Ok(Self::Change),
            RTM_GET => Ok(Self::Get),
            RTM_LOSING => Ok(Self::Losing),
            RTM_REDIRECT => Ok(Self::Redirect),
            RTM_MISS => Ok(Self::Miss),
            RTM_LOCK => Ok(Self::Lock),
            RTM_OLDADD => Ok(Self::Oldadd),
            RTM_OLDDEL => Ok(Self::Olddel),
            RTM_RESOLVE => Ok(Self::Resolve),
            RTM_NEWADDR => Ok(Self::Newaddr),
            RTM_DELADDR => Ok(Self::Deladdr),
            RTM_IFINFO => Ok(Self::Ifinfo),
            RTM_NEWMADDR => Ok(Self::Newmaddr),
            RTM_DELMADDR => Ok(Self::Delmaddr),
            RTM_IFINFO2 => Ok(Self::Ifinfo2),
            RTM_NEWMADDR2 => Ok(Self::Newmaddr2),
            RTM_GET2 => Ok(Self::Get2),
            _ => Err(MessageTypeParseError(value)),
        }
    }
}

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

#[allow(dead_code)]
/// Mostly equivalent to rt_msghdr from `man 4 route`
pub struct MessageHeader {
    /// to skip over non-understood messages
    length: u16,
    /// message type
    message_type: MessageType,
    /// index for associated ifp or interface scope
    index: u16,
    /// identify sender
    pid: i32,
    /// bitmask identifying sockaddrs in msg
    addrs: i32,
    /// for sender to identify action
    seq: i32,
    /// why failed
    errno: i32,
    /// flags, incl kern & message, e.g. DONE
    flags: i32,
    /// which values we are initializing
    inits: u32,
    /// metrics themselves
    metrics: Metrics,
}

impl TryFrom<rt_msghdr> for MessageHeader {
    type Error = MessageTypeParseError;

    fn try_from(value: rt_msghdr) -> Result<Self, Self::Error> {
        Ok(Self {
            addrs: value.rtm_addrs,
            errno: value.rtm_errno,
            flags: value.rtm_flags,
            index: value.rtm_index,
            inits: value.rtm_inits,
            length: value.rtm_msglen,
            pid: value.rtm_pid,
            seq: value.rtm_seq,
            message_type: MessageType::try_from(value.rtm_type)?,
            metrics: Metrics::from(value.rtm_rmx),
        })
    }
}

pub struct InterfaceData {
    ifi_type: char,
    ifi_typelen: char,
    ifi_physical: char,
    ifi_addrlen: char,
    ifi_hdrlen: char,
    ifi_recvquota: char,
    ifi_xmitquota: char,
    ifi_unused1: char,
    ifi_mtu: u32,
    ifi_metric: u32,
    ifi_baudrate: u32,
    ifi_ipackets: u32,
    ifi_ierrors: u32,
    ifi_opackets: u32,
    ifi_oerrors: u32,
    ifi_collisions: u32,
    ifi_ibytes: u32,
    ifi_obytes: u32,
    ifi_imcasts: u32,
    ifi_omcasts: u32,
    ifi_iqdrops: u32,
    ifi_noproto: u32,
    ifi_recvtiming: u32,
    ifi_xmittiming: u32,
    // TODO: chrono? (time value)
    // (prev: timeval32)
    ifi_lastchange: u64,
    ifi_unused2: u32,
    ifi_hwassist: u32,
    ifi_reserved1: u32,
    ifi_reserved2: u32,
}

pub struct InterfaceMessageHeader {
    length: u16,
    // TODO?
    message_type: MessageType,
    addrs: i32,
    flags: i32,
    index: u16,
    interface_data: InterfaceData,
}

pub struct InterfaceAddressMessageHeader {
    msglen: u16,
    version: u8,
    // TODO?
    message_type: u8,
    addrs: i32,
    flags: i32,
    index: u16,
    metric: i32,
}
