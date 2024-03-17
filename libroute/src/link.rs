use crate::addresses::{AddressFlags, AddressParseError, AddressSet};

use nix::libc::{
    if_msghdr, IFF_ALLMULTI, IFF_BROADCAST, IFF_DEBUG, IFF_LOOPBACK, IFF_NOARP, IFF_NOTRAILERS,
    IFF_OACTIVE, IFF_POINTOPOINT, IFF_PROMISC, IFF_RUNNING, IFF_SIMPLEX, IFF_UP, RTM_DELADDR,
    RTM_DELMADDR, RTM_IFINFO, RTM_IFINFO2, RTM_NEWADDR, RTM_NEWMADDR, RTM_NEWMADDR2,
};

#[derive(Debug)]
pub enum MessageType {
    Info,
    NewAddr,
    NewMAddr,
    DelAddr,
    DelMAddr,
    Info2,
    NewMAddr2,
}

impl MessageType {
    pub fn from_raw(value: i32) -> Option<Self> {
        match value {
            RTM_IFINFO => Some(MessageType::Info),
            RTM_NEWADDR => Some(MessageType::NewAddr),
            RTM_NEWMADDR => Some(MessageType::NewMAddr),
            RTM_DELADDR => Some(MessageType::DelAddr),
            RTM_DELMADDR => Some(MessageType::DelMAddr),
            RTM_IFINFO2 => Some(MessageType::Info2),
            RTM_NEWMADDR2 => Some(MessageType::NewMAddr2),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct LinkInfo {
    pub operation: MessageType,
    pub index: u16,
    pub flags: LinkFlags,
    pub addrs: AddressSet,
}

impl LinkInfo {
    pub fn from_raw(data: &[u8]) -> Result<Option<Self>, AddressParseError> {
        let hdr_ptr: *const if_msghdr = data.as_ptr() as *const _;
        let hdr = unsafe { *hdr_ptr };

        let struct_size = std::mem::size_of::<if_msghdr>();
        let data_len = data.len();
        assert!(struct_size <= data_len);

        // The source code says to see rtm_attrs for these, so..
        let addr_flags = AddressFlags::new(hdr.ifm_addrs);
        let addrs_data = &data[struct_size..];

        Ok(Some(Self {
            operation: MessageType::from_raw(hdr.ifm_type.into()).unwrap(),
            index: hdr.ifm_index,
            flags: LinkFlags::new(hdr.ifm_flags),
            addrs: AddressSet::from_raw(addrs_data, &addr_flags)?,
        }))
    }

    pub fn print_self(&self) -> String {
        format!(
            "
    operation:      {:?}
    index:          {:?}
    addrs:          {}

    is_up:          {}
    is_broadcast:   {}
    is_debug:       {}
    is_loopback:    {}
    is_p2p:         {}
    is_notrailers:  {}
    is_running:     {}
    is_noarp:       {}
    is_promisc:     {}
    is_allmulti:    {}
    is_oactive:     {}
    is_simplex:     {}

    {:?}
",
            self.operation,
            self.index,
            self.addrs.print_self(),
            self.flags.is_up(),
            self.flags.is_broadcast(),
            self.flags.is_debug(),
            self.flags.is_loopback(),
            self.flags.is_pointopoint(),
            self.flags.is_notrailers(),
            self.flags.is_running(),
            self.flags.is_noarp(),
            self.flags.is_promisc(),
            self.flags.is_allmulti(),
            self.flags.is_oactive(),
            self.flags.is_simplex(),
            self,
        )
    }
}

#[derive(Debug)]
pub struct LinkFlags(i32);

impl LinkFlags {
    pub fn new(flags: i32) -> Self {
        Self(flags)
    }

    pub fn is_up(&self) -> bool {
        self.0 & IFF_UP != 0
    }
    pub fn is_broadcast(&self) -> bool {
        self.0 & IFF_BROADCAST != 0
    }
    pub fn is_debug(&self) -> bool {
        self.0 & IFF_DEBUG != 0
    }
    pub fn is_loopback(&self) -> bool {
        self.0 & IFF_LOOPBACK != 0
    }
    pub fn is_pointopoint(&self) -> bool {
        self.0 & IFF_POINTOPOINT != 0
    }
    pub fn is_notrailers(&self) -> bool {
        self.0 & IFF_NOTRAILERS != 0
    }
    pub fn is_running(&self) -> bool {
        self.0 & IFF_RUNNING != 0
    }
    pub fn is_noarp(&self) -> bool {
        self.0 & IFF_NOARP != 0
    }
    pub fn is_promisc(&self) -> bool {
        self.0 & IFF_PROMISC != 0
    }
    pub fn is_allmulti(&self) -> bool {
        self.0 & IFF_ALLMULTI != 0
    }
    pub fn is_oactive(&self) -> bool {
        self.0 & IFF_OACTIVE != 0
    }
    pub fn is_simplex(&self) -> bool {
        self.0 & IFF_SIMPLEX != 0
    }
}
