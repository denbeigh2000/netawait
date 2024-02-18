use std::net::SocketAddr;

use route_sys::{
    if_msghdr, RTM_DELADDR, RTM_DELMADDR, RTM_IFINFO, RTM_IFINFO2, RTM_NEWADDR, RTM_NEWMADDR,
    RTM_NEWMADDR2,
};

use crate::addresses::{parse_address, AddressFlags, AddressParseError};

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
    pub fn from_raw(value: u32) -> Option<Self> {
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
    pub destination: Option<SocketAddr>,
    pub gateway: Option<SocketAddr>,
    pub netmask: Option<SocketAddr>,
    pub interface_addr: Option<SocketAddr>,
    pub broadcast: Option<SocketAddr>,
    pub operation: MessageType,
    pub index: u32,
}

impl LinkInfo {
    pub fn from_raw(data: &[u8]) -> Result<Option<Self>, AddressParseError> {
        let hdr_ptr: *const if_msghdr = data.as_ptr() as *const _;
        let hdr = unsafe { *hdr_ptr };

        let struct_size = std::mem::size_of::<if_msghdr>();
        let data_len = data.len();
        eprintln!("{struct_size}, {data_len}");
        if struct_size > data_len {
            log::warn!(
                "skipping payload, struct size {} greater than data size {}",
                struct_size,
                data_len
            );
            return Ok(None);
        }
        // assert!(struct_size <= data_len);

        let mut res = Self {
            destination: None,
            gateway: None,
            netmask: None,
            interface_addr: None,
            broadcast: None,
            operation: MessageType::from_raw(hdr.ifm_type.into()).unwrap(),
            index: hdr.ifm_index as u32,
        };

        // The source code says to see rtm_attrs for these, so..
        let addr_flags = AddressFlags::new(hdr.ifm_addrs as u32);
        let mut offset = 0;
        let addrs_data = &data[struct_size..];

        if addr_flags.has_destination() {
            log::debug!("parsing destination");
            let (dest, len) = parse_address(&addrs_data[offset..])?;
            log::debug!("parsed {} bytes", len);
            res.destination = dest;
            offset += len;
        }

        if addr_flags.has_gateway() {
            log::debug!("parsing gateway");
            let (gw, len) = parse_address(&addrs_data[offset..])?;
            log::debug!("parsed {} bytes", len);
            res.gateway = gw;
            offset += len;
        }

        if addr_flags.has_netmask() {
            log::debug!("parsing netmask");
            let (netmask, len) = parse_address(&addrs_data[offset..])?;
            res.netmask = netmask;
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
            res.interface_addr = interface_addr;
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
            (res.broadcast, _) = parse_address(&addrs_data[offset..])?;
        }

        Ok(Some(res))
    }

    pub fn print_self(&self) -> String {
        format!(
            "
    operation:      {:?},
    destination:    {:?},
    gateway:        {:?},
    netmask:        {:?},
    broadcast:      {:?},
    interface_addr: {:?},
",
            self.operation,
            self.destination,
            self.gateway,
            self.netmask,
            self.broadcast,
            self.interface_addr,
        )
    }
}
