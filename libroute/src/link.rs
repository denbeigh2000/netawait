use route_sys::{
    if_msghdr, RTM_DELADDR, RTM_DELMADDR, RTM_IFINFO, RTM_IFINFO2, RTM_NEWADDR, RTM_NEWMADDR,
    RTM_NEWMADDR2,
};

use crate::addresses::{AddressFlags, AddressParseError, AddressSet};

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
    pub operation: MessageType,
    pub index: u32,
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
        let addr_flags = AddressFlags::new(hdr.ifm_addrs as u32);
        let addrs_data = &data[struct_size..];

        Ok(Some(Self {
            operation: MessageType::from_raw(hdr.ifm_type.into()).unwrap(),
            index: hdr.ifm_index as u32,
            addrs: AddressSet::from_raw(addrs_data, &addr_flags)?,
        }))
    }

    pub fn print_self(&self) -> String {
        format!(
            "
    operation:      {:?}
    index:          {:?}
    addrs:          {}
",
            self.operation,
            self.index,
            self.addrs.print_self(),
        )
    }
}
