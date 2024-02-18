// use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

// use route_sys::{RTF_GATEWAY, RTF_UP};
//
// static ZERO_IPV4: IpAddr = IpAddr::V4(Ipv4Addr::UNSPECIFIED);
// static ZERO_IPV6: IpAddr = IpAddr::V6(Ipv6Addr::UNSPECIFIED);

// pub struct Route {
//     /// Network address of the destination. `0.0.0.0` with a prefix of `0` is considered a default route.
//     pub destination: IpAddr,
//
//     /// Length of network prefix in the destination address.
//     pub prefix: u8,
//
//     /// The address of the next hop of this route.
//     ///
//     /// On macOS, this must be `Some` if ifindex is `None`
//     pub gateway: Option<IpAddr>,
//
//     /// The index of the local interface through which the next hop of this route may be reached.
//     ///
//     /// On macOS, this must be `Some` if gateway is `None`
//     pub ifindex: Option<u32>,
// }
//
// impl Route {
//     pub fn is_viable_default(&self) -> bool {
//         self.gateway.is_some() && self.is_default()
//     }
//
//     pub fn is_default(&self) -> bool {
//         self.prefix == 0 && (self.destination == ZERO_IPV4 || self.destination == ZERO_IPV6)
//     }
// }
