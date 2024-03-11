use flags::Args;
use libroute::addresses::{AddressOperation, SockAddr};
use libroute::header::Header;
use libroute::link::MessageType as LinkMessageType;
use libroute::route::MessageType as RouteMessageType;
use libroute::socket::{get_ifindex, ReadError, RouteSocket};

use clap::Parser;
use ipnetwork::{Ipv4Network, Ipv6Network};

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::flags::WaitConditionFlag;

lazy_static::lazy_static! {
    static ref ZERO_IPV4: Ipv4Addr = Ipv4Addr::from([0, 0, 0, 0]);
    static ref ZERO_IPV6: Ipv6Addr = Ipv6Addr::from([0, 0, 0, 0, 0, 0, 0, 0]);

    static ref LOCAL_IPV6_ADDR: Ipv6Addr = Ipv6Addr::from([0, 0, 0, 0, 0, 0, 0, 1]);
    static ref LOCAL_IPV4_RANGE: Ipv4Network = Ipv4Network::new(Ipv4Addr::from([127, 0, 0, 0]), 8).unwrap();

    // Link local address range: 169.254.0.0/16
    // https://en.wikipedia.org/wiki/Link-local_address#IPv4
    static ref LINK_LOCAL_IPV4_RANGE: Ipv4Network = Ipv4Network::new(Ipv4Addr::from([169, 254, 0, 0]), 16).unwrap();
    // Link local address range: fe80::/10
    // https://en.wikipedia.org/wiki/Link-local_address#IPv6
    static ref LINK_LOCAL_IPV6_RANGE: Ipv6Network = Ipv6Network::new(Ipv6Addr::from([65152, 0, 0, 0, 0, 0, 0, 0]), 10).unwrap();
}

mod flags;

#[derive(Clone, Debug)]
enum InterfaceSpec {
    Index(u16),
    Name(String),
    // Maybe Address sometime in future?
}

#[derive(Debug)]
enum WaitCondition {
    AnyDefaultRoute,
    Interface(InterfaceCondition, InterfaceSpec),
}

#[derive(Clone, Debug)]
enum InterfaceCondition {
    HasAddress,
    HasRoute,
}

fn to_ifspec(if_name: &str) -> InterfaceSpec {
    match get_ifindex(if_name) {
        Ok(v) => {
            log::info!("found index {v} for interface {if_name}");
            InterfaceSpec::Index(v as u16)
        }
        Err(e) => {
            log::warn!("Fetching index for {if_name} failed: {e}, tracking new connections");
            assert!(!if_name.is_empty());
            InterfaceSpec::Name(if_name.to_string())
        }
    }
}

fn real_main() -> Result<(), ReadError> {
    env_logger::init();

    let args = Args::parse();
    // NOTE: This should be kept as early as humanly possible so that we can
    // catch up on any events we missed (e.g., new interfaces, etc). Otherwise
    // we could miss an interface/route created between the time we queried
    // and the time we opened the socket.
    // let mut rs = RouteSocket::new().unwrap();
    let mut rs = RouteSocket::new(args.timeout).unwrap();

    // NOTE: mut so we can eventually change this to an Index when we find one
    // that we want
    let mut wait_cond = match args.wait_condition {
        WaitConditionFlag::DefaultRouteExists => WaitCondition::AnyDefaultRoute,
        WaitConditionFlag::InterfaceHasRoute(if_name) => {
            let spec = to_ifspec(&if_name);
            WaitCondition::Interface(InterfaceCondition::HasRoute, spec)
        }
        WaitConditionFlag::InterfaceHasAddress(if_name) => {
            let spec = to_ifspec(&if_name);
            WaitCondition::Interface(InterfaceCondition::HasAddress, spec)
        }
    };

    match wait_cond {
        WaitCondition::AnyDefaultRoute => rs.request_default_ipv4().unwrap(),
        WaitCondition::Interface(_, InterfaceSpec::Index(idx)) => {
            rs.request_interface_info(idx).unwrap()
        }
        WaitCondition::Interface(_, InterfaceSpec::Name(ref if_name)) => {
            log::info!("No interface index found for {if_name}")
        }
    }

    log::debug!("wait_cond: {:?}", wait_cond);

    loop {
        let packet = rs.recv()?;
        log::debug!("received: {}", packet.print_self());
        match &mut wait_cond {
            WaitCondition::AnyDefaultRoute => {
                // This was an event which notes that a default route is up.
                if is_ready_default_route(&packet) {
                    return Ok(());
                }
            }
            WaitCondition::Interface(ref mut cond, ref mut spec) => {
                // NOTE: We permit specifying by an interface name, but this is not
                // present in every event we receive. However, the interface index is. If
                // we are currently looking for an index name, we also do an additional
                // check to see if we've gotten a link event, and if it is a link event for
                // our interface, and use that to identify the interface instead.
                if let InterfaceSpec::Name(name) = &spec {
                    if let Some(idx) = index_for_name(&packet, name) {
                        *spec = InterfaceSpec::Index(idx);
                    }
                }

                match spec {
                    InterfaceSpec::Index(idx) => {
                        if is_given_interface_running(&packet, cond, idx) {
                            return Ok(());
                        }
                    }
                    // We've already `continue`d above if spec is a Name
                    InterfaceSpec::Name(_) => unreachable!(),
                }
            }
        };
    }
}

fn is_ready_default_route(h: &Header) -> bool {
    // We only care about routes being added
    let info = match h {
        Header::Route(ref i) => i,
        _ => return false,
    };

    // We only care about routes that are not being removed.
    if !matches!(
        info.operation,
        RouteMessageType::Add | RouteMessageType::Get | RouteMessageType::Change
    ) {
        return false;
    }

    if !(info.flags.is_up() && info.addrs.gateway.is_some()) {
        return false;
    }

    match &info.addrs.destination {
        Some(SockAddr::V4(addr)) => {
            if addr.ip().octets() != ZERO_IPV4.octets() {
                log::info!("found default IPV4 route");
                return false;
            }
        }
        Some(SockAddr::V6(addr)) => {
            if addr.ip().octets() != ZERO_IPV6.octets() {
                log::info!("found default IPV6 route");
                return false;
            }
        }
        _ => return false,
    };

    true
}

fn is_not_local_addr(addr: &SockAddr) -> bool {
    match addr {
        SockAddr::V4(a) => {
            let ip = *a.ip();
            let b = !(LOCAL_IPV4_RANGE.contains(ip) || LINK_LOCAL_IPV4_RANGE.contains(ip));
            log::trace!("{ip} not local? {b}");
            // the address is NOT localhost OR a self-assigned IP
            !(LOCAL_IPV4_RANGE.contains(ip) || LINK_LOCAL_IPV4_RANGE.contains(ip))
        }
        SockAddr::V6(a) => {
            let ip = *a.ip();
            let b = !(*LOCAL_IPV6_ADDR == ip || LINK_LOCAL_IPV6_RANGE.contains(ip));
            log::trace!("{ip} not local? {b}");
            !(*LOCAL_IPV6_ADDR == ip || LINK_LOCAL_IPV6_RANGE.contains(ip))
        }
        _ => false,
    }
}

fn index_for_name(h: &Header, if_name: &str) -> Option<u16> {
    match h.addrs().interface_link.as_ref() {
        Some(la) => match la.interface_name.as_str() {
            n if n == if_name => Some(la.index),
            _ => None,
        },
        _ => None,
    }
}

fn is_given_interface_running(h: &Header, condition: &InterfaceCondition, index: &u16) -> bool {
    let idx = h.index();
    if *index != idx as u16 {
        log::trace!("wrong index {index}");
        return false;
    }

    let is_alive = match h {
        Header::Link(link) => match link.operation {
            LinkMessageType::Info => link.flags.is_up() && link.flags.is_running(),
            _ => return false,
        },
        Header::Address(addr) => match addr.operation {
            AddressOperation::Add => addr.flags.is_up() && !addr.flags.is_dead(),
            _ => return false,
        },
        Header::Route(route) => match route.operation {
            RouteMessageType::Add | RouteMessageType::Get => match route.addrs.destination.as_ref()
            {
                Some(dest) => {
                    if is_not_local_addr(dest) {
                        route.flags.is_up()
                    } else {
                        return false;
                    }
                }
                None => false,
            },
            _ => return false,
        },
    };

    log::trace!("index {index} alive? {is_alive}");
    if !is_alive {
        // The interface (or route) is not up and alive
        return false;
    }

    let addrs = h.addrs();
    match &condition {
        InterfaceCondition::HasRoute => match &addrs.destination {
            Some(dest) => is_not_local_addr(dest),
            _ => false,
        },
        InterfaceCondition::HasAddress => match &addrs.interface_addr {
            Some(addr) => is_not_local_addr(addr),
            _ => false,
        },
    }
}

fn main() {
    let code = match real_main() {
        Ok(_) => 0,
        Err(ReadError::IO(e)) => {
            log::error!("error: {e}");
            1
        }
        Err(ReadError::Timeout) => {
            log::error!("timeout");
            2
        }
        Err(ReadError::ParsingAddress(e)) => {
            log::error!("error parsing address: {e}");
            3
        }
    };
    std::process::exit(code);
}
