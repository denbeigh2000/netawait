use libroute::addresses::{AddressOperation, SockAddr};
use libroute::header::Header;
use libroute::link::MessageType as LinkMessageType;
use libroute::route::MessageType as RouteMessageType;
use libroute::socket::{get_ifindex, ReadError, RouteSocket};

use clap::Parser;
use ipnetwork::{Ipv4Network, Ipv6Network};

use std::net::{Ipv4Addr, Ipv6Addr};

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

#[derive(Parser)]
struct Args {
    /// If specified, waits for a default route to be up on this interface
    #[arg(short, long)]
    interface: Option<String>,
    /// If specified, wait this many seconds before a default network is
    /// available
    #[arg(short, long)]
    timeout_secs: Option<i64>,
}

#[derive(Clone, Debug)]
enum InterfaceSpec {
    Index(u16),
    Name(String),
    // Maybe Address sometime in future?
}

#[derive(Debug)]
enum WaitCondition {
    AnyDefaultRoute,
    Interface(InterfaceSpec),
}

fn real_main() -> Result<(), ReadError> {
    env_logger::init();

    let args = Args::parse();
    // NOTE: This should be kept as early as humanly possible so that we can
    // catch up on any events we missed (e.g., new interfaces, etc). Otherwise
    // we could miss an interface/route created between the time we queried
    // and the time we opened the socket.
    let mut rs = RouteSocket::new(args.timeout_secs).unwrap();

    // NOTE: mut so we can eventually change this to an Index when we find one
    // that we want
    let mut wait_cond = match args.interface {
        None => {
            rs.request_default_ipv4().unwrap();
            WaitCondition::AnyDefaultRoute
        }
        Some(ref if_name) => WaitCondition::Interface({
            match get_ifindex(if_name) {
                Ok(v) => {
                    log::info!("found index {v} for interface {if_name}");
                    rs.request_interface_info(v as u16).unwrap();
                    InterfaceSpec::Index(v as u16)
                }
                Err(e) => {
                    log::warn!(
                        "Fetching index for {if_name} failed: {e}, tracking new connections"
                    );
                    assert!(!if_name.is_empty());
                    InterfaceSpec::Name(if_name.to_string())
                }
            }
        }),
    };

    log::debug!("wait_cond: {:?}", wait_cond);

    loop {
        let packet = rs.recv()?;
        log::debug!("received: {}", packet.print_self());
        match &wait_cond {
            WaitCondition::AnyDefaultRoute => {
                // This was an event which notes that a default route is up.
                if is_ready_default_route(&packet) {
                    return Ok(());
                }
            }
            WaitCondition::Interface(if_spec) => {
                match is_given_interface_running(&packet, if_spec) {
                    // Our interface is running
                    (true, _) => return Ok(()),
                    // Our interface isn't running, but we found an index for
                    // it to use later.
                    (false, Some(idx)) => {
                        // NOTE: rust thinks this is unused?
                        wait_cond = WaitCondition::Interface(InterfaceSpec::Index(idx));
                        continue;
                    }
                    // Neither.
                    _ => continue,
                }
            }
        };

        // match interface {
        //     InterfaceSpec::Any => {
        //         log::info!("finishing, we haven't specified an interface");
        //     }
        //     InterfaceSpec::Index(ref idx) => {
        //         // NOTE: this will give us the interface associated with the
        //         // routing table, but that's not really want we want here.
        //         // we want to wait for either:
        //         // - any interface to become available (a default route is created)
        //         // - an interface to come up (marked with IFF_RUNNING)
        //         // let new_idx = match packet.index() {
        //         //     0 => info
        //         //         .addrs
        //         //         .interface_link
        //         //         .as_ref()
        //         //         .map(|l| l.index as u32)
        //         //         .unwrap_or(0),
        //         //     i => i,
        //         // };

        //         if new_idx == 0 {
        //             log::warn!("skipping index 0 case for now (this is purely a routing table update, and needs a second lookup?)");
        //         } else if *idx as u32 != new_idx {
        //             log::info!("skipping: saw {new_idx}, waiting for {idx}");
        //             continue;
        //         } else {
        //             log::info!("finishing, we've seen index {idx}");
        //         }
        //     }
        //     InterfaceSpec::Name(ref name_str) => {
        //         // Because we've been watching for new interfaces matching
        //         // this name, we know this route doesn't match the interface
        //         // we're waiting for.
        //         log::info!("Skipping, still haven't seen if {name_str}");
        //         continue;
        //     }
        // }
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
        SockAddr::Link(_) => false,
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
    }
}

fn is_given_interface_running(h: &Header, given_spec: &InterfaceSpec) -> (bool, Option<u16>) {
    // NOTE: We permit specifying by an interface name, but this is not
    // present in every event we receive. However, the interface index is. If
    // we are currently looking for an index name, we also do an additional
    // check to see if we've gotten a link event, and if it is a link event for
    // our interface, and use that to identify the interface instead.
    let updated_index = match given_spec {
        InterfaceSpec::Index(_) => None,
        InterfaceSpec::Name(n) => match &h.addrs().interface_link {
            Some(SockAddr::Link(l)) => {
                if l.interface_name.as_str() == n {
                    Some(l.index)
                } else {
                    None
                }
            }
            _ => None,
        },
    };

    // If we've found a more accurate representation of our interface earlier
    // this run, be sure to use it for this check instead of the name.
    let spec = match updated_index {
        Some(idx) => InterfaceSpec::Index(idx),
        // TODO: feels silly to clone for this?
        None => given_spec.clone(),
    };

    let (index, is_alive) = match h {
        Header::Link(link) => match link.operation {
            LinkMessageType::Info => (link.index, (link.flags.is_up() && link.flags.is_running())),
            _ => return (false, updated_index),
        },
        Header::Address(addr) => match addr.operation {
            AddressOperation::Add => (addr.index, addr.flags.is_up() && !addr.flags.is_dead()),
            _ => return (false, updated_index),
        },
        Header::Route(route) => match route.operation {
            RouteMessageType::Add | RouteMessageType::Get => match route.addrs.destination.as_ref()
            {
                Some(dest) => {
                    if is_not_local_addr(dest) {
                        (route.index, route.flags.is_up())
                    } else {
                        return (false, updated_index);
                    }
                }
                None => return (false, updated_index),
            },
            _ => return (false, updated_index),
        },
    };

    log::trace!("index {index} alive? {is_alive}");

    // TODO: This whole logic is kinda kludgy. It goes and checks whether we
    // have a route that is default, and if that's not true, checks to see
    // whether it has a non-local + non-self-assigned IP address, and returns
    // true.
    // The logic should probably be defined such that we have one clearly
    // defined check, or subcommands for different checks
    match spec {
        InterfaceSpec::Index(idx) => {
            if index != idx as u32 {
                log::trace!("wrong index {index}");
                return (false, updated_index);
            }

            // The interface is up and alive
            if is_alive {
                let addrs = h.addrs();
                // TODO: cleanu
                match addrs.destination {
                    Some(SockAddr::V4(addr)) => {
                        if *addr.ip() == *ZERO_IPV4 {
                            log::info!("found default IPV4 route");
                            return (true, updated_index);
                        }
                    }
                    Some(SockAddr::V6(addr)) => {
                        if *addr.ip() == *ZERO_IPV6 {
                            log::info!("found default IPV6 route");
                            return (true, updated_index);
                        }
                    }
                    _ => (),
                };

                return (
                    // TODO: Should we make a separate check for if the
                    // interface has a known good ip?
                    h.addrs()
                        .interface_addr
                        .as_ref()
                        .map(is_not_local_addr)
                        .unwrap_or(false),
                    updated_index,
                );
            }
        }
        InterfaceSpec::Name(_) => {
            // NOTE: i don't think it's possible to get here?
            // TODO: confirm
            return (false, updated_index);
        }
    }

    log::trace!("default case");

    (false, updated_index)
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
