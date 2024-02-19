use libroute::addresses::SockAddr;
use libroute::header::Header;
use libroute::route::MessageType;
use libroute::socket::{get_ifindex, ReadError, RouteSocket};

use clap::Parser;

use std::net::{Ipv4Addr, Ipv6Addr};

lazy_static::lazy_static! { static ref ZERO_IPV4: Ipv4Addr = Ipv4Addr::from([0, 0, 0, 0]);
    static ref ZERO_IPV6: Ipv6Addr = Ipv6Addr::from([0, 0, 0, 0, 0, 0, 0, 0]);
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

#[derive(Debug)]
enum InterfaceSpec {
    Any,
    Index(u16),
    Name(String),
    // Maybe Address sometime in future?
}

fn real_main() -> Result<(), ReadError> {
    env_logger::init();

    let args = Args::parse();

    // NOTE: mut so we can eventually change this to an Index when we find one
    // that we want
    let mut interface = match args.interface {
        None => InterfaceSpec::Any,
        Some(ref if_name) => match get_ifindex(if_name) {
            Ok(res) => {
                log::info!("found index {res} for interface {if_name}");
                InterfaceSpec::Index(res as u16)
            }
            Err(e) => {
                log::warn!("Fetching index for {if_name} failed: {e}, tracking new connections");
                assert!(!if_name.is_empty());
                InterfaceSpec::Name(if_name.to_string())
            }
        },
    };

    eprintln!("interface: {:?}", interface);

    let mut rs = RouteSocket::new(args.timeout_secs).unwrap();
    match interface {
        InterfaceSpec::Any => rs.request_default_ipv4(None),
        InterfaceSpec::Index(idx) => rs.request_default_ipv4(Some(idx)),
        InterfaceSpec::Name(ref n) => {
            // NOTE: do nothing here - we've requested that we want to wait for
            // an interface the system doesn't know about, so there's no way we
            // can request a default route associated with it.
            log::info!("Not requesting route for unknown interface {n}");
            Ok(())
        }
    }
    .unwrap();
    loop {
        let packet = rs.recv()?;
        log::debug!("received: {}", packet.print_self());
        let info = match packet {
            // TODO: This needs to be changed so we also register new indexes
            // etc when appropriate
            Header::Route(ref i) => i,
            _ => {
                log::info!("ignoring message: {packet:?}");
                continue;
            }
        };
        match info.operation {
            MessageType::Add | MessageType::Get => (),
            _ => continue,
        }

        if !(info.flags.is_up() && info.addrs.gateway.is_some()) {
            continue;
        }

        match &info.addrs.destination {
            Some(SockAddr::V4(addr)) => {
                if addr.ip().octets() != ZERO_IPV4.octets() {
                    continue;
                }
                log::info!("found default IPV4 route");
            }
            Some(SockAddr::V6(addr)) => {
                if addr.ip().octets() != ZERO_IPV6.octets() {
                    continue;
                }
                log::info!("found default IPV6 route");
            }
            Some(SockAddr::Link(link)) => {
                if let InterfaceSpec::Name(ref n) = &interface {
                    if n.as_str() == link.interface_name.as_str() {
                        log::info!("saw interface {n} with index {}", link.index);
                        interface = InterfaceSpec::Index(link.index)
                    }
                }
                // TODO: Capture index => interface names here
                log::info!("discarding AF_LINK packet: {:?}", link);
                continue;
            }
            None => continue,
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

        return Ok(());
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
