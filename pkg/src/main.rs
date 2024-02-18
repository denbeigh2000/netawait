use libroute::header::Header;
use libroute::route::MessageType;
use libroute::socket::{ReadError, RouteSocket};

use clap::Parser;

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

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

fn real_main() -> Result<(), ReadError> {
    env_logger::init();

    let args = Args::parse();

    let mut rs = RouteSocket::new(args.timeout_secs).unwrap();
    rs.request_default_ipv4(args.interface.as_deref()).unwrap();
    loop {
        let packet = rs.recv()?;
        let info = match packet {
            Header::Route(i) => i,
            _ => {
                log::info!("ignoring message: {packet:?}");
                continue;
            }
        };
        match info.operation {
            MessageType::Add | MessageType::Get => (),
            _ => continue,
        }

        if let Some(ref intf) = args.interface {
            match info.interface_name {
                None => continue,
                Some(ref given_if) => {
                    if given_if != intf {
                        continue;
                    }
                }
            }
        }

        if !(info.flags.is_up() && info.flags.has_gateway()) {
            continue;
        }

        match info.destination {
            Some(SocketAddr::V4(addr)) => {
                if addr.ip().octets() == ZERO_IPV4.octets() {
                    log::info!("found default IPV4 route");
                    eprintln!("{}", info.print_self());
                    return Ok(());
                }

                continue;
            }
            Some(SocketAddr::V6(addr)) => {
                if addr.ip().octets() == ZERO_IPV6.octets() {
                    log::info!("found default IPV6 route");
                    eprintln!("{}", info.print_self());
                    return Ok(());
                }

                continue;
            }
            None => continue,
        };
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
