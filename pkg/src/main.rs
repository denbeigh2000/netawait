use libroute::header::MessageType;
use libroute::socket::{ReadError, RouteSocket};

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

lazy_static::lazy_static! {
    static ref ZERO_IPV4: Ipv4Addr = Ipv4Addr::from([0, 0, 0, 0]);
    static ref ZERO_IPV6: Ipv6Addr = Ipv6Addr::from([0, 0, 0, 0, 0, 0, 0, 0]);
}

fn real_main() -> Result<(), ReadError> {
    env_logger::init();

    // let dur = Duration::from_secs(2);
    let mut rs = RouteSocket::new(None).unwrap();
    rs.request_default_ipv4().unwrap();
    loop {
        let info = rs.recv()?;
        match info.operation {
            MessageType::Add | MessageType::Get => (),
            _ => continue,
        }

        if !(info.flags.is_up() && info.flags.has_gateway()) {
            continue;
        }

        match info.destination {
            Some(SocketAddr::V4(addr)) => {
                if addr.ip().octets() == ZERO_IPV4.octets() {
                    log::info!("found default IPV4 route");
                    eprintln!("{}", info.print_self());
                    return 0;
                }

                continue;
            }
            Some(SocketAddr::V6(addr)) => {
                if addr.ip().octets() == ZERO_IPV6.octets() {
                    log::info!("found default IPV6 route");
                    eprintln!("{}", info.print_self());
                    return 0;
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
