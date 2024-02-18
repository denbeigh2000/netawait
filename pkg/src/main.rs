use libroute::socket::RouteSocket;

fn main() {
    env_logger::init();

    let mut rs = RouteSocket::default();
    rs.request_default_ipv4().unwrap();
    rs.monitor();
}
