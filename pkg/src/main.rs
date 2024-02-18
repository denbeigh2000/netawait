use libroute::socket::RouteSocket;

fn main() {
    env_logger::init();

    let mut rs = RouteSocket::default();
    rs.monitor();
}
