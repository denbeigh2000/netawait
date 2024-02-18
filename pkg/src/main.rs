use libroute::socket::RouteSocket;

fn main() {
    let mut rs = RouteSocket::default();
    rs.monitor();
}
