# netawait

## What?

`netawait` is a small tool for macOS that waits for some configurable network
condition.

## Why?

The [`launchd` documentation][launchd-docs] says:
> If your daemon depends on the network being available, this cannot be handled with dependencies because network interfaces can come and go at any time in OS X. To solve this problem, you should use the network reachability functionality or the dynamic store functionality in the System Configuration framework.

This is inconvenient, and not always within our control, so many resort to
writing small scripts like this:
```bash
while ! ping 8.8.8.8
do
    sleep 1
done
```

This tool aims to solve this problem by providing a small, fast, unix-y tool
that waits for the network to be available.

```
$ du -sh ./target/release/netawait
1.2M	./target/release/netawait

$ time ./target/release/netawait
./target/release/netawait  0.00s user 0.00s system 58% cpu 0.010 total
```

## Usage

### `-w/--wait-condition`

Specify when the program will exit.

- `default-route`: Wait for any interface to have a default route available<br />
  (this is the default, and what most people would want)
- `if-gets-address=IF_NAME`: Wait for a specific interface to get an address.
- `if-gets-route=IF_ROUTE`: Wait for a specific interface to get assigned a route.

Addresses and route ranges wholly contained within link-local and loopback ranges
(as defined by [RFC 3927][rfc-3927] and [RFC 4291][rfc-4291]) are always excluded
from these checks, because they're often assigned before the interface is
able to do anything materially usable.

### `-t/--timeout`
Specify a timeout in seconds to wait for the wait condition. If a timeout is
reached, the program will exit with status code 2.

### `--help`
Displays help text
```
Waits for a network condition to be met

Usage: netawait [OPTIONS]

Options:
  -w, --wait-condition <WAIT_CONDITION>
          Specifes the exit condition:
          - A global default route is available (default-route)
          - A specific interface receives a non-link-local address (if-gets-address=<eth0>)
          - A specific interface receives a non-local route (if-gets-route=<eth0>) [env: NETAWAIT_WAIT_CONDITION=] [default: default-route]
  -t, --timeout <TIMEOUT>
          If specified, will only wait this long for our condition to be met [env: NETAWAIT_TIMEOUT=]
  -l, --log-level <LOG_LEVEL>
          Log level to display output at [env: NETAWAIT_LOG_LEVEL=] [default: warn]
  -h, --help
          Print help
```
[launchd-docs]: https://developer.apple.com/library/archive/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html "launchd developer documentation"
[rfc-3927]: https://datatracker.ietf.org/doc/html/rfc3927 "IETF RFC 3927"
[rfc-4291]: https://datatracker.ietf.org/doc/html/rfc4291 "IETF RFC 4291"

## Compilation

With standard rust tooling:
```
cd pkg/
cargo build --release
```

With Nix (flakes):
```
nix build
```

