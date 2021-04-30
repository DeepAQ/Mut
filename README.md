# Mut <sup>[Multi-usage tunnel]</sup>, a DeepAQ Labs project

**WARNING: This project is for research purposes only. We take no responsibility for the use of the project. Usage in the real environment is not recommended. You may view the license part below.**

## License

Mut is licensed under the [AGPLv3](LICENSE) license.

## Usage

```
Usage of mut:
  -debug int
        localhost debug port
  -dns string
        dns config, protocol://host:port[/path...]
  -in string
        inbound config, protocol://[username:password@]host:port[/?option=value...]
  -out string
        outbound config, protocol://[username:password@]host:port[/?option=value...]
  -rules string
        router rules, rule1:action1[;rule2:action2...][;final:action]
  -stdin
        receive other arguments from stdin
```

## Configuration

### Inbound config

#### `forward` inbound

Forwards all TCP traffic to the given target destination.

Options:
- `target`: address of the target destination

#### `http` inbound

Receives standard HTTP/1.1 requests. HTTP basic authorization is supported. Both plain HTTP requests and CONNECT requests are supported.

#### `https` inbound

Receives HTTP requests over a TLS 1.2/1.3 connection. HTTP/2 is automatically enabled if the client supports it.

Options:
- `cert`: path to a base64-encoded certificate file
- `key`: path to a base64-encoded private key file

#### `socks` inbound

Receives SOCKS5 requests. Username and password authorization is supported. Currently, UDP bind requests are not supported.

#### `mix` inbound

Receives both HTTP and SOCKS5 requests. The underlying protocol is automatically determined by the first packet received from client. 

### Outbound config

#### `direct` outbound

Sends all outbound traffic directly.

#### `http` outbound

Sends all outbound traffic to a target that receives HTTP/1.1 CONNECT requests. HTTP basic authorization is supported.

#### `https` outbound

Sends all outbound traffic to a target that receives HTTP/1.1 CONNECT requests over a TLS 1.2/1.3 connection.

Options:
- `host`: (optional) overrides the SNI server hostname. If not specified, the outbound hostname will be used as server name.

#### `h2` outbound

Sends all outbound traffic to a target that receives HTTP/2 CONNECT requests over a TLS 1.2/1.3 connection.

Options:
- `host`: (optional) see above
- `concurrency`: (optional, default=8) specifies how many concurrent TCP connections (at least) to open.
- `alive`: (optional) specifies how long a TCP connection can keep. If not specified, there will be no limit to the TCP keepalive time.

#### `socks` outbound

Sends all outbound traffic to a target that receives SOCKS5 requests. Username and password authorization is supported.

### DNS config

By default, all DNS requests will be handled by OS. If a DNS server is specified, outbound traffic will use the specified server.

#### Supported DNS server types

- Plain UDP, example: `udp://1.1.1.1:53`
- DNS over HTTPS (DoH), example: `doh://1.1.1.1/dns-query`

#### Local DNS server and Fake IP

You can open a local DNS server by adding `local_listen=host:port` parameter to the DNS config URL. The local server supports plain UDP protocol.

If `fake_ip=1` parameter is specified, the local DNS server will always return fake IPs. The DNS resolve process will be done when the inbound receives a request with a fake IP address. This feature should only be used for integration with other platforms, for example, tun devices.

### Routing rules config

Mut includes a rule-based router for handling inbound requests. By default, all connections will be sent through the default outbound.

#### Rules format

Routing rules are joined by semicolon (`;`). Each rule is in a format of `condition,action`.

#### Conditions

- `domains:` condition: matches domain suffixes, following by a file containing domain suffixes, one in a line. Example: `domains:1.txt`
- `cidr:` condition: matches IPv4 CIDR address ranges, following by a file containing CIDRs, one in a line. Example: `cidr:1.txt`

#### Actions

- `default`: the connection will be sent through the default outbound.
- `direct`: the connection will be sent directly.
- `reject`: the connection will be rejected.

### Local debug config

Specifying `-debug <port>` argument will open a local HTTP server for debugging.

#### Debugging endpoints
- `/debug/pprof`: for Go pprof usage.
- `/debug/mut/dns`: shows the content of DNS cache and fake IP pool, if corresponding feature is enabled.
