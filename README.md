## About

Get SSL certificate from ZeroSSL for an IP address.

## Usage

### Help

```
go run main.go
```

```
Currently get a SSL Certificate from ZeroSSL

Usage:
  ip-cert [command]

Available Commands:
  check       Check SSL Certificate
  completion  Generate the autocompletion script for the specified shell
  help        Help about any command
  issue       Issue Certificate for an IP Address

Flags:
  -h, --help   help for ip-cert
```

### issue ssl certificate

```
sudo go run main.go issue --ip x.x.x.x --key xxxx --dir ~/.ip-certs/
```

Note:

- get `key/access key` from [ZeroSSL]<https://app.zerossl.com/developer>
- might need to start the program with `sudo` because the issue certificate needs to listen on port `80` in order for zerossl to verify
- you can also change kernel config
  + [Exposing privileged ports](https://docs.docker.com/engine/security/rootless/#exposing-privileged-ports)
  + ref: [ip_unprivileged_port_start](https://sysctl-explorer.net/net/ipv4/ip_unprivileged_port_start/)

### check ssl certificate information

check ssl certificate from local filesystem

```
go run main.go check --cert /tmp/ip-certs/x.x.x.x/certificate.crt --priv /tmp/ip-certs/x.x.x.x/private.key
```
check ssl certificate for a website uri

```
go run main.go check --url https://github.com
```
