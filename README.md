# rebind

DNS server for the discovery and testing of SSRF DNS rebinding vulnerabilities.

## SSRF via DNS Rebinding

Imagine web application code - such as the following - intended to prevent SSRF:

```python
from flask import request
import ipaddress
import requests
import socket
import urllib.parse

attributes = urllib.parse.urlparse(request.form['url'])
host, port = socket.getaddrinfo(attributes.hostname, attributes.port, family=socket.AF_INET, type=socket.SOCK_STREAM)[0][-1]
ip = ipaddress.IPv4Address(host)
if ip.is_global:
    requests.get(request.form['url'])
```

**Note that here there are 2 DNS lookups**:
1. DNS lookup to validate the URL
2. DNS lookup as part of the HTTP request

As a result, this type of SSRF prevention can potentially be exploited by a DNS server - such as this - which does the following:
1.  Returns a public A/AAAA record with a low TTL (this is used in the URL validation)
2.  Returns a private/reserved/loopback/link_local A/AAAA record (this is used in the actual HTTP request)

## Build
```bash
$ mkdir build
$ cd build
$ cmake ..
$ cmake --build .
```

## Installation
```bash
$ sudo make install
```

## Usage

### Options
* `-t`: DNS TTL (default `0`)
* `-c`: number of legitimate responses for each reserved response (default `1`)
* `-6` (`${HOST_IP}` is an IPv6 address)
* `-a`: public A record target (default `0.0.0.0`)
* `-A`: public AAAA record target (default `::`)

### Running
1. Create a CSV file of the form `qtype,subdomain,reservedIP`. An example of such a file is `example.csv`
2. Run the DNS server
```bash
$ rebind [-c ${VALID_RESPONSE_COUNT}] [-t ${TTL}] ${DOMAIN_NAME} ${FILENAME} ${HOST_IP}
```

### Reloading
Changes to the CSV file can be reloaded without restarting the server
```bash
$ kill -s SIGHUP ${PID}
```

## Example Usage

Server:
```bash
$ cat ./example.csv 
A,one,127.0.0.1
A,two,192.168.0.1
A,three,169.254.169.254
AAAA,four,::1
A,five,127.0.0.2
$ rebind example.com ./example.csv 34.232.67.223
```

Client:
```bash
$ dig +noall +answer one.example.com @127.0.0.1
one.example.com.	0	IN	A	0.0.0.0
$ dig +noall +answer one.example.com @127.0.0.1
one.example.com.	0	IN	A	127.0.0.1
```
