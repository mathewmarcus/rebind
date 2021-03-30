# rebind

DNS server for the discovery and testing of SSRF DNS rebinding vulnerabilities. 

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
* `-r`: number of legitimate responses for each reserved response (default `1`)

### Running
1. Create a CSV file of the form `subdomain,reservedIP`. An example of such a file is `example.csv`
2. Run the DNS server
```bash
$ rebind [-r ${RESPONSE_RATIO}] [-t ${TTL}] ${DOMAIN_NAME} ${FILENAME} ${HOST_IP}
```