# Overview

This directory contains a rudimentary test suite that allows for validating
changes to the dissector do not break protocol dissection.

## Requirements

* [Lua 5.2](https://www.lua.org) or newer
* [LuaUnit]
* [tshark](https://www.wireshark.org/docs/wsug_html_chunked/AppToolstshark.html)
* [text2pcap](https://www.wireshark.org/docs/wsug_html_chunked/AppToolstext2pcap.html)

## Installing dependencies

In order to run the unit tests located in this directory, you must first install
[LuaUnit]. The easiest way to do this is using [LuaRocks](https://luarocks.org).

```shell-session
$ luarocks install luaunit
Warning: falling back to wget - install luasec to get native HTTPS support
Installing https://luarocks.org/luaunit-3.4-1.rockspec

luaunit 3.4-1 depends on lua >= 5.1 (5.4-1 provided by VM)
luaunit 3.4-1 depends on lua < 5.5 (5.4-1 provided by VM)
luaunit 3.4-1 is now installed in /opt/homebrew (license: BSD)
```

Wireshark and its associated CLI tools are also required to run the protocol
decoding tests. Installation steps will vary depending on your operating system.
On macOS, the easiest way to install Wireshark is using Homebrew.

```shell-session
brew install --cask wireshark
```

## Running tests

There are two test suites available.

* `test_decode.lua` - Validates dissected PCAPs matches expected data.
* `test_utils.lua` - Tests the utility functions that are shared by multiple
  dissectors.

### Protocol dissection tests

The protocol dissection tests help validate that test data matches the expected
output when decoded. The protocol tests are ran by executing the
`test_decode.lua` file. For example:

```shell-session
$ lua test_decode.lua
Duplicate dissectors http-over-tls and http-over-tcp for protocol HTTP in dissector table tcp.port
Duplicate dissectors http-over-tls and http-over-tcp for protocol HTTP in dissector table tcp.port
.Duplicate dissectors http-over-tls and http-over-tcp for protocol HTTP in dissector table tcp.port
.Duplicate dissectors http-over-tls and http-over-tcp for protocol HTTP in dissector table tcp.port
.Duplicate dissectors http-over-tls and http-over-tcp for protocol HTTP in dissector table tcp.port
.Duplicate dissectors http-over-tls and http-over-tcp for protocol HTTP in dissector table tcp.port
.Duplicate dissectors http-over-tls and http-over-tcp for protocol HTTP in dissector table tcp.port
.
Ran 6 tests in 0.006 seconds, 6 successes, 0 failures
OK
```

The decoded packet payloads are compared against known good output located under
the `tests/tshark_tests/protocol_data/expected/` directory.

In order to update these files after making improvements and/or fixes to the
dissection plugins, run the `test_decode.lua` program with the
`GENERATE_PROTOCOL_DATA` environment variable equal to `1`.

```shell-session
GENERATE_PROTOCOL_DATA=1 lua test_decode.lua
```

### Example output from utilities unit tests

```shell-session
lua test_utils.lua
..
Ran 2 tests in 0.000 seconds, 2 successes, 0 failures
OK
```

## Generating sample PCAPs

The `tests/tshark_tests` script also contains a shell script that will generate
PCAP files from the test data, allowing the sample captures to be evaluated by
a user.

```shell-session
$ cd tests/tshark_tests
$ ./generate-pcaps.sh
Input from: protocol_data/source/dns.txt
Output to: test_dns-tcp.pcapng
Output format: pcapng
Generate dummy Ethernet header: Protocol: 0x800
Generate dummy IP header: Protocol: 6
Generate dummy TCP header: Source port: 8600. Dest port: 8600
Wrote packet of 114 bytes.
Wrote packet of 114 bytes.
Wrote packet of 118 bytes.
Read 3 potential packets, wrote 3 packets (628 bytes).
...
<omitted for brevity>
```

The resultant generated PCAPs are saved in the current directory with the file
extension of `.pcapng`.

```shell-session
$ tree -P '*.pcapng' -L 1
.
├── protocol_data
├── test_dns-tcp.pcapng
├── test_dns-udp.pcapng
├── test_rpc-grpc.pcapng
├── test_rpc-raft.pcapng
├── test_rpc-snapshot.pcapng
├── test_rpc-tls-insecure.pcapng
├── test_rpc-tls.pcapng
├── test_serf-tcp.pcapng
├── test_serf-udp.pcapng
└── test_yamux.pcapng

1 directory, 10 files
```

<!-- Reference style links -->
[LuaUnit]: https://github.com/bluebird75/luaunit/
