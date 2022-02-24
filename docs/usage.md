# Usage instructions

A Wireshark dissector for HashiCorp [Consul](https://www.consul.io/), written in
Lua. This dissector is capable of decoding Consul's RPC and Gossip communication.

This plugin attaches several protocol dissectors to various TCP and UDP ports,
several of which are built-in to Wireshark. No additional action is required to
enable dissection of traffic received on the following ports.

| Port | Protocol(s) | Dissector | Description |
| ---- | ----------- | --------- | ----------- |
| 8300 | TCP | [Consul] | RPC |
| 8301 | TCP and UDP | [Serf] | LAN Gossip |
| 8302 | TCP and UDP | [Serf] | WAN Gossip |
| 8500 | TCP | HTTP-over-TCP | HTTP API |
| 8501 | TCP | HTTP-over-TLS | HTTPS API |
| 8502 | TCP | gRPC | xDS server
| 8600 | TCP and UDP | DNS | DNS server

## Modifying protocol ports

In some environments, Consul may be configured to use ports other than the
aforementioned values. In these scenarios, it is desirable to reconfigure the
dissectors so that they correctly decode traffic on the non-standard port.

The port values can be modified by changing the the protocol's preferences under
Wireshark's preference pane (Preferences > Protocols > \<protocol\>). The
following screenshot displays the protocol preference pane for the `consul`
protocol dissector.

![Screenshot of the Consul protocol's preference pane in Wireshark](/img/Consul-proto-preferences.png "Screenshot of the Consul protocol's preference pane in Wireshark.")

Once modified, the dissector(s) will only use the specified ports for decoding
associated protocol traffic.

Alternatively, it may be desirable to have Wireshark decode a specific stream as
a particular protocol type without modifying the default port configuration.
This can be achieved by using Wireshark's *Decode as* functionality
(Analyze > Decode As...). Refer to the [User Specified Decodes] section of the
Wireshark manual for more information on using this feature.

<!-- Reference style links -->
[Consul]: ../src/consul/consul.lua
[Serf]: ../src/serf/serf.lua
[User Specified Decodes]: https://www.wireshark.org/docs/wsug_html_chunked/ChCustProtocolDissectionSection.html
