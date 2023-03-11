# wireshark-consul-dissector

A Wireshark dissector for HashiCorp [Consul](https://www.consul.io/) and HashiCorp [Yamux](https://github.com/hashicorp/yamux/blob/master/spec.md), written in
Lua. This dissector is capable of decoding Consul's RPC and Gossip communication.

## Screenshot

![Screenshot of Consul decoded traffic in Wireshark](/img/Consul-Wireshark.png "Screenshot of Wireshark displaying decoded Consul traffic.")

## Requirements

- Wireshark 3.5 or higher with Lua enabled

## Installation

Download this repository, and copy the folders under `src/` to the Wireshark
plugin directory. The location varies depending on your operating system.

- **Unix**: `$HOME/.local/lib/wireshark/plugins/`
- **Windows**: `%PROGRAMFILES%\Wireshark\plugins\`

For example:

```shell-session
git clone https://github.com/blake/wireshark-consul-dissector.git
cd wireshark-consul-dissector
export WIRESHARK_PLUGIN_DIR="${HOME}/.local/lib/wireshark/plugins/"
mkdir -p $WIRESHARK_PLUGIN_DIR
cp -R src/* "${WIRESHARK_PLUGIN_DIR}"
```

## Displayed Information

The Consul dissector supports identifying and/or decoding the following
RPC protocols and message types.

### RPC types

| RPC type | Byte identifier | Can identify | Can decode |
| ---------| --------------- | --------- | -------- |
| Consul | `0x00` | No | N/A |
| Raft | `0x01` | Yes | Yes
| Multiplex (Muxado) | `0x02` | No | N/A |
| TLS | `0x03` | Yes | No |
| MultiplexV2 (Yamux) | `0x04` | Yes | Yes |
| Snapshot | `0x05` | Yes | No |
| Gossip | `0x06` | Yes | Partially (Only headers of type 'packet')
| TLS Insecure | `0x07` | Yes | No |
| gRPC | `0x08` | Yes | Yes |

### Serf messages

| Message type | Byte identifier | Supported |
| ------------ | --------------- | --------- |
| Ping | `0x00` | Yes |
| IndirectPing | `0x01` | Partially |
| ACK Response | `0x02` | Yes |
| Suspect | `0x03` | Yes |
| Alive | `0x04` | Yes |
| Dead | `0x05` | Yes |
| Push/pull | `0x06` | Unknown |
| Compound | `0x07` | Yes |
| User | `0x08` | Yes |
| Compress | `0x09` | Partially (no decompression)  |
| Encrypt | `0x0a` | Partially (no decryption) |
| NACK Response | `0x0b` | Yes |
| Has CRC | `0x0c` | Yes |
| Error | `0x0d` | Unknown |

## Display filters

Wireshark display filters can be used to filter packets from the packet list
pane.

Each protocol dissector supported by this plugin will decode its packet
payload into one or more packet fields. These fields can be referenced in the
display filter, along with the filter fields supported by the lower layer
protocols.

If a field name is specified with no match criteria (e.g., `yamux.version`), all
packets containing that field will be displayed.

The following table contains the list of supported fields for each protocol
dissector.

| Name | Description | Example |
| ---- | ----------- | ------- |
| rpcgossip.addr.ip | The IP address that the packet was received on. | `rpcgossip.addr.ip == 192.0.2.10` |
| rpcgossip.addr.port | The port the RPC Gossip packet was received on. | `rpcgossip.addr.port == 8300` |
| rpcgossip.addr.zone | The IPv6 scoped addressing zone. | |
| rpcgossip.tag | The tuple identifying the datacenters with which to associate the RPC Gossip header | `rpcgossip.tag == "dc-tuple:dc1:dc3"` |
| rpcgossip.type | The RPC Gossip header type. | `rpcgossip.type == Packet` |
| rpcraft.type | The RPC Raft message type. | `rpcraft.type == "Append Entries"` |
| serf.label.length | The length of the Serf label | `serf.label.length >= 3` |
| serf.label.name | The value of the Serf label | `serf.label.name == 'foo'` |
| serf.label.type | The Serf label type. Only value of 244 is supported. | `serf.label.type == 244` |
| serf.message.checksum | The checksum value for a Serf HasCRC message | `serf.message.type == HasCRC` |
| serf.message.compound_length | The number of messages in a Serf Compound message | `serf.message.compound_length == 22` |
| serf.message.encryption_length | The length of the encrypted payload in the Serf Encrypt message | `serf.message.encrypted_length >= 50` |
| serf.message.encryption_nonce | The value of the encryption nonce for a Serf Encrypt message | `serf.message.encryption_nonce == 9a8dedabdea9ed61064601c8` |
| serf.message.encryption_version | The encryption algorithm used for a Serf Encrypt payload | `serf.message.encryption_version == 1` |
| serf.message.remaining_payload | The unparsed, encrypted payload of the Serf Encrypt message | `serf.message.remaining_payload` |
| serf.message.type | The Serf message type | `serf.message.type == HasCRC` |
| yamux.error_code | The Yamux GoAway error code field value | `yamux.error_code == NormalTermination` |
| yamux.flags | The flags associated with the Yamux frame | `yamux.flags == SYN` |
| yamux.length | The Yamux length field value | `yamux.length == 999` |
| yamux.next_frame | The ID of the next Yamux frame in this stream | `yamux.next_frame == 1132` |
| yamux.payload_length | The length of the payload following the Yamux Data frame | `yamux.payload_length == 1000` |
| yamux.ping_payload | The Yamux Ping frame payload | `yamux.ping_payload == 0xFEEDCAFE` |
| yamux.previous_frame | The ID of the previous Yamux frame in this stream | `yamux.previous_frame == 879` |
| yamux.recv_window_delta | The Yamux Window Update message payload: the receive window size increasing for current Yamux Stream | `yamux.recv_window_delta == 1024` |
| yamux.stream_id | The ID of a Yamux stream | `yamux.stream_id == 3` |
| yamux.type | The Yamux packet type | `yamux.type == WindowUpdate` |
| yamux.version | The Yamux protocol version (currently always zero) | `yamux.version == 0` |
| yamux.window_size.client.after | The Yamux client window size after message sending | `yamux.window_size.client.after < 1000` |
| yamux.window_size.client.before | The Yamux client window size before message sending | `yamux.window_size.client.before >= 2000` |
| yamux.window_size.server.after | The Yamux server window size after message sending | `yamux.window_size.server.after < 3000` |
| yamux.window_size.server.before | The Yamux server window size before message sending | `yamux.window_size.server.before >= 4000` |
