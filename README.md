# wireshark-consul-dissector

A Wireshark dissector for HashiCorp [Consul](https://www.consul.io/), written in
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

| RPC type | Byte identifier | Identify | Decode |
| ---------| --------------- | --------- | -------- |
| Consul | `0x00` | No | N/A |
| Raft | `0x01` | Yes | Yes
| Multiplex (Muxado) | `0x02` | No | N/A |
| TLS | `0x03` | Yes | No |
| MultiplexV2 (Yamux) | `0x04` | Yes | Yes |
| Snapshot | `0x05` | Identify | No |
| Gossip | `0x06` | Yes | Partial (Only packet header type)
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
| User | `0x08` | Partial (No user message parsing) |
| Compress | `0x09` | Partial (no decompression)  |
| Encrypt | `0x0a` | Partial (no decryption) |
| NACK Response | `0x0b` | Yes |
| Has CRC | `0x0c` | Yes |
| Error | `0x0d` | Unknown |

## Filters

It is possible to use Wireshark filters with fields provided by the various
protocols dissectors. There are many fields that can be used to filter on. When
a value following the field is absent all TCP packets with the field will be
shown.  The following is a selection of useful fields.

| Filter field | Detail | Example |
| ------------ | ------ | ------- |
| serf.message.type | Filter by the Serf message type | `serf.message.type == HasCRC` |
| yamux.stream_id | Find packets matching the Yamux stream ID | `yamux.stream_id == 3` |
| yamux.type | Find packets matching the Yamux packet type | `yamux.type == WindowUpdate` |
