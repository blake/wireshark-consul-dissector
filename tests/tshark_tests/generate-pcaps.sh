#!/bin/sh
set -o errexit xtrace

# Copyright 2022 Blake Covarrubias
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Generate PCAPs from test data
#
# Usage: ./generate-pcaps.sh
#
# Formand of command
# $ text2pcap <flags> \
# <protocol; e.g. -T[cp]/-u[dp]> \
# <source port>,<destination port> \
# -n Output capture in pcapng format \
# <source file>\
# <destination file>

# '-4' Source and destination IPv4 addresses
CMD="text2pcap -4 192.0.2.100,192.0.2.200"
DATA_DIRECTORY="protocol_data/source"

# Generate PCAP for RPC gRPC protocol
$CMD -T 8600,8600 -n "${DATA_DIRECTORY}/dns.txt" test_dns-tcp.pcapng
$CMD -u 8600,8600 -n "${DATA_DIRECTORY}/dns.txt" test_dns-udp.pcapng

# Generate PCAP for RPC gRPC protocol
$CMD -T 8300,8300 -n "${DATA_DIRECTORY}/rpc_grpc.txt" test_rpc-grpc.pcapng

# Generate PCAP for RPC Raft protocol
$CMD -T 8300,8300 -n "${DATA_DIRECTORY}/rpc_raft.txt" test_rpc-raft.pcapng

# Generate PCAP for RPC Snapshot protocol
$CMD -T 8300,8300 -n "${DATA_DIRECTORY}/rpc_snapshot.txt" test_rpc-snapshot.pcapng

# Generate PCAP for RPC TLS protocol
$CMD -T 8300,8300 -n "${DATA_DIRECTORY}/rpc_tls.txt" test_rpc-tls.pcapng

# Generate PCAP for RPC TLS Insecure protocol
$CMD -T 8300,8300 -n "${DATA_DIRECTORY}/rpc_tls_insecure.txt" test_rpc-tls-insecure.pcapng

# Generate PCAP for Serf protocol
$CMD -T 8301,8301 -n "${DATA_DIRECTORY}/serf.txt" test_serf-tcp.pcapng
$CMD -u 8301,8301 -n "${DATA_DIRECTORY}/serf.txt" test_serf-udp.pcapng

# Generate PCAP for Yamux protocol
$CMD -T 8300,8300 -n "${DATA_DIRECTORY}/yamux.txt" test_yamux.pcapng
