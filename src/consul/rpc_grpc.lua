-- Copyright 2022 Blake Covarrubias
--
-- Licensed under the Apache License, Version 2.0 (the "License");
-- you may not use this file except in compliance with the License.
-- You may obtain a copy of the License at
--
--     http://www.apache.org/licenses/LICENSE-2.0
--
-- Unless required by applicable law or agreed to in writing, software
-- distributed under the License is distributed on an "AS IS" BASIS,
-- WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-- See the License for the specific language governing permissions and
-- limitations under the License.

-- Import utility functions
-- Ensure that this plugin's utilities are loaded first.
package.prepend_path("plugins/consul")
local util = require("util")

-- RPC type
local rpc_type = "0x08"

local proto_grpc = Proto("RPCGRPC", "gRPC")

--- Initialization function for this protocol
--  Adds this protocol to the 'consul.protocol' dissector table
-- @function proto_grpc.init
function proto_grpc.init()
    -- This shouldn't be necessary, but return if the RPC type isn't set
    if not rpc_type then
        return
    end

    -- Register this protocol pattern with our parent dissector
    util.register_protocol_pattern(rpc_type)

    -- Register this protocol pattern with the consul.protocol table in Wireshark
    local consul_proto_dissector_table = DissectorTable.get("consul.protocol")
    if consul_proto_dissector_table then
        consul_proto_dissector_table:add(rpc_type, proto_grpc)
    end
end

--- Dissector for the RPCGRPC protocol
-- Parses a Tvb to determine if it is a RPCGRPC type
-- @function proto_tls_insecure.dissector
--
-- @tparam Tvb tvb A Testy Virtual(-izable) Buffer
-- @tparam Pinfo pinfo An object containing packet information
-- @tparam TreeItem tree An object representing the root of the packet tree
-- @treturn number The number of bytes processed by this dissector
function proto_grpc.dissector(tvb, pinfo, tree)
    local buffer_length = tvb:captured_len()

    -- Skip processing of packets that are empty
    if buffer_length == 0 then
        return 0
    end

    if buffer_length == 1 and util.number_to_hex(tvb():uint()) == rpc_type then
        -- Associate the protocol with the stream for future packets if it has not
        -- already been done
        if pinfo.private.existing_dissector == nil then
            pinfo.conversation = proto_grpc
        end

        pinfo.columns.protocol:set(proto_grpc.name)
        pinfo.columns.protocol:fence()

        return buffer_length
    end

    local http2_dissector = Dissector.get("http2")
    if http2_dissector == nil then
        return 0
    end

    -- This is a data packet that is msgpack encoded
    return http2_dissector:call(tvb, pinfo, tree)
end
