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

local proto_snapshot = Proto("RPCSnapshot", "RPCSnapshot Protocol")

--- Initialization function for this protocol
--- Adds this protocol to the 'consul.protocol' dissector table
-- @function proto_snapshot.init
function proto_snapshot.init()
    local consul_proto_dissector_table = DissectorTable.get("consul.protocol")

    -- RPC type
    local rpc_type = "0x05"

    if consul_proto_dissector_table then
        consul_proto_dissector_table:add(rpc_type, proto_snapshot)
    end
end

--- Dissector for the RPCSnapshot protocol
-- Parses a Tvb to determine if it is a RPCSnapshot type
-- @function proto_snapshot.dissector
--
-- @tparam Tvb tvb A Testy Virtual(-izable) Buffer
-- @tparam Pinfo pinfo An object containing packet information
-- @tparam TreeItem tree An object representing the root of the packet tree
-- @treturn number The number of bytes processed by this dissector
function proto_snapshot.dissector(tvb, pinfo, _)
    local buffer_len = tvb:captured_len()

    -- Set the protocol column to the protocol name and then return
    pinfo.columns.protocol:set(proto_snapshot.name)
    pinfo.columns.protocol:fence()

    return buffer_len
end
