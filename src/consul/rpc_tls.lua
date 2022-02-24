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

local proto_tls = Proto("RPCTLS", "RPCTLS Protocol")

--- Initialization function for this protocol
--  Adds this protocol to the 'consul.protocol' dissector table
-- @function proto_tls.init
function proto_tls.init()
    local consul_proto_dissector_table = DissectorTable.get("consul.protocol")

    -- RPC type
    local rpc_type = "0x03"

    if consul_proto_dissector_table then
        consul_proto_dissector_table:add(rpc_type, proto_tls)
    end
end

--- Dissector for the RPCTLS protocol
-- Parses a Tvb to determine if it is a RPCTLS type
-- @function proto_tls.dissector
--
-- @tparam Tvb tvb A Testy Virtual(-izable) Buffer
-- @tparam Pinfo pinfo An object containing packet information
-- @tparam TreeItem tree An object representing the root of the packet tree
-- @treturn number The number of bytes processed by this dissector
function proto_tls.dissector(tvb, pinfo, tree)
    local buffer_len = tvb:captured_len()

    if buffer_len == 0 then
        return
    end

    -- Associate the protocol with the stream for future packets if it has not
    -- already been done
    if pinfo.private.existing_dissector == nil then
        pinfo.conversation = proto_tls
    end

    if buffer_len == 1 then
        pinfo.columns.protocol:set(proto_tls.name)
        return buffer_len
    else
        pinfo.columns.protocol:set("RPC")
    end

    pinfo.columns.protocol:fence()

    local tls_dissector = Dissector.get("tls")
    if tls_dissector == nil then
        return 0
    end

    -- This is a TLS packet. Hand off to that dissector.
    return tls_dissector:call(tvb, pinfo, tree)
end
