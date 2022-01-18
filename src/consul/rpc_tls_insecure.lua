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

local proto_tls_insecure = Proto("RPCTLSInsecure", "RPCTLSInsecure Protocol")

--- Initialization function for this protocol
--  Adds this protocol to the 'consul.protocol' dissector table
-- @function proto_tls_insecure.init
function proto_tls_insecure.init()
    local consul_proto_dissector_table = DissectorTable.get("consul.protocol")

    -- RPC type
    local rpc_type = "0x07"

    if consul_proto_dissector_table then
        consul_proto_dissector_table:add(rpc_type, proto_tls_insecure)
    end
end

--- Dissector for the RPCTLSInsecure protocol
-- Parses a Tvb to determine if it is a RPC TLS Insecure type
-- @function proto_tls_insecure.dissector
--
-- @tparam Tvb tvb A Testy Virtual(-izable) Buffer
-- @tparam Pinfo pinfo An object containing packet information
-- @tparam TreeItem tree An object representing the root of the packet tree
-- @treturn number The number of bytes processed by this dissector
function proto_tls_insecure.dissector(tvb, pinfo, tree)
    local buffer_len = tvb:captured_len()

    -- Associate the protocol with the stream for future packets if it has not
    -- already been done
    if pinfo.private.existing_dissector == nil then
        dprint("Associating packet " .. pinfo.number .. " with the RPC TLS Insecure protocol.")
        pinfo.conversation = proto_tls_insecure
    end

    pinfo.columns.protocol:set(proto_tls_insecure.name)
    pinfo.columns.protocol:fence()

    if buffer_len == 1 then
        return buffer_len
    end

    local tls_dissector = Dissector.get("tls")
    if tls_dissector == nil then
        return 0
    end

    -- This is a TLS packet. Hand off to that dissector.
    return tls_dissector:call(tvb, pinfo, tree)
end
