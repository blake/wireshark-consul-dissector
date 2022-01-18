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
package.prepend_path("plugins/consul")
local util = require("util")

local debug_levels = util.debug.levels

local default_settings = {
    debug_level = debug_levels.DISABLED,
}

-- Set up debugging functions
function dprint(...)
end
function dprint2(...)
end
local reset_debug = function()
    if default_settings.debug_level > debug_levels.DISABLED then
        dprint = function(...)
            print(table.concat({"Lua (RPCRaft):", ...}, " "))
        end

        if default_settings.debug_level > debug_levels.LEVEL_1 then
            dprint2 = dprint
        end
    end
end
reset_debug()

-- A map Raft RPC types to readable name
local TYPE_MAP = {
    ["0x00"] = "Append Entries",
    ["0x01"] = "Request Vote",
    ["0x02"] = "Install Snapshot",
    ["0x03"] = "Timeout Now",
    ["0xa0"] = "RPCResponse",
}

local msgpack_dissector = Dissector.get("msgpack")

-- Set the initial byte cursor position to zero
local pos = 0

local proto_raft = Proto("RPCRaft", "Raft Protocol")

-- Set up the fields for the Raft protocol
local raft_fields = {
    type = ProtoField.uint8("rpcraft.type", "Type", base.HEX, TYPE_MAP),
}

-- Add the defined fields to the protocol
proto_raft.fields = raft_fields

-- Protocol preferences
proto_raft.prefs.debug = Pref.enum("Debug level", default_settings.debug_level, "The debug level verbosity",
    util.debug.pref_enum)

--- Handle changes to Wireshark preferences for this protocol
-- @function proto_raft.prefs_changed
function proto_raft.prefs_changed()
    dprint2("prefs_changed called")

    -- Change debug level
    default_settings.debug_level = proto_raft.prefs.debug
    reset_debug()
end

--- Inspect a Tvb to determine if it is a Raft packet.
-- @tparam Tvb tvb A Testy Virtual(-izable) Buffer
-- @treturn bool Boolean indicating if the packet is a Raft packet
local function is_raft_rpc(tvb)
    local buffer_len = tvb:captured_len()

    -- Stop processing if the packet buffer is empty
    if buffer_len == 0 then
        return false
    end

    local peek_byte = tvb:range(0, 1):uint()
    local rpc_type = util.number_to_hex(peek_byte)
    if TYPE_MAP[rpc_type] == nil then
        -- Return false if this packet was not identified as a Raft packet
        dprint2("The first byte (" .. rpc_type .. ") does not match a known Raft RPC type.")
        return false
    end

    return true
end

--- Get the specified number of bytes from the Tvb and advance the cursor position
-- @function util.get_bytes
--
-- @tparam Tvb tvb A Testy Virtual(-izable) Buffer
-- @tparam number length The number of bytes to get from the buffer
-- @treturn TvbRange The TvbRange of the specified number of bytes
local function get_bytes(tvb, length)
    local tvb_range = tvb:range(pos, length)
    pos = pos + length

    return tvb_range
end

--- Initialization function for this protocol
--  Adds this protocol to the 'consul.protocol' dissector table
-- @function proto_raft.init
function proto_raft.init()
    -- RPC type
    local rpc_type = "0x01"

    -- Register this protocol pattern with our parent dissector
    util.register_protocol_pattern(rpc_type)

    -- Register this protocol pattern with the consul.protocol table in Wireshark
    local consul_proto_dissector_table = DissectorTable.get("consul.protocol")
    if consul_proto_dissector_table then
        consul_proto_dissector_table:add(rpc_type, proto_raft)
    end
end

--- Dissector for the Raft protocol
-- Parses a Tvb to determine if it is a Raft packet
-- @function proto_raft.dissector
--
-- @tparam Tvb tvb A Testy Virtual(-izable) Buffer
-- @tparam Pinfo pinfo An object containing packet information
-- @tparam TreeItem tree An object representing the root of the packet tree
-- @treturn number The number of bytes processed by this dissector
function proto_raft.dissector(tvb, pinfo, tree)
    local buffer_length = tvb:captured_len()

    -- Reset the cursor position to zero
    pos = 0

    -- Return immediately if this is not a Raft RPC packet
    if not is_raft_rpc(tvb) then
        return 0
    end

    -- Associate the protocol with the stream for future packets if it has not
    -- already been done
    if pinfo.private.existing_dissector == nil then
        dprint("Associating packet", tostring(pinfo.number), "with the Raft protocol.")
        pinfo.conversation = proto_raft

        -- Set the protocol name in the column output to Raft
        pinfo.columns.protocol:set(proto_raft.name)
    end

    if buffer_length == 1 then
        return buffer_length
    end

    local subtree = tree:add(proto_raft, tvb(), "Raft")

    local msg_type = get_bytes(tvb, 1)
    subtree:add(raft_fields.type, msg_type)

    -- Return buffer_length if the MessagePack dissector is not referenced in
    -- the filter/tap/UI. This saves processing time by not unnecessarily
    -- decoding data that will not be displayed.
    if not tree:referenced(msgpack_dissector) then
        return pos
    end

    -- Decode the payload. Iterate over it until all MsgPack objects have
    -- been decoded.
    local dissected_bytes
    repeat
        local raft_payload = tvb(pos):tvb()
        local payload_field = subtree:add(proto_raft, raft_payload(), "Payload")

        if msgpack_dissector == nil then
            return 0
        end

        dprint("Decoding MsgPack object from position " .. pos .. ". Current frame is " .. pinfo.number)

        dissected_bytes = msgpack_dissector:call(raft_payload, pinfo, payload_field)

        if dissected_bytes > 0 then
            -- Move cursor forward
            pos = pos + dissected_bytes

            -- Otherwise, set the protocol to this protocol
            -- set_protocol(pinfo)

            -- Set the protocol name in the column output to MessagePack
            if tostring(pinfo.columns.protocol) ~= "MessagePack" then
                pinfo.columns.protocol:set("MessagePack")
                pinfo.columns.protocol:fence()
            end

        else
            break
        end
    until dissected_bytes == 0 or pos == buffer_length

    return buffer_length
end
