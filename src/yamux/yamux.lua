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

-- The Yamux dissector is written per the spec at https://github.com/hashicorp/yamux/blob/master/spec.md

-- Import utility functions
package.prepend_path("plugins/consul")
local util = require("util")

-- RPC type
local rpc_type = "0x04"

-- Default window value
-- 256 KB: https://github.com/hashicorp/yamux/blob/3d6f54d66fc83411743d3421f7a84a7d348f071c/spec.md#flow-control
local window_start_value = 256 * 1024

-- Map Yamux header type to variables
local hdr_type = {
    DATA = 0x00,
    WINDOW_UPDATE = 0x01,
    PING = 0x02,
    GO_AWAY = 0x03,
}

-- Map Yamux header type to readable name
local HDR_TYPE_MAP = {
    [hdr_type.DATA] = "Data", -- Used to transmit data. May transmit zero length payloads depending on the flags.
    [hdr_type.WINDOW_UPDATE] = "WindowUpdate", -- Used to updated the senders receive window size.
        -- This is used to implement per-session flow control.
    [hdr_type.PING] = "Ping", -- Used to measure RTT. It can also be used to heart-beat and do keep-alives over TCP.
    [hdr_type.GO_AWAY] = "GoAway", -- Used to close a session.
}

-- Map Yamux header flag to readable name
local HDR_FLAG_MAP = {
    [0x0000] = "None",
    [0x0001] = "SYN", -- Signals the start of a new stream. May be sent with a
                    -- data or window update message. Also sent with a ping to
                    -- indicate outbound.

    [0x0002] = "ACK", -- Acknowledges the start of a new stream. May be sent with
                    -- a data or window update message. Also sent with a ping to
                    -- indicate response.

    [0x0004] = "FIN", -- Performs a half-close of a stream. May be sent with a
                    -- data message or window update.

    [0x0008] = "RST", -- Reset a stream immediately. May be sent with a data or window update message.
}

-- Map names of message types to their corresponding integers
local HDR_FLAG_NAME_MAP = {}
for k, v in pairs(HDR_FLAG_MAP) do
    HDR_FLAG_NAME_MAP[v] = k
end

-- Used for session termination.
-- Tracks the reason for termination.
local GOAWAY_FLAG_MAP = {
    [0x00] = "NormalTermination",
    [0x01] = "ProtocolError",
    [0x02] = "InternalError",
}

--- A useful table of constants
local consts = {
    protocol_version = 0, -- The current Yamux protocol version, '0'
    rpc_gossip_type_int = 6, -- The RPC type of the Gossip RPC
    yamux_header_len = 0, -- The length of the Yamux header
}

-------------------------------------
-- Byte lengths for various fields --
-------------------------------------
local sizeOf = {
    -- Version field is 8-bits (1 byte)
    version = 1,

    -- Type field is 8-bits (1 byte)
    type = 1,

    -- Flags field is 16-bits (2 bytes)
    flags = 2,

    -- StreamID field is 32-bits (4 bytes)
    stream_id = 4,

    -- Length field is 32-bits (4 bytes)
    length = 4
}

-- Get the dissector for decoding MessagePack
local msgpack_dissector = Dissector.get("msgpack")

-- Set the initial byte cursor position to zero
local pos = 0

-- Compute Yamux header size
for _, byte_len in next, sizeOf do
    consts.yamux_header_len = consts.yamux_header_len + byte_len
end

local proto_yamux = Proto("Yamux", "Yamux Protocol")

-- Set up the fields for the Yamux protocol
local yamux_fields = {
    version = ProtoField.uint8("yamux.version", "Version", base.DEC),
    type = ProtoField.uint8("yamux.type", "Type", base.HEX, HDR_TYPE_MAP),
    flags = ProtoField.uint16("yamux.flags", "Flags", base.HEX, HDR_FLAG_MAP),
    stream_id = ProtoField.uint32("yamux.stream_id", "Stream ID", base.DEC),
    length = ProtoField.uint32("yamux.length", "Length", base.DEC),
    payload_length = ProtoField.uint32("yamux.payload_length", "Payload Length", base.DEC),
    recv_window_delta = ProtoField.uint32("yamux.recv_window_delta", "Receive window delta", base.DEC),
    ping_payload = ProtoField.uint32("yamux.ping_payload", "Ping payload", base.HEX),
    error_code = ProtoField.uint32("yamux.error_code", "Error code", base.HEX, GOAWAY_FLAG_MAP),

    window_size_client_before = ProtoField.uint32("yamux.window_size.client.before", "Client window size (before)", base.DEC),
    window_size_server_before = ProtoField.uint32("yamux.window_size.server.before", "Server window size (before)", base.DEC),
    window_size_client_after = ProtoField.uint32("yamux.window_size.client.after", "Client window size (after)", base.DEC),
    window_size_server_after = ProtoField.uint32("yamux.window_size.server.after", "Server window size (after)", base.DEC),

    prev_frame_request = ProtoField.framenum("yamux.previous_frame", "Previous frame (request)", base.NONE,
        frametype.REQUEST),
    prev_frame_response = ProtoField.framenum("yamux.previous_frame", "Previous frame (response)", base.NONE,
        frametype.RESPONSE),
    prev_frame_ack = ProtoField.framenum("yamux.previous_frame", "Previous frame (ACK)", base.NONE, frametype.ACK),
    next_frame_request = ProtoField.framenum("yamux.next_frame", "Next frame (request)", base.NONE, frametype.REQUEST),
    next_frame_response = ProtoField.framenum("yamux.next_frame", "Next frame (response)", base.NONE, frametype.RESPONSE),
    next_frame_ack = ProtoField.framenum("yamux.next_frame", "Next frame (ACK)", base.NONE, frametype.ACK),
}

-- Add the defined fields to the protocol
proto_yamux.fields = yamux_fields

-- Fields to retrieve protocol data from the packet tree after dissection
--
-- ID of the current TCP stream
local stream_index = Field.new("tcp.stream")
local src_port = Field.new("tcp.srcport")
local dst_port = Field.new("tcp.dstport")
local yamux_flags_field = Field.new("yamux.flags")
local yamux_stream_id_field = Field.new("yamux.stream_id")

-- Track information related to Yamux streams
-- Map Yamux stream IDs to multiplexed protocol type.
local yamux_stream_info = {}

-- Track the current stream ID
local current_stream_id = nil

--- Return the RPC type for the given stream ID, if found
-- @tparam number stream_id The ID of the stream
-- @treturn string The RPC type, if found
local function get_rpc_type_for_stream(stream_id)
    return yamux_stream_info[stream_id].rpc_type
end

-- Debug log levels
local debug_levels = util.debug.levels

--- Default settings for this protocol
local default_settings = {
    debug_level = debug_levels.DISABLED,
    heuristic_enabled = true, -- Whether heuristic dissection is enabled
    ports = 443,
}

local consul_dissector_table = DissectorTable.get("consul.protocol")

-- Set up debugging functions
function dprint(...)
end
function dprint2(...)
end
local reset_debug = function()
    if default_settings.debug_level > debug_levels.DISABLED then
        dprint = function(...)
            print(table.concat({"Lua (Yamux):", ...}, " "))
        end

        if default_settings.debug_level > debug_levels.LEVEL_1 then
            dprint2 = dprint
        end
    end
end
reset_debug()

proto_yamux.prefs.heuristic = Pref.bool("Heuristic enabled", default_settings.heuristic_enabled,
    "Whether heuristic dissection is enabled.")
proto_yamux.prefs.debug = Pref.enum("Debug level", default_settings.debug_level, "The debug level verbosity",
    util.debug.pref_enum)
proto_yamux.prefs.ports = Pref.range("Port(s)", default_settings.ports,
    "Set the TCP port(s) for Yamux, default is 443. That ports are used only with disabled heuristics analysis", 65535)

-- Got from zabbixagent
local function enableDissector()
    if not default_settings.heuristic_enabled then
        DissectorTable.get("tcp.port"):add(default_settings.ports, proto_yamux)
        -- supports also TLS decryption if the session keys are configured in Wireshark
        DissectorTable.get("tls.port"):add(default_settings.ports, proto_yamux)
    end
end
-- call it now, because we're enabled by default
enableDissector()

local function disableDissector()
    if not default_settings.heuristic_enabled then
        DissectorTable.get("tcp.port"):remove(default_settings.ports, proto_yamux)
        DissectorTable.get("tls.port"):remove(default_settings.ports, proto_yamux)
    end
end

--- Handle changes to Wireshark preferences for this protocol
-- @function proto_yamux.prefs_changed
function proto_yamux:prefs_changed()
    dprint2("prefs_changed called")
    -- Disable the dissector if heuristic detection is disabled.
    -- The dissector will be re-enabled if the heuristic detection is still
    -- disabled after processing the preference changes.
    disableDissector()

    -- Change debug level
    default_settings.debug_level = proto_yamux.prefs.debug
    reset_debug()

    default_settings.heuristic_enabled = proto_yamux.prefs.heuristic
    default_settings.ports = proto_yamux.prefs.ports

    enableDissector()
end

--- Calls a sub-dissector for the given protocol pattern
-- @tparam string pattern The protocol pattern to try for this packet
-- @tparam Tvb tvb A Testy Virtual(-izable) Buffer
-- @tparam Pinfo pinfo An object containing packet information
-- @tparam TreeItem tree An object representing the root of the packet tree
-- @treturn number The expected length of a Yamux header
local function call_sub_dissector(pattern, tvb, pinfo, tree)
    -- Signal to the sub-dissector that this packet has already been processed
    -- by the Yamux dissector. This will prevent the sub-dissector from
    -- overwriting 'pinfo.conversation' and 'columns.protocol'
    pinfo.private.existing_dissector = "true"

    -- Call the sub-dissector
    return consul_dissector_table:try(pattern, tvb, pinfo, tree)
end

--- Get the specified number of bytes from the Tvb and advance the cursor position
-- @function get_bytes
--
-- @tparam Tvb tvb A Testy Virtual(-izable) Buffer
-- @tparam number length The number of bytes to get from the buffer
-- @treturn TvbRange The TvbRange of the specified number of bytes
local function get_bytes(tvb, length)
    local tvb_range = tvb:range(pos, length)
    pos = pos + length

    return tvb_range
end

--- Returns the TCP stream ID for the current packet
-- @treturn number The ID of the current TCP stream
local function get_stream_index()
    local stream_id = stream_index()
    if not stream_id then
        return nil
    end

    return stream_id.value
end

--- Constructs a unique stream ID for the current packet. This is a combination
--- of the TCP and Yamux stream IDs. It is used to uniquely identify a Yamux
--- stream in the packet tree.
-- @treturn string A string representing a unique ID for this Yamux stream
local function make_unique_stream_id()
    return string.format("%s-%s", get_stream_index(), yamux_stream_id_field().value)
end

--- Constructs a full stream ID for the current packet. This is a combination
--- of the unique stream ID and source/destination TCP port. It is used to
--- trace packets through logs
-- @treturn string A string representing a unique ID for this Yamux stream
local function make_full_stream_id()
    return string.format("%s-%s-%s", make_unique_stream_id(), src_port().value, dst_port().value)
end

--- Returns the expected length of a Yamux header
-- @treturn number The expected length of a Yamux header
local function header_length()
    return consts.yamux_header_len
end

--- Test if the packet is a Yamux header
-- @tparam Tvb tvb A Testy Virtual(-izable) Buffer
-- @treturn bool True if the packet is a Yamux header, false otherwise
local function is_yamux(tvb)
    local buffer_len = tvb:captured_len()

    -- Stop processing if the packet buffer is empty
    if buffer_len == 0 then
        return false
    end

    -- Verify the length of the packet is equal to the length of the Yamux
    -- header and the first byte (version) is 0, which should indicate that this
    -- is a Yamux stream
    if buffer_len == header_length() and tvb:range(0, 1):int() == consts.protocol_version then
        return true
    end

    -- This is not a Yamux frame
    return false
end

--- Test if the packet is a Yamux RPC indicator
-- @tparam Tvb tvb A Testy Virtual(-izable) Buffer
-- @treturn bool True if the packet is a Yamux RPC, false otherwise
local function is_yamux_rpc(tvb)
    local peek_byte = tvb:range(0, 1):uint()
    local converted_byte = util.number_to_hex(peek_byte)

    return converted_byte == rpc_type
end

--- Test if the Yamux stream is default opened (neither client not server will open it)
-- @treturn bool True if the stream was opened by default, false otherwise
local function is_yamux_stream_default_created()
    -- Based on https://github.com/hashicorp/yamux/blob/3d6f54d66fc83411743d3421f7a84a7d348f071c/spec.md#streamid-field
    return yamux_stream_id_field().value == 0
end

--- Test if the Yamux stream is opened by client
-- @treturn bool True if the stream was opened by client, false otherwise
local function is_yamux_stream_client_created()
    -- Based on https://github.com/hashicorp/yamux/blob/3d6f54d66fc83411743d3421f7a84a7d348f071c/spec.md#streamid-field
    return (yamux_stream_id_field().value % 2 == 1) and not is_yamux_stream_default_created()
end

--- Test if the Yamux stream is opened by server
-- @treturn bool True if the stream was opened by server, false otherwise
local function is_yamux_stream_server_created()
    -- Based on https://github.com/hashicorp/yamux/blob/3d6f54d66fc83411743d3421f7a84a7d348f071c/spec.md#streamid-field
    return (yamux_stream_id_field().value % 2 == 0) and not is_yamux_stream_default_created()
end

--- Set the protocol for future conversations to be Yamux
-- @tparam Pinfo pinfo An object containing packet information
local function set_protocol(pinfo)
    -- Associate the protocol with the stream for future packets
    pinfo.conversation = proto_yamux

    -- Set the protocol name in the column output to Yamux
    pinfo.columns.protocol:set(proto_yamux.name)
end

--- Parse Yamux header from packet buffer
-- @tparam TreeItem subtree An object representing the subtree to append packet details
-- @tparam {ProtoField,...} fields Table containing ProtoField objects for this protocol
-- @tparam TvbRange yamux_header A TvbRange object representing the Yamux header
-- @return bool True if the packet is a Yamux header, false otherwise
local function parse_yamux(subtree, pinfo, fields, yamux_header)

    -- Do not attempt to parse header if provided packets are less than expected
    -- size
    if yamux_header:captured_len() ~= header_length() then
        return false
    end

    -- Reset cursor position
    pos = 0

    -- Get the 8-bit version identifier from the header
    subtree:add(fields.version, get_bytes(yamux_header, sizeOf.version))

    local typeBytes = get_bytes(yamux_header, sizeOf.type)
    local typeValue = typeBytes:uint()
    subtree:add(fields.type, typeBytes)
    subtree:add(fields.flags, get_bytes(yamux_header, sizeOf.flags))
    subtree:add(fields.stream_id, get_bytes(yamux_header, sizeOf.stream_id))

    -- Based on https://github.com/hashicorp/yamux/blob/3d6f54d66fc83411743d3421f7a84a7d348f071c/spec.md#length-field
    local lenBytes = get_bytes(yamux_header, sizeOf.length)
    local lenValue = lenBytes:uint()
    subtree:add(fields.length, lenBytes)

    local payloadLen = 0
    local windowDelta = 0

    if typeValue == hdr_type.DATA then
        subtree:add(fields.payload_length, lenBytes):set_generated()
        payloadLen = lenValue
    elseif typeValue == hdr_type.WINDOW_UPDATE then
        subtree:add(fields.recv_window_delta, lenBytes):set_generated()
        windowDelta = lenValue
    elseif typeValue == hdr_type.PING then
        subtree:add(fields.ping_payload, lenBytes):set_generated()
    elseif typeValue == hdr_type.GO_AWAY then
        subtree:add(fields.error_code, lenBytes):set_generated()
    else
        dprint("Bad packet type", typeValue)
    end

    -- Obtain a few fields that were added to the dissection tree
    local flags = yamux_flags_field().value

    -- Use a unique ID to track packets for this Yamux stream across all TCP
    -- sessions
    current_stream_id = make_unique_stream_id()

    if yamux_stream_info[current_stream_id] == nil then
        yamux_stream_info[current_stream_id] = {
            rpc_type = "",
            frame_prev_next_map = {}
        }
    end

    if flags == HDR_FLAG_NAME_MAP.SYN then
        -- This is the start of a new Yamux conversation. Set the protocol.
        set_protocol(pinfo)
    end

    if is_yamux_stream_default_created() and not (typeValue == hdr_type.PING or typeValue == hdr_type.GO_AWAY) then
        dprint("Default opened stread cannot be with type", typeValue)

        -- TODO: add expert info
    end

    -- Determine client/server tcp ports for window calculation
    local disable_window_calc_logic = false
    if flags == HDR_FLAG_NAME_MAP.SYN then
        if src_port().value == dst_port().value then
            disable_window_calc_logic = true
            dprint("TCP source port", src_port().value, "is equal to destination port", dst_port().value, ". No possibility to determine Yamux client/server direction. Window calculation logic will be disabled")
        elseif is_yamux_stream_default_created() then
            disable_window_calc_logic = true
            dprint("Default opened stread cannot be opened")
            -- TODO: add expert info
        elseif is_yamux_stream_server_created() then
            yamux_stream_info[current_stream_id].server_tcp_port = src_port().value
        else
            yamux_stream_info[current_stream_id].server_tcp_port = dst_port().value
        end
    end

    -- Get the current stream's mapping of frame numbers to previous and next
    -- frame numbers
    local stream_prev_next_map = yamux_stream_info[current_stream_id].frame_prev_next_map

    -- Get the last frame number that was processed by this dissector
    local last_frame = yamux_stream_info[current_stream_id].last_frame

    -- Track the current frame number being processed by this dissector
    local current_frame = pinfo.number

    -- If this frame hasn't been seen before, create a table for holding the
    -- mapping for the previous and next frame numbers
    if not pinfo.visited and stream_prev_next_map[current_frame] == nil then
        stream_prev_next_map[current_frame] = {}
    end

    -- This is the first conversation that has been seen for this stream.
    -- There are no previous frames before this. Set the last_frame to the
    -- current frame and return
    if not last_frame then
        yamux_stream_info[current_stream_id].last_frame = current_frame
        return
    end

    if not pinfo.visited then
        if last_frame < pinfo.number then
            -- Set the previous frame for this frame
            stream_prev_next_map[current_frame].prev = last_frame

            -- Modify the mapping for the last frame to set the next frame to
            -- this frame number
            yamux_stream_info[current_stream_id].frame_prev_next_map[last_frame].next = current_frame
        end
    end

    local previous_frame = stream_prev_next_map[current_frame].prev
    local next_frame = stream_prev_next_map[current_frame].next

    if previous_frame then
        if flags == HDR_FLAG_NAME_MAP.SYN then
            subtree:add(fields.prev_frame_ack, previous_frame):set_generated()
        else
            subtree:add(fields.prev_frame_request, previous_frame):set_generated()
        end
    end
    if next_frame then
        if flags == HDR_FLAG_NAME_MAP.SYN then
            subtree:add(fields.next_frame_ack, next_frame):set_generated()
        else
            subtree:add(fields.next_frame_request, next_frame):set_generated()
        end
    end

    -- Update the last frame number that was processed by this dissector
    yamux_stream_info[current_stream_id].last_frame = current_frame

    if not (disable_window_calc_logic or is_yamux_stream_default_created()) then
        -- Window values recalculation
        local new_server_window_size = window_start_value
        local new_client_window_size = window_start_value

        if previous_frame then
            -- Use prev values, if prev frame is presented
            new_server_window_size = yamux_stream_info[current_stream_id].server_window_size
            new_client_window_size = yamux_stream_info[current_stream_id].client_window_size
        end

        subtree:add(fields.window_size_server_before, new_server_window_size):set_generated()
        subtree:add(fields.window_size_client_before, new_client_window_size):set_generated()

        if src_port().value == yamux_stream_info[current_stream_id].server_tcp_port then
            dprint2("Packet", make_full_stream_id(), "is server one")
            new_server_window_size = new_server_window_size + windowDelta
            new_client_window_size = new_client_window_size - payloadLen
        elseif dst_port().value == yamux_stream_info[current_stream_id].server_tcp_port then
            dprint2("Packet", make_full_stream_id(), "is client one")
            new_client_window_size = new_client_window_size + windowDelta
            new_server_window_size = new_server_window_size - payloadLen
        else
            dprint("Yamux Stream", make_full_stream_id(), "packets were detected without SYN flag")
            -- TODO: add expert info
        end

        yamux_stream_info[current_stream_id].server_window_size = new_server_window_size
        yamux_stream_info[current_stream_id].client_window_size = new_client_window_size

        subtree:add(fields.window_size_server_after, new_server_window_size):set_generated()
        subtree:add(fields.window_size_client_after, new_client_window_size):set_generated()
    end

    return true
end

--- Initialization function for this protocol
--  Adds this protocol to the 'consul.protocol' dissector table
-- @function proto_yamux.init
function proto_yamux.init()
    -- This shouldn't be necessary, but return if the RPC type isn't set
    if not rpc_type then
        return
    end

    -- Register this protocol pattern with our parent dissector
    util.register_protocol_pattern(rpc_type)

    -- Register this protocol pattern with the consul.protocol table in Wireshark
    local consul_proto_dissector_table = DissectorTable.get("consul.protocol")
    if consul_proto_dissector_table then
        consul_proto_dissector_table:add(rpc_type, proto_yamux)
    end

    if gui_enabled() then

        -- Set the color of the packets from this protocol
        -- Color: Green 1
        set_color_filter_slot(5, string.lower(proto_yamux.name))
    end
end

--- Dissector for the Yamux protocol
-- Parses a Tvb to determine if it is a Yamux frame
-- @function proto_yamux.dissector
--
-- @tparam Tvb tvb A Testy Virtual(-izable) Buffer
-- @tparam Pinfo pinfo An object containing packet information
-- @tparam TreeItem tree An object representing the root of the packet tree
-- @treturn number The number of bytes processed by this dissector
function proto_yamux.dissector(tvb, pinfo, tree)
    -- Get length of Tvb
    local buffer_length = tvb:captured_len()

    -- Skip processing of packets that are empty
    if buffer_length == 0 then
        return 0
    end

    -- Reset cursor position to 0
    pos = 0

    if buffer_length == 1 then
        if is_yamux_rpc(tvb) then
            -- This is a Yamux RPC packet.
            -- Set the protocol for this conversation to Yamux
            set_protocol(pinfo)
            return buffer_length
        end
    elseif is_yamux(tvb) then

        local subtree = tree:add(proto_yamux, tvb(), "Yamux")
        local result = parse_yamux(subtree, pinfo, yamux_fields, tvb)

        if result then
            set_protocol(pinfo)
            return header_length()
        end
    end

    -- Stream ID has not been set so there is no way to associate this packet
    -- with a particular RPC type.
    if current_stream_id == nil then
        return 0
    end

    -- If this stream already has another RPC type associated with it, call that
    -- dissector.
    ::call_sub_dissector::
    local multiplexed_rpc_type = get_rpc_type_for_stream(current_stream_id)
    if multiplexed_rpc_type and multiplexed_rpc_type ~= "" then
        -- Propagate the stream ID to the sub-dissector
        if pinfo.private.yamux_stream_id == nil then
            pinfo.private.yamux_stream_id = current_stream_id
        end
        dprint2("Calling sub-dissector", multiplexed_rpc_type, "for stream ID", current_stream_id)
        return call_sub_dissector(multiplexed_rpc_type, tvb, pinfo, tree)
    end

    -- Multiplexed network area communication can also be handled on a Yamux
    -- stream. Check if this is a multiplexed RPC packet.
    local first_byte = tvb:range(0, 1):uint()
    if first_byte == consts.rpc_gossip_type_int then
        dprint2("Stream ID", current_stream_id, "is a RPC gossip packet")

        -- Track the RPC type for this stream ID if it is not already set
        yamux_stream_info[current_stream_id].rpc_type = util.number_to_hex(consts.rpc_gossip_type_int)

        -- Call the sub-dissector.
        goto call_sub_dissector
    end

    -- Since no other actions matched, this must be an RPC packet.
    -- Decode the packet as MessagePack if the first byte appears to be a
    -- msgpack-encoded map and the MessagePack dissector is enabled.
    if util.is_msgpack_map(tvb) and msgpack_dissector ~= nil then
        -- Decode the payload. Iterate over it until all MsgPack objects have
        -- been decoded.
        local dissected_bytes
        repeat
            dissected_bytes = msgpack_dissector:call(tvb(pos):tvb(), pinfo, tree)
            if dissected_bytes > 0 then
                -- Move cursor forward
                pos = pos + dissected_bytes

                -- Set the protocol name in the column output to MessagePack
                if tostring(pinfo.columns.protocol) ~= "MessagePack" then
                    pinfo.columns.protocol:set("MessagePack")
                    pinfo.columns.protocol:fence()
                end
            end
        until dissected_bytes == 0 or pos == buffer_length
    end

    -- Return the number of bytes processed by this dissector
    return pos
end

--- Heuristic detection method for Yamux
-- Parses a Tvb to determine if it is a Yamux header or RPC frame
-- @tparam Tvb tvb A Testy Virtual(-izable) Buffer
-- @tparam Pinfo pinfo An object containing packet information
-- @tparam TreeItem tree An object representing the root of the packet tree
-- @treturn bool True if the packet is a Yamux header or RPC, false otherwise
local function heuristic_dissect_yamux(tvb, pinfo, _)
    -- if our preferences tell us not to do this, return false
    if not default_settings.heuristic_enabled then
        return false
    end

    local buffer_length = tvb:captured_len()

    if buffer_length == 1 and is_yamux_rpc(tvb) then
        set_protocol(pinfo)
        return true
    end

    if is_yamux(tvb) then
        set_protocol(pinfo)
        return true
    end
end

-- Register a heuristic dissector for the Yamux protocol
proto_yamux:register_heuristic("tcp", heuristic_dissect_yamux)
proto_yamux:register_heuristic("tls", heuristic_dissect_yamux)
