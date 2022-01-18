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

-- Debug log levels
local debug = util.debug.levels

local default_settings = {
    debug_level = debug.DISABLED,
}

-- Set up debugging functions
function dprint(...)
end
function dprint2(...)
end
local reset_debug = function()
    if default_settings.debug_level > debug.DISABLED then
        dprint = function(...)
            print(table.concat({"Lua (RPCGossip):", ...}, " "))
        end

        if default_settings.debug_level > debug.LEVEL_1 then
            dprint2 = dprint
        end
    end
end
reset_debug()

-- RPC type
local rpc_type = "0x06"

-- Various dissectors
local msgpack_dissector = require("MessagePack")
local serf_dissector

-- Track the expected number of msgpack elements
local expected_msgpack_elements = {}

-- Header bytes for stream
local header_for_stream = {}

-- Track the packets that have already been processed
local seen_packets = {}

-- A map Raft Gossip packet type to readable name
local TRAFFIC_TYPE_MAP = {
    [0x00] = "Packet",
    [0x01] = "Stream",
}

local proto_rpc_gossip = Proto("RPCGossip", "Gossip")

local rpcgossip_fields = {
    tag = ProtoField.string("rpcgossip.tag", "Tag", base.ASCII),
    type = ProtoField.uint8("rpcgossip.type", "Type", base.DEC, TRAFFIC_TYPE_MAP),
    addr_ip = ProtoField.ipv4("rpcgossip.addr.ip", "IP Addr", "IPv4 address that the packet was received on"),
    addr_port = ProtoField.uint16("rpcgossip.addr.port", "IP Port", base.DEC),
    addr_zone = ProtoField.string("rpcgossip.addr.zone", "Zone", base.ASCII),
}

proto_rpc_gossip.fields = rpcgossip_fields
proto_rpc_gossip.prefs.debug = Pref.enum("Debug level", default_settings.debug_level, "The debug level verbosity",
    util.debug.pref_enum)

local pos = 0

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

--- Handle changes to Wireshark preferences for this protocol
-- @function proto_rpc_gossip.prefs_changed
function proto_rpc_gossip:prefs_changed()
    -- Change debug level
    default_settings.debug_level = proto_rpc_gossip.prefs.debug
    reset_debug()
end

--- Set the protocol for future conversations to be RPC Gossip
-- @tparam Pinfo pinfo An object containing packet information
local function set_protocol(pinfo)
    -- Associate the protocol with the stream for future packets if it
    -- has not already been done
    if pinfo.private.existing_dissector == nil then
        dprint2("Associating packet", pinfo.number, "with the RPC Gossip protocol.")
        pinfo.conversation = proto_rpc_gossip
    end

    -- Set the protocol name in the column output to Yamux
    pinfo.columns.protocol:set(proto_rpc_gossip.name)
    pinfo.columns.protocol:fence()
end

-- Take the given tvb and return a modified format that is suitable for adding
-- to the protocol tree.
-- @function transform_header
--
-- @tparam ByteArray byte_arr A ByteArray containing the header bytes
-- @treturn string A hex string of the re-encoded header bytes
local function transform_header(byte_arr)
    -- Stop processing the packet if the MessagePack library is not
    -- loaded
    if msgpack_dissector == nil then
        return 0
    end

    -- Decode the MessagePack data into a Lua table
    local decoded_result = msgpack_dissector.unpack(byte_arr:raw())

    -- Generate a new byte string with the following format:
    -- 1 byte: Length of tag
    -- n bytes: Tag
    -- 1 byte: Header type
    -- 2 bytes: Port where the packet was received
    -- 16 bytes: IP where the packet was received
    -- 1 byte: Length of zone
    -- n bytes: Zone
    local byte_str = Struct.pack(">i1c0>i1i2c0>ic0",
        #decoded_result.Tag,
        decoded_result.Tag,
        decoded_result.Type,
        decoded_result.Addr.Port,
        decoded_result.Addr.IP,
        #decoded_result.Addr.Zone,
        decoded_result.Addr.Zone
    )
    return Struct.tohex(byte_str)
end

--- Initialization function for this protocol
--  Adds this protocol to the 'consul.protocol' dissector table
-- @function proto_rpc_gossip.init
function proto_rpc_gossip.init()
    -- This shouldn't be necessary, but return if the RPC type isn't set
    if not rpc_type then
        return
    end

    -- Register this protocol pattern with our parent dissector
    util.register_protocol_pattern(rpc_type)

    -- Register this protocol pattern with the consul.protocol table in Wireshark
    local consul_proto_dissector_table = DissectorTable.get("consul.protocol")
    if consul_proto_dissector_table then
        consul_proto_dissector_table:add(rpc_type, proto_rpc_gossip)
    end

    if gui_enabled() then
        -- Set the color of the packets from this protocol
        -- Color: Yellow 1
        set_color_filter_slot(8, string.lower(proto_rpc_gossip.name))
    end

    -- Get Serf dissector
    serf_dissector = Dissector.get("serf")
end

--- Dissector for the RPC Gossip protocol
-- Parses a Tvb to determine if it is a Yamux frame
-- @function proto_rpc_gossip.dissector
--
-- @tparam Tvb tvb A Testy Virtual(-izable) Buffer
-- @tparam Pinfo pinfo An object containing packet information
-- @tparam TreeItem tree An object representing the root of the packet tree
-- @treturn number The number of bytes processed by this dissector
function proto_rpc_gossip.dissector(tvb, pinfo, tree)
    -- Get length of Tvb
    local buffer_length = tvb:captured_len()

    -- Skip processing of packets that are empty
    if buffer_length == 0 then
        return 0
    end

    -- Get the stream ID for this packet. This should have been set by the Yamux
    -- dissector. The format should be "<TCP stream ID>-<Yamux stream ID>"
    local stream_id = pinfo.private.yamux_stream_id

    -- Create cache for header packet
    if header_for_stream[stream_id] == nil then
        header_for_stream[stream_id] = {
            complete = false,
            packet = nil,
            bytes = ByteArray.new(),
            -- Holds the state for processing this stream
            state = {
                expected_msgpack_elements = {}
            }
        }
    end

    if buffer_length == 1 and util.number_to_hex(tvb:range(0, 1):uint()) == rpc_type then
        -- Stop processing if the packet if it is just an RPC type byte
        set_protocol(pinfo)
        return buffer_length
    end

    -- If the header has been constructed, then we can process the packet
    local header = header_for_stream[stream_id]
    local state = header.state
    local expected_msgpack_elements = state.expected_msgpack_elements

    -- Reset cursor position to zero
    pos = 0

    -- If a stream is marked as complete, process the parsed header
    if header.complete then
        -- Do not process packets that have already been processed
        if pinfo.number < header.packet and seen_packets[pinfo.number] then
            return buffer_length
            -- If the packet is the one with the decoded header
        elseif pinfo.number == header.packet then
            -- Append the header to this packet as a separate tvb
            local ba

            if type(header.bytes) == "userdata" then
                if util.is_msgpack_map(header.bytes:tvb()) then
                    -- For some reason the header was not properly converted to
                    -- the new format, so we need to convert it here
                    local converted_header = transform_header(header.bytes)
                    header.bytes = converted_header
                else
                    dprint2("Tried to decode header as msgpack, but it was already decoded.")
                end
            else
                ba = ByteArray.new(header.bytes)
            end

            pinfo.columns.info = "Header for stream " .. stream_id
            pinfo.columns.info:fence()
            set_protocol(pinfo)

            local assembled_tvb = ba:tvb("Constructed header")
            local subtree = tree:add(proto_rpc_gossip, assembled_tvb(), "RPC Gossip Header")

            local tag_len = get_bytes(assembled_tvb, 1):uint()
            subtree:add(rpcgossip_fields.tag, get_bytes(assembled_tvb, tag_len)):set_generated()
            subtree:add(rpcgossip_fields.type, get_bytes(assembled_tvb, 1)):set_generated()
            subtree:add(rpcgossip_fields.addr_port, get_bytes(assembled_tvb, 2)):set_generated()

            -- Advance the position by 12 bytes to skip the subnet mask in the
            -- encoded IPv4 address
            pos = pos + 12
            subtree:add(rpcgossip_fields.addr_ip, get_bytes(assembled_tvb, 4)):set_generated()

            local zone_len = get_bytes(assembled_tvb, 1):uint()
            subtree:add(rpcgossip_fields.addr_zone, get_bytes(assembled_tvb, zone_len)):set_generated()

            -- Return the length of the packet so that Wireshark correctly knows
            -- that this packet was processed, even though it contains additional
            -- generated data
            return buffer_length

            -- If the packet comes after the decoded header, it must be a Serf packet
        elseif pinfo.number > header.packet then
            if serf_dissector == nil then
                return 0
            end

            -- Decode the remaining packets with the Serf dissector
            pinfo.private.existing_dissector = "true"
            local dissected_bytes = serf_dissector:call(tvb, pinfo, tree)

            if dissected_bytes == 0 then
                dprint2("The Serf dissector returned 0 bytes when attempting to dissect packet", pinfo.number)
            end

            return dissected_bytes
        end
    else
        -- Skip packets that have already been processed. This is to prevent
        -- duplicate entries in the packet list.
        --
        -- We can't rely on pinfo.visited because that is set to true when any
        -- dissector processes the packet, and this dissector is only called as
        -- a sub-dissector of a parent dissector.
        if seen_packets[pinfo.number] then
            return buffer_length
        end
    end

    -- Mark the packet as already processed so that it is not processed again
    seen_packets[pinfo.number] = true

    -- This protocol will stream MessagePack data in chunks.
    -- We need to parse the chunks, track the number of expected frames,
    -- and build the complete packet.
    -- TODO (blake): Correctly handle 'stream' session types where large chunks
    -- of data are sent in some packets.
    if buffer_length == 1 then
        local peek_byte = tvb():uint()

        -- This might be a stream message that we will need to dissect later
        if util.is_msgpack_map(tvb) then
            -- Need to multiply the map length by four because the length of keys
            -- and their values are provided in separate packets.
            -- If a map length is three, then the data will received as
            -- described below.
            -- 'P' is the packet number, 'K' is the key, and 'V' is the value
            --
            -- P1: Length of K
            -- P2: Value for K
            -- P3: Length of V
            -- P4: V
            --
            -- This is repeated for each element in the map, so the map length
            -- must be multiplied by four to account for the total number of
            -- packets required to complete the map.
            local map_len = (tvb:range(0, 1):bitfield(4, 4)) * 4

            -- Append the current byte to the header bytes buffer
            header.bytes:append(tvb:bytes())

            local msgpack_elems_len = #expected_msgpack_elements
            if msgpack_elems_len == 0 then
                -- This is the first map in the stream.
                -- Set the number of expected elements and return
                table.insert(expected_msgpack_elements, map_len)
                return buffer_length
            else
                -- Decrement the current map's expected number of elements
                expected_msgpack_elements[msgpack_elems_len] =
                    expected_msgpack_elements[msgpack_elems_len] - 1

                if expected_msgpack_elements[msgpack_elems_len] == 0 then
                    -- Still only processing one map.
                    -- Set the expected elements to the next map's length
                    expected_msgpack_elements[msgpack_elems_len] = map_len
                else
                    -- We are processing another map inside the existing map.
                    -- Add the map length to the current list of expected elements
                    table.insert(expected_msgpack_elements, map_len)
                end

                return buffer_length
            end
        elseif util.is_msgpack_fixstr(tvb) then
            state.next_element_length = tvb:range(0, 1):bitfield(3, 5)
            header.bytes:append(tvb:bytes())

            dprint2("Processed a fixed string. The next element length is:", state.next_element_length)

            -- This signifies that the next item is a 16-bit integer, so there
            -- are two bytes to read from the next packet
        elseif tostring(tvb(0, 1)) == "cd" then
            state.next_element_length = 2
            header.bytes:append(tvb:bytes())

        elseif util.is_msgpack_pos_fixint(tvb) then
            header.bytes:append(tvb:bytes())

            -- Set the next expected element length to zero, because we don't
            -- know the expected length
            state.next_element_length = 0
        end
    elseif state.next_element_length == tvb:len() then
        header.bytes:append(tvb:bytes())
        dprint2("Packet", pinfo.number, "with bytes", tostring(tvb:bytes()),
            "matches the expected length for the next packet, which was", state.next_element_length)

    else
        dprint2("Packet", pinfo.number, "The length of this TVB", tvb:len(), "doesn't match the expected length",
            state.next_element_length)
        return 0
    end

    local msgpack_elems_len = #expected_msgpack_elements
    if #expected_msgpack_elements > 0 then
        local remaining_items = expected_msgpack_elements[#expected_msgpack_elements]
        if remaining_items > 0 then
            -- Decrement the number of msgpack elements by one
            remaining_items = remaining_items - 1
        end

        -- If there are no more items in the map, or the last item is an empty
        -- string, then remove the last element from the list
        if remaining_items == 0 or (remaining_items == 1 and state.next_element_length == 0) then
            dprint2("There are no more remaining elements")
            table.remove(expected_msgpack_elements)

            -- This means one map element has been processed, so decrease the map length
            -- for the parent map
            if #expected_msgpack_elements > 0 then
                expected_msgpack_elements[#expected_msgpack_elements] =
                    expected_msgpack_elements[#expected_msgpack_elements] - 1

                return buffer_length
            end
            dprint2("Ending (early) with the expected number of msgpack elements",
                table.concat(expected_msgpack_elements, ", "))
        else
            expected_msgpack_elements[#expected_msgpack_elements] = remaining_items
        end
    end

    if #expected_msgpack_elements == 0 then
        -- Mark the packet as fully processed
        header.complete = true
        header.packet = pinfo.number

        -- Byte Arrays don't survive across dissection calls, so the header
        -- bytes must be saved as a string value in the global scope so that it
        -- will persist. The packet contents are encoded in a format defined in
        -- transform_header() that is used later to reconstruct the header.
        local transformed_bytes = transform_header(header.bytes)
        header.bytes = transformed_bytes
    end

    return buffer_length
end
