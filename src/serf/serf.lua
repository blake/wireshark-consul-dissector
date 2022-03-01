--[[
Consul Gossip/Serf dissector

This plugin attempts to dissect Consul's Serf port.

### Installation ###
Place in:
%PROGRAMFILES%\Wireshark\plugins\ (Windows)
$HOME/.local/lib/wireshark/plugins/ (Unix)
--]]

-- Set plugin version information
set_plugin_info({
    author = "Blake Covarrubias <blake@covarrubi.as>",
    description = [[
    Wireshark plugin for dissecting HashiCorp Consul's gossip communication.
    ]],
    repository = "https://github.com/blake/wireshark-consul-dissector.git",
    version = "0.0.1"
})

-- Import utility functions
package.prepend_path("plugins/consul")
local util = require("util")

-----------------------------------
-- Tables to map values to names --
-----------------------------------
local COMPRESSION_TYP_MAP = {
    [0] = "lzwAlgo", -- 0x00
}

local ENCRYPTION_VERSION_MAP = {
    [0] = "AES-GCM 128, using PKCS7 padding", -- 0x00
    [1] = "AES-GCM 128, no padding.",         -- 0x01
}

local MSG_TYPE_MAP = {
    [0] = "Ping",          -- 0x00
    [1] = "IndirectPing",  -- 0x01
    [2] = "ACKResponse",   -- 0x02
    [3] = "Suspect",       -- 0x03
    [4] = "Alive",         -- 0x04
    [5] = "Dead",          -- 0x05
    [6] = "Push/pull",     -- 0x06
    [7] = "Compound",      -- 0x07
    [8] = "User",          -- 0x08
    [9] = "Compress",      -- 0x09
    [10] = "Encrypt",      -- 0x0a
    [11] = "NACKResponse", -- 0x0b
    [12] = "HasCRC",       -- 0x0c
    [13] = "Error",        -- 0x0d
    [244] = "Label",       -- 0xf4
}

-- Map names of message types to their corresponding integers
local MSG_TYPE_NAME_MAP = {}
for k, v in pairs(MSG_TYPE_MAP) do
    MSG_TYPE_NAME_MAP[v] = k
end

-------------------------------------
-- Byte lengths for various fields --
-------------------------------------
local sizeOf = {
    compound_num_parts = 1,
    -- The length of the field indicating the size of the compound message
    compound_length = 2,
    crc_length = 4,
    encrypt_length = 4,
    encrypt_nonce = 12,
    encrypt_version = 1,
    label_length = 1,
    message_type = 1,
}

-- Get the dissector for decoding MessagePack
local msgpack_dissector = Dissector.get("msgpack")

-- Protocol tables
local tcp_port_dissector_table = DissectorTable.get("tcp.port")
local udp_port_dissector_table = DissectorTable.get("udp.port")

-- Set the initial byte cursor position to zero
local pos = 0

-- Create a new protocol in Wireshark
-- (name, description)
local proto_serf = Proto("serf", "Serf gossip protocol")

local serf_fields = {
    -- Label fields
    label_type = ProtoField.uint8("serf.label.type", "Type", base.DEC),
    label_length = ProtoField.uint8("serf.label.length", "Length", base.DEC),
    label_name = ProtoField.string("serf.label.name", "Name", base.NONE),
    message_type = ProtoField.uint8("serf.message.type", "Message Type", base.DEC, MSG_TYPE_MAP),

    checksum = ProtoField.uint32("serf.message.checksum", "Checksum", base.DEC_HEX),
    compound_length = ProtoField.uint16("serf.message.compound_length", "Compound Length", base.DEC),

    -- Encryption fields
    encryption_version = ProtoField.uint8("serf.message.encryption_version", "Encryption version", base.DEC,
        ENCRYPTION_VERSION_MAP),
    encryption_nonce = ProtoField.bytes("serf.message.encryption_nonce", "Encryption nonce", base.NONE),
    remaining_payload = ProtoField.bytes("serf.message.remaining_payload", "Remaining Payload", base.NONE,
        "The remaining unparsed payload"),
    encrypted_length = ProtoField.uint8("serf.message.encrypted_length", "Length", base.DEC),
}

-- Add the defined fields to the protocol
proto_serf.fields = serf_fields

-- Fields to retrieve protocol data from the packet tree after dissection
local serf_checksum_field = Field.new("serf.message.checksum")
local serf_compound_length_field = Field.new("serf.message.compound_length")
local serf_encrypted_length_field = Field.new("serf.message.encrypted_length")
local serf_encryption_version_field = Field.new("serf.message.encryption_version")
local serf_label_length_field = Field.new("serf.label.length")

--- Construct the name for the Serf message based on the message type
-- @function construct_serf_message_name
--
-- @tparam number message_type_int The integer representing the message type
-- @treturn string The formatted name for the tree item
local function construct_serf_message_name(message_type_int)
    return string.format("Serf Message (%s)", MSG_TYPE_MAP[message_type_int])
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

--- Ensure that all of the TCP packet is present
-- @function has_complete_compound_payload
-- @tparam Pinfo pinfo An object containing packet information
-- @tparam number buffer_length The length of the buffer
-- @tparam number compound_length The expected length of the compound message
-- @treturn boolean true if the packet is complete, false otherwise
local function has_complete_compound_payload(pinfo, buffer_length, compound_length)

    repeat
        if buffer_length < compound_length then
            pinfo.desegment_len = compound_length - buffer_length
            return false
        end
    until buffer_length >= compound_length

    return true
end

--- Parse a compound Serf message
-- @tparam Tvb tvb A Testy Virtual(-izable) Buffer
-- @tparam TreeItem subtree An object representing the subtree to append packet details
-- @tparam {ProtoField,...} fields Table containing ProtoField objects for this protocol
-- @treturn {number,...} A list of the byte lengths for each message
local function parse_compound_msg(tvb, subtree, serf_fields)
    subtree:set_len(pos + sizeOf.compound_length)
    local numParts = get_bytes(tvb, sizeOf.compound_num_parts)

    -- Ensure there are enough bytes to read the number of parts
    if tvb(pos):len() < numParts:uint() * sizeOf.compound_length then
        return nil
    end

    subtree:add(serf_fields.compound_length, numParts)

    local compound_num_parts = serf_compound_length_field().value

    -- Decode the lengths
    local lengths = {}
    for i = 0, compound_num_parts - 1, 1 do
        local length = get_bytes(tvb, sizeOf.compound_length):uint()
        lengths[i + 1] = length
    end

    return lengths
end

--- Parse an encrypted Serf message
-- @tparam Tvb tvb A Testy Virtual(-izable) Buffer
-- @tparam TreeItem subtree An object representing the subtree to append packet details
-- @tparam {ProtoField,...} fields Table containing ProtoField objects for this protocol
local function parse_encrypt_msg(tvb, subtree, serf_fields)
    -- TODO: Fix parsing of encrypted payload length
    subtree:add(serf_fields.encrypted_length, get_bytes(tvb, sizeOf.encrypt_length))
    subtree:add(serf_fields.encryption_version, get_bytes(tvb, sizeOf.encrypt_version))
    subtree:add(serf_fields.encryption_nonce, get_bytes(tvb, sizeOf.encrypt_nonce))

    local encryption_version_field = serf_encryption_version_field()

    if encryption_version_field.value == 1 then
        subtree:add(serf_fields.remaining_payload, tvb(pos))
    end

    local encrypted_header_len =
        sizeOf.message_type + serf_encrypted_length_field().len + encryption_version_field.len + sizeOf.encrypt_nonce
    subtree:set_len(encrypted_header_len)

end

--- Parse a Serf message with a CRC
-- @tparam Tvb tvb A Testy Virtual(-izable) Buffer
-- @tparam TreeItem subtree An object representing the subtree to append packet details
-- @tparam Pinfo pinfo An object containing packet information
-- @tparam {ProtoField,...} fields Table containing ProtoField objects for this protocol
local function parse_hascrc_msg(tvb, subtree, serf_fields)
    -- TODO (blake): Validate checksum
    subtree:add(serf_fields.checksum, get_bytes(tvb, sizeOf.crc_length))

    subtree:set_len(sizeOf.message_type + serf_checksum_field().len)
end

-- Debug log levels
local debug_levels = util.debug.levels

local default_settings = {
    debug_level = debug_levels.DISABLED,
    lan_port = 8301,
    wan_port = 8302,
}

-- Set up debugging functions
function dprint(...)
end
function dprint2(...)
end
local reset_debug = function()
    if default_settings.debug_level > debug_levels.DISABLED then
        dprint = function(...)
            print(table.concat({"Lua (Serf):", ...}, " "))
        end

        if default_settings.debug_level > debug_levels.LEVEL_1 then
            dprint2 = dprint
        end
    end
end
reset_debug()

proto_serf.prefs.lan_port = Pref.uint("Serf LAN port number", default_settings.lan_port,
    "The TCP/UDP port number for Consul's Serf LAN traffic")
proto_serf.prefs.wan_port = Pref.uint("Serf WAN port number", default_settings.wan_port,
    "The TCP/UDP port number for Consul's Serf WAN traffic")
proto_serf.prefs.debug = Pref.enum("Debug level", default_settings.debug_level, "The debug level verbosity",
    util.debug.pref_enum)

--- Initialization function for this protocol
--  Adds this protocol to the 'consul.protocol' dissector table
-- @function proto_serf.init
function proto_serf.init()
    if gui_enabled() then
        -- Set the color of the packets from this protocol
        -- Color: Pink 1
        set_color_filter_slot(1, string.lower(proto_serf.name))
    end
end

--- Handle changes to Wireshark preferences for this protocol
-- @function proto_serf.prefs_changed
function proto_serf.prefs_changed()
    dprint2("prefs_changed called")

    -- Change debug level
    default_settings.debug_level = proto_serf.prefs.debug
    reset_debug()

    -- Handle Serf LAN port change
    if default_settings.lan_port ~= proto_serf.prefs.lan_port then
        -- remove old one, if not 0
        if default_settings.lan_port ~= 0 then
            tcp_port_dissector_table:remove(default_settings.lan_port, proto_serf)
            udp_port_dissector_table:remove(default_settings.lan_port, proto_serf)
        end
        -- set our new default
        default_settings.lan_port = proto_serf.prefs.lan_port

        -- add new one, if not 0
        if default_settings.lan_port ~= 0 then
            tcp_port_dissector_table:add(default_settings.lan_port, proto_serf)
            udp_port_dissector_table:add(default_settings.lan_port, proto_serf)
        end
    end

    -- Handle Serf WAN port change
    if default_settings.wan_port ~= proto_serf.prefs.wan_port then
        -- remove old one, if not 0
        if default_settings.wan_port ~= 0 then
            tcp_port_dissector_table:remove(default_settings.wan_port, proto_serf)
            udp_port_dissector_table:remove(default_settings.wan_port, proto_serf)
        end
        -- set our new default
        default_settings.wan_port = proto_serf.prefs.wan_port

        -- add new one, if not 0
        if default_settings.wan_port ~= 0 then
            tcp_port_dissector_table:add(default_settings.wan_port, proto_serf)
            udp_port_dissector_table:add(default_settings.wan_port, proto_serf)
        end
    end
end

--- Dissector for the Serf protocol
-- Parses a Tvb to determine if it is a Serf packet
-- @function proto_serf.dissector
--
-- @tparam Tvb tvb A Testy Virtual(-izable) Buffer
-- @tparam Pinfo pinfo An object containing packet information
-- @tparam TreeItem tree An object representing the root of the packet tree
-- @treturn number The number of bytes processed by this dissector
function proto_serf.dissector(tvb, pinfo, tree)
    -- Get the length of the packet
    local buffer_length = tvb:captured_len()

    -- Skip processing of packets that are empty
    if buffer_length == 0 then
        dprint2("Skipping empty packet")
        return 0
    end

    -- Reset cursor position
    pos = 0

    -- Declare a variable to hold the compound message lengths
    -- If this is not empty, we need to process each of these messages
    local compound_message_lengths = {}

    -- Used to check if compound message lengths table is empty
    -- Declare next() as a local variable for faster performance
    -- https://stackoverflow.com/a/1252776/12384224
    local next = next

    local serf_subtree = tree:add(proto_serf, tvb())

    -- Label to jump back to in order to process the next message in the buffer
    ::process_serf_message::

    local message_type = get_bytes(tvb, sizeOf.message_type)
    local message_type_int = message_type:uint()

    if not MSG_TYPE_MAP[message_type_int] then
        -- This packet does not appear to be a Serf packet
        return 0
    end

    -- Add the message to the packet tree
    local message_tree = serf_subtree:add(proto_serf, tvb(pos - sizeOf.message_type),
        construct_serf_message_name(message_type_int))
    -- Add the message type field to the message_tree
    message_tree:add(serf_fields.message_type, message_type)

    -- Associate the protocol with the stream for future packets if it has not
    -- already been done
    if pinfo.private.existing_dissector == nil then
        dprint2("Associating packet " .. tostring(pinfo.number) .. " with the Serf protocol.")
        pinfo.conversation = proto_serf
    end
    pinfo.columns.protocol:set(proto_serf.name)

    -- Compare the integer value of the retrieved byte to the message type name
    -- table. This comparison must always be done using the most recently parsed
    -- message type, not the Fieldinfo object for the message type field because
    -- the Fieldinfo object is not updated when looping back to decode embedded
    -- messages.
    if message_type_int == MSG_TYPE_NAME_MAP.Label then
        -- Parse the label length
        message_tree:add(serf_fields.label_length, get_bytes(tvb, sizeOf.label_length))
        message_tree:add(serf_fields.label_name, get_bytes(tvb, serf_label_length_field().value))

        -- Set the size of this Tvb
        local label_header_length = sizeOf.message_type + serf_label_length_field().len +
                                        serf_label_length_field().value
        message_tree:set_len(label_header_length)

        -- Restart message processing to decode the wrapped message(s)
        goto process_serf_message
    elseif message_type_int == MSG_TYPE_NAME_MAP.Encrypt then
        -- This is an encrypted message. Process as much of the message as possible
        parse_encrypt_msg(tvb, message_tree, serf_fields)

        return buffer_length
    elseif message_type_int == MSG_TYPE_NAME_MAP.HasCRC then
        -- This message has a Checksum
        parse_hascrc_msg(tvb, message_tree, serf_fields)

        -- Restart message processing to decode the checksummed message
        goto process_serf_message
    elseif message_type_int == MSG_TYPE_NAME_MAP.Compound then
        -- This is a compound message
        compound_message_lengths = parse_compound_msg(tvb, message_tree, serf_fields)

        -- Restart message processing to decode the list of compound messages
        goto process_serf_message
    end

    local serf_payload

    -- Only grab the bytes for this compound message
    if next(compound_message_lengths) ~= nil then
        -- Get the length of the compound message
        local cp_message_len = table.remove(compound_message_lengths, 1)

        if not has_complete_compound_payload(pinfo, tvb(pos):len(), cp_message_len) then
            return
        end

        -- Set the message length to the length of the compound message
        message_tree:set_len(cp_message_len)

        -- Add Tvb to the tree. Include the message type which was just processed.
        local message_bytes = get_bytes(tvb, cp_message_len - 1)

        -- Get the payload for the compound message starting from the first
        -- byte (message type) going forward.
        serf_payload = message_bytes(sizeOf.message_type):tvb()
    else
        -- This is not a compound message. The payload is the remainder of the Tvb
        serf_payload = tvb(pos):tvb()
    end

    -- Decode MessagePack if the dissector is present and if MessagePack is
    -- referenced in the filter/tap/UI.
    if msgpack_dissector ~= nil and tree:referenced(msgpack_dissector) then
        local payload_field = message_tree:add(proto_serf, serf_payload(), "Payload (MessagePack)")
        msgpack_dissector:call(serf_payload, pinfo, payload_field)
    end

    if next(compound_message_lengths) == nil then
        -- No more compound messages remain. Return the length of the packet
        return buffer_length
    else
        -- Restart message processing to decode the next compound message
        goto process_serf_message
    end

    return false
end

-- Dissector for the Serf protocol
if default_settings.lan_port ~= 0 then
    tcp_port_dissector_table:add(default_settings.lan_port, proto_serf)
    udp_port_dissector_table:add(default_settings.lan_port, proto_serf)
end

if default_settings.wan_port ~= 0 then
    tcp_port_dissector_table:add(default_settings.wan_port, proto_serf)
    udp_port_dissector_table:add(default_settings.wan_port, proto_serf)
end
