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

-- This contains a list of utility functions that are shared between the various
-- dissectors and sub-dissectors in this plugin.

-- Module table to export
local util = {
    -- Debug levels
    debug = {
        levels = {
            DISABLED = 0,
            LEVEL_1 = 1,
            LEVEL_2 = 2

        }
    },

    -- Registered sub-dissectors under the 'consul' protocol
    protocol_patterns = {},
}

-- Enum for use in the protocol preferences pane to express the debug level
util.debug.pref_enum = {
    {1, "Disabled", util.debug.levels.DISABLED},
    {2, "Level 1", util.debug.levels.LEVEL_1},
    {3, "Level 2", util.debug.levels.LEVEL_2}
}

--- Get the specified number of bytes from the Tvb and advance the cursor position
-- @function util.get_bytes
--
-- @tparam Tvb tvb A Testy Virtual(-izable) Buffer
-- @tparam number length The number of bytes to get from the buffer
-- @treturn TvbRange The TvbRange of the specified number of bytes
function util.get_bytes(tvb, pos, length)
    local tvb_range = tvb:range(pos, length)
    pos = pos + length

    return tvb_range
end

--- Test if a packet is a MessagePack fixstr
-- @function util.is_msgpack_fixstr
--
-- @tparam Tvb tvb A Testy Virtual(-izable) Buffer
-- @tparam number pos The current position in the buffer
-- @treturn bool True if the packet is a MessagePack fixstr, false otherwise
function util.is_msgpack_fixstr(tvb)
    -- Check if the first nibble matches the value for a MessagePack map.
    local first_nibble = tvb:range(0, 1):bitfield(0, 3)

    -- The first 3 bits must equal the value for a MessagePack fixstr in binary
    -- (101xxxxx)
    return first_nibble == 5
end

--- Test if a packet is a MessagePack map
-- @function util.is_msgpack_map
--
-- @tparam Tvb tvb A Testy Virtual(-izable) Buffer
-- @tparam number pos The current position in the buffer
-- @treturn bool True if the packet is a MessagePack map, false otherwise
function util.is_msgpack_map(tvb)
    -- Check if the first nibble matches the value for a MessagePack map.
    local first_nibble = tvb:range(0, 1):bitfield(0, 4)

    return first_nibble == 8
end

--- Test if a packet is a MessagePack positive fixint
-- @function util.is_msgpack_pos_fixint
--
-- @tparam Tvb tvb A Testy Virtual(-izable) Buffer
-- @tparam number pos The current position in the buffer
-- @treturn bool True if the packet is a MessagePack map, false otherwise
function util.is_msgpack_pos_fixint(tvb)
    -- Check if the first bit matches the value for a MessagePack positive fixint.
    return tvb:range(0, 1):bitfield(0, 1) == 0
end

--- Convert an number to a hex string with the leading '0x'
-- @function util.number_to_hex
--
-- @tparam number An integer to convert to a hex string
-- @treturn string The converted hex string
function util.number_to_hex(number)
    return string.format("0x%02x", number)
end

local function protocol_is_registered(pattern)
    for _, value in ipairs(util.protocol_patterns) do
        if value == pattern then
            return true
        end
    end

    return false
end

--- Return an array of protocol patterns registered with the consul.protocol
-- dissector table. Used to test if a packet is a particular protocol from the
-- main dissector.
-- @function util.get_patterns_for_protocol
--
-- @tparam string protocol The name of the dissector table
-- @tparam number length The number of bytes to get from the buffer
-- @treturn TvbRange The TvbRange of the specified number of bytes
function util.register_protocol_pattern(pattern)
    -- if util.protocol_patterns[pattern] == nil then
    -- end
    if not protocol_is_registered(pattern) then
        table.insert(util.protocol_patterns, pattern)
    end
end

-- Export module
return util
