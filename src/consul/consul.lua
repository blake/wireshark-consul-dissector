--[[
Consul RPC dissector

This plugin attempts to identify and dissect various protocols that are
multiplexed over Consul's RPC port.

### Installation ###
Place in:
%PROGRAMFILES%\Wireshark\plugins\ (Windows)
$HOME/.local/lib/wireshark/plugins/ (Unix)
--

TODO: Add support for the following protocols:

0x00 = RPCConsul
0x02 = RPCMultiplex (Muxado)

]]

-- Set plugin version information
set_plugin_info({
    author = "Blake Covarrubias <blake@covarrubi.as>",
    description = [[
    Wireshark plugin for dissecting HashiCorp Consul's RPC communication.
    ]],
    repository = "https://github.com/blake/wireshark-consul-dissector.git",
    version = "0.0.1"
})

-- Import utility functions
package.prepend_path("plugins/consul")
local util = require("util")

-- Create a new protocol in Wireshark
-- (name, description)
local proto_consul = Proto("Consul", "Consul RPC Protocol")

local consul_fields = {
    protocol = ProtoField.protocol("consul.protocol", "Protocol", base.NONE)
}

-- Add the defined fields to the protocol
proto_consul.fields = consul_fields

-- Debug log levels
local debug_levels =  util.debug.levels

local default_settings = {
    debug_level = debug_levels.DISABLED,
    heuristic_enabled = false, -- Whether heuristic dissection is enabled
    rpc_port = 8300,
    dns_port = 8600,
    http_port = 8500,
    https_port = 8501,
    grpc_port = 8502,
}

-- Set up debugging functions
function dprint(...) end
function dprint2(...) end
local reset_debug = function()
    if default_settings.debug_level > debug_levels.DISABLED then
        dprint = function(...)
            print(table.concat({"Lua (Consul):", ...}, " "))
        end

        if default_settings.debug_level > debug_levels.LEVEL_1 then
            dprint2 = dprint
        end
    end
end
reset_debug()

proto_consul.prefs.dns_port = Pref.uint("DNS port number", default_settings.dns_port,
    "The TCP/UDP port number for Consul's DNS traffic")
proto_consul.prefs.http_port = Pref.uint("HTTP port number", default_settings.http_port,
    "The TCP/UDP port number for Consul's HTTP API")
proto_consul.prefs.https_port = Pref.uint("HTTPS port number", default_settings.https_port,
    "The TCP/UDP port number for Consul's HTTPS API")
proto_consul.prefs.grpc_port = Pref.uint("gRPC port number", default_settings.grpc_port,
    "The TCP/UDP port number for Consul's gRPC/xDS server")
proto_consul.prefs.rpc_port = Pref.uint("RPC port number", default_settings.rpc_port,
    "The TCP port number for Consul's RPC traffic")
proto_consul.prefs.heuristic = Pref.bool("Heuristic enabled", default_settings.heuristic_enabled,
"Whether heuristic dissection is enabled for the sub-protocols.")
proto_consul.prefs.debug = Pref.enum("Debug level", default_settings.debug_level, "The debug level verbosity", util.debug.pref_enum)

-- Dissector tables
-- Create a dissector table for Consul's sub-protocols to register with
local consul_dissector_table = DissectorTable.new("consul.protocol", "Consul", ftypes.STRING, base.HEX, proto_consul)
local tcp_port_dissector_table = DissectorTable.get("tcp.port")
local udp_port_dissector_table = DissectorTable.get("udp.port")

--- Handle changes to Wireshark preferences for this protocol
-- @function proto_consul.prefs_changed
function proto_consul.prefs_changed()
    dprint2("prefs_changed called")

    -- Change debug level
    default_settings.debug_level = proto_consul.prefs.debug
    reset_debug()

    -- Change heuristic detection setting
    default_settings.heuristic_enabled = proto_consul.prefs.heuristic

    -- Handle RPC port change
    if default_settings.rpc_port ~= proto_consul.prefs.rpc_port then
        -- remove old one, if not 0
        if default_settings.rpc_port ~= 0 then
            tcp_port_dissector_table:remove(default_settings.rpc_port, proto_consul)
        end
        -- set our new default
        default_settings.rpc_port = proto_consul.prefs.rpc_port

        -- add new one, if not 0
        if default_settings.rpc_port ~= 0 then
            tcp_port_dissector_table:add(default_settings.rpc_port, proto_consul)
        end
    end

    -- Handle DNS port change
    if default_settings.dns_port ~= proto_consul.prefs.dns_port then
        local dns = Dissector.get("dns")

        -- remove old one, if not 0
        if default_settings.dns_port ~= 0 then
            tcp_port_dissector_table:remove(default_settings.dns_port, dns)
            udp_port_dissector_table:remove(default_settings.dns_port, dns)
        end
        -- set our new default
        default_settings.dns_port = proto_consul.prefs.dns_port

        -- add new one, if not 0
        if default_settings.dns_port ~= 0 then
            tcp_port_dissector_table:add(default_settings.dns_port, dns)
            udp_port_dissector_table:add(default_settings.dns_port, dns)
        end
    end

    -- Handle HTTP port change
    if default_settings.http_port ~= proto_consul.prefs.http_port then
        local http_tcp = Dissector.get("http-over-tcp")

        -- remove old one, if not 0
        if default_settings.http_port ~= 0 then
            tcp_port_dissector_table:remove(default_settings.http_port, http_tcp)
        end
        -- set our new default
        default_settings.http_port = proto_consul.prefs.http_port

        -- add new one, if not 0
        if default_settings.http_port ~= 0 then
            tcp_port_dissector_table:set(default_settings.http_port, http_tcp)
        end
    end

    -- Handle HTTPS port change
    if default_settings.https_port ~= proto_consul.prefs.https_port then
        local http_tls = Dissector.get("http-over-tls")

        -- remove old one, if not 0
        if default_settings.https_port ~= 0 then
            tcp_port_dissector_table:remove(default_settings.https_port, http_tls)
        end
        -- set our new default
        default_settings.https_port = proto_consul.prefs.https_port

        -- add new one, if not 0
        if default_settings.https_port ~= 0 then
            tcp_port_dissector_table:set(default_settings.https_port, http_tls)
        end
    end

    -- Handle gRPC port change
    if default_settings.grpc_port ~= proto_consul.prefs.grpc_port then
        local http2 = Dissector.get("http2")

        -- remove old one, if not 0
        if default_settings.grpc_port ~= 0 then
            tcp_port_dissector_table:remove(default_settings.grpc_port, http2)
        end
        -- set our new default
        default_settings.grpc_port = proto_consul.prefs.grpc_port

        -- add new one, if not 0
        if default_settings.grpc_port ~= 0 then
            tcp_port_dissector_table:set(default_settings.grpc_port, http2)
        end
    end
end

-- Test whether this is a RPC packet on port the configured RPC port
-- @tparam Pinfo pinfo An object containing packet information
-- @treturn boolean True if the packet is a RPC packet on the configured RPC port, otherwise false
local function is_consul_rpc(pinfo)
    local tcp_proto = 2

    -- Check if protocol is TCP and destination port is Consul's RPC port
    return (pinfo.port_type == tcp_proto) and
               (pinfo.match_uint == default_settings.rpc_port)
end

--- Initialization function for this protocol
-- @function proto_consul.init
function proto_consul.init()
    if default_settings.rpc_port ~= 0 then
        tcp_port_dissector_table:add(default_settings.rpc_port, proto_consul)
        tcp_port_dissector_table:add_for_decode_as(proto_consul)
    end

    -- Allow Consul to dissect well-known protocols for HTTP and DNS
    if default_settings.dns_port ~= 0 then
        local dns = Dissector.get("dns")
        udp_port_dissector_table:add(default_settings.dns_port, dns)
        tcp_port_dissector_table:add(default_settings.dns_port, dns)
    end

    if default_settings.http_port ~= 0 then
        local http_tcp = Dissector.get("http-over-tcp")
        tcp_port_dissector_table:set(default_settings.http_port, http_tcp)
    end

    if default_settings.https_port ~= 0 then
        local http_tls = Dissector.get("http-over-tls")
        tcp_port_dissector_table:set(default_settings.https_port, http_tls)
    end

    if default_settings.grpc_port ~= 0 then
        local http2 = Dissector.get("http2")
        tcp_port_dissector_table:set(default_settings.grpc_port, http2)
    end
end

--- Dissector for the Consul protocol
-- Parses a Tvb to determine if it is a Consul RPC packet or one of its
-- multiplexed protocols.
-- @function proto_consul.dissector
--
-- @tparam Tvb tvb A Testy Virtual(-izable) Buffer
-- @tparam Pinfo pinfo An object containing packet information
-- @tparam TreeItem tree An object representing the root of the packet tree
-- @treturn number The number of bytes processed by this dissector
function proto_consul.dissector(tvb, pinfo, tree)
    -- Get length of Tvb
    local buffer_length = tvb:captured_len()

    -- Skip processing of packets that are empty
    if buffer_length == 0 then
        return 0
    end

    -- Return if the Consul dissector table is not available
    if consul_dissector_table == nil then
        return 0
    end

    -- Stop processing packet if it is not destined to Consul's RPC port.
    -- This should be unnecessary because this dissector is only attached to the
    -- configured RPC port, but it's a safety check.
    if not is_consul_rpc(pinfo) then
        dprint2("Packet " .. pinfo.number .. "is not a Consul RPC packet.")
        return 0
    end

    -- If the payload length is 1 byte, this is likely a new TCP stream that
    -- will indicate the RPC type at the beginning of the payload.
    if buffer_length == 1 then
        local subtree = tree:add(proto_consul, tvb(), "Consul RPC")

        local peek_byte = tvb:range(0, 1):uint()
        local proto_pattern = util.number_to_hex(peek_byte)

        -- Attempt to retrieve the registered dissector for this RPC type
        return consul_dissector_table:try(proto_pattern, tvb, pinfo, subtree)
    end

    -- These packets are not part of existing connections that have already been
    -- established. Try to determine the packet type by performing a more in-depth
    -- dissection of the packet.

    -- Iterate through the the registered sub-dissectors to see if this packet
    -- matches one of those dissectors
    -- TODO: Fix this. Its buggy and sometimes detects protocols multiplexed in Yamux as MsgPack
    if default_settings.heuristic_enabled then
        for _, p in ipairs(util.protocol_patterns) do
            local dissected_bytes = consul_dissector_table:try(p, tvb, pinfo, tree)

            -- Be wary if the dissector returns byte lengths equal to the length
            -- of the packet
            dprint("Dissected " .. dissected_bytes .. " bytes" .. " using pattern " .. p)

            if dissected_bytes > 0 and dissected_bytes ~= buffer_length then
                return dissected_bytes
            end
        end
    end
end
