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

-- Test decoding of protocols
local lu = require('luaunit')

PROTOCOL_DATA_DIR = "tshark_tests/protocol_data"

-- Whether to generate protocol data
GENERATE_DATA = false

TestProtocols = {} -- class

--- Construct the command string for generating the PCAP files from the test data
-- @function text2pcap_command
--
-- @treturn string The command string to be executed
local function text2pcap_command(arguments)
    local cmd = {
       'text2pcap',
        -- Run text2pcap with fixed source and destination IPs
       '-4',
       '192.0.20.100,192.0.2.200',
        -- Output file in pcapng format
       '-n',
        -- Silence command output
       '-q',
    }

    if type(arguments) ~= "table" then
        error("function argument must be a table")
    elseif type(arguments.protocol) ~= "string" then
        error("protocol must be 'tcp' or 'udp'")
    elseif type(arguments.pcap_file) ~= "string" then
        error("pcap_file must be set")
    elseif type(arguments.source_data) ~= "string" then
        error("source_data must be set")
    elseif type(arguments.src_port) ~= "number" then
        error("src_port must be set")
    elseif type(arguments.dst_port) ~= "number" then
        error("dst_port must be set")
    end

    if arguments.protocol == "tcp" then
        table.insert(cmd, "-T")
    elseif arguments.protocol == "udp" then
        table.insert(cmd, "-u")
    end

    -- Add src and destination ports
    table.insert(cmd, tostring(arguments.src_port) .. "," .. tostring(arguments.dst_port))

    -- Add input file to command
    table.insert(cmd, PROTOCOL_DATA_DIR .. "/source/" .. arguments.source_data)

    -- Add output filename for generated PCAP file
    table.insert(cmd, arguments.pcap_file)

    return table.concat(cmd, " ")
end

--- Construct the command string for parsing the capture file with tshark
-- @function construct_tshark_cmd
--
-- @tparam table arguments A table containing the additional arguments to the function
-- @treturn string The command string to be executed
local function construct_tshark_cmd(arguments)

    if type(arguments) ~= "table" then
        error("function argument must be a table")
    elseif type(arguments.protocols) ~= "string" then
        error("protocols must be set")
    elseif type(arguments.pcap_file) ~= "string" then
        error("pcap_file must be set")
    end

    local cmd_parts = {
        "tshark",
        -- Output the data in JSON format
        "-T",
        "json",
        -- Flush stdout immediately after each packet is printed
        "-l"
    }

    -- Add additional arguments
    -- Add list of protocols
    table.insert(cmd_parts, "-J")

    local decode_protos = arguments.protocols
    -- Append 'consul' protocol to the list if not present
    if string.find(decode_protos, "consul") == nil then
        decode_protos = "consul " .. decode_protos
    end
    table.insert(cmd_parts, "\"" .. decode_protos .. "\"")

    -- Add PCAP argument
    table.insert(cmd_parts, "-r")
    table.insert(cmd_parts, arguments.pcap_file)

    return table.concat(cmd_parts, " ")
end

local function expected_data_filename(name, protocol)
    if protocol == nil then
        return PROTOCOL_DATA_DIR .. "/expected/" .. name .. ".json"
    else
        return PROTOCOL_DATA_DIR .. "/expected/" .. name .. "-" .. protocol .. ".json"
    end
end

local function test_protocol(name, arguments)
    -- Create temporary file for pcap data
    local tmpfile = os.tmpname()

    local text2pcap_args = arguments

    -- Add additional required arguments
    arguments.pcap_file = tmpfile

    -- Track the original protocol value so that we can use it in building the
    -- resultant filename for parsed data. If protocol is nil, the protocol will
    -- be omitted from the filename.
    local original_protocol_value = arguments.protocol

    -- Default protocol to TCP if not defined
    if arguments.protocol == nil then
        arguments.protocol = "tcp"
    end

    -- Generate the pcap file
    local generate_pcap_cmd = text2pcap_command(arguments)
    local success = os.execute(generate_pcap_cmd)
    if not success then
        error("Failed to generate PCAP file")
    end

    -- Read the pcap file
    local cmd = construct_tshark_cmd{protocols=name, pcap_file=tmpfile}

    -- Append command to remove index so that packet data works on any date it
    -- is compared
    local filter_cmd = " | sed -e '/\"_index\": \".*$/d'"
    cmd = cmd .. filter_cmd

    local tshark_handle = io.popen(cmd, "r")
    local tshark_json = tshark_handle:read("*a")
    tshark_handle:close()

    -- Remove the temporary file
    os.remove(tmpfile)

    -- Replace test data if needed
    if GENERATE_DATA == true then
        io.open(expected_data_filename(name, original_protocol_value), "w"):write(tshark_json):close()
        return
    end

    local test_data_handle = io.open(expected_data_filename(name, original_protocol_value), "r")

    local test_data
    -- Ensure that the file exists and is available for reading
    if test_data_handle ~= nil then
        test_data =  test_data_handle:read("*a")
        io.close(test_data_handle)
    else
        lu.fail("Could not open test data file")
    end

    -- Check that the result is as expected
    lu.assertEquals(tshark_json, test_data)
end

function TestProtocols:testDns()
    -- DNS over TCP
    test_protocol("dns", {
        src_port=8600,
        dst_port=8600,
        source_data="dns.txt",
        protocol="tcp",
    })

    -- DNS over UDP
    test_protocol("dns", {
        src_port=8600,
        dst_port=8600,
        source_data="dns.txt",
        protocol="udp",
    })
end

function TestProtocols:testGrpc()
    test_protocol("rpcgrpc", {
        src_port=8300,
        dst_port=8300,
        source_data="rpc_grpc.txt",
    })
end

function TestProtocols:testSerfTcp()
    test_protocol("serf", {
        protocol="tcp",
        src_port=8301,
        dst_port=8301,
        source_data="serf.txt",
    })
end

function TestProtocols:testSerfUdp()
    test_protocol("serf", {
        protocol="udp",
        src_port=8301,
        dst_port=8301,
        source_data="serf.txt",
    })
end

function TestProtocols:testRaft()
    test_protocol("rpcraft", {
        src_port=8300,
        dst_port=8300,
        source_data="rpc_raft.txt",
    })
end

function TestProtocols:testYamux()
    test_protocol("yamux", {
        src_port=8300,
        dst_port=8300,
        source_data="yamux.txt",
    })
end


-- Check if arguments have been passed
if os.getenv("GENERATE_PROTOCOL_DATA") ~= nil then
    GENERATE_DATA = true
end

local runner = lu.LuaUnit.new()
runner:setOutputType("text")

os.exit( runner:runSuite() )
