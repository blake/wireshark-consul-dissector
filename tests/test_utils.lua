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

local util_file = package.searchpath("consul.util", "../src/?.lua")
local util = loadfile(util_file)()

-- Unit testing starts
local lu = require('luaunit')

TestUtils = {} -- class

function TestUtils:testNumberToHex_number()
    -- Test that util.number_to_hex correctly converts a number to a hex string
    lu.assertIsFunction(util.number_to_hex)

    -- Ensure that a number is properly converted to hex
    local result = util.number_to_hex(15)
    lu.assertIsString(result)
    lu.assertEquals(result, "0x0f")

    -- Ensure that a string representation of the number is properly encoded to
    -- hex
    local result = util.number_to_hex("16")
    lu.assertIsString(result)
    lu.assertEquals(result, "0x10")
end

function TestUtils:testDebugTable()
    -- Test that util.debug exists and is a table
    lu.assertIsTable(util.debug)
    lu.assertIsTable(util.debug.levels)

    -- Ensure that the debug levels are defined
    lu.assertItemsEquals(
        util.debug.levels,
        {DISABLED = 0, LEVEL_1 = 1, LEVEL_2 = 2}
    )
end

local runner = lu.LuaUnit.new()
runner:setOutputType("text")
os.exit( runner:runSuite() )
