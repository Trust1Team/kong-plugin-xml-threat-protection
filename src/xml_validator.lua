local string = require "string"
require("LuaXML")

local XmlValidator = {}

----------------------
-- Utility function --
----------------------

-- Determine with a Lua table can be treated as an array.
-- Explicitly returns "not an array" for very sparse arrays.
-- Returns:
-- -1   Not an array
-- 0    Empty table
-- >0   Highest index in the array
local function is_array(table)
    local max = 0
    local count = 0
    for k, v in pairs(table) do
        if type(k) == "number" then
            if k > max then max = k end
            count = count + 1
        else
            return -1
        end
    end
    if max > count * 2 then
        return -1
    end

    return max
end

local function validateXml(value)
    if type(value) == "table" then

        for k,v in pairs(value) do
            ngx.log(ngx.DEBUG, "k=" .. k)
            if k == 0 then -- 
                ngx.log(ngx.DEBUG, "TAG -- " .. v)
            elseif type(k) == "string" then
                ngx.log(ngx.DEBUG, "ATTRIB -- " .. value[k])
            else
                validateXml(v) -- recursively repeat the same procedure
            end
        end
    else
        ngx.log(ngx.DEBUG, "VALUE " .. value)
    end
end

------------------------------
-- Validator implementation --
------------------------------

function XmlValidator.execute(body)

    local parsedXml = xml.eval(body)
    validateXml(parsedXml)
end

return XmlValidator
