local string = require "string"
require("LuaXML")

local XmlValidator = {}

-------------
-- Globals --
-------------
local nl_element
local nl_attribute
local nl_ns_prefix
local nl_pit
local st_lnd
local st_lacpe
local st_lncpe
local st_lcc
local v_text
local v_attrib
local v_ns_uri
local v_comment
local v_pid

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

--------------------------
-- Validation functions --
--------------------------

local function validateAttribute(attrib, value)
    if nl_attribute > 0 then
        if #attrib > nl_attribute then
            return false, "XMLThreatProtection[AttrNameExceeded]: Attribute name length exceeded."
        end
    end

    if v_attrib > 0 then
        if #value > v_attrib then
            return false, "XMLThreatProtection[AttrValueExceeded]: Attribute value length exceeded."
        end
    end

    return true, ""
end

local function validateXml(value)
    if type(value) == "table" then

        for k,v in pairs(value) do
            ngx.log(ngx.DEBUG, "k=" .. k)
            if k == 0 then -- TAG
                ngx.log(ngx.DEBUG, "TAG -- " .. v)
            elseif type(k) == "string" then -- Attribute
                local result, message = validateAttribute(k, value[k])
                if result == false then
                    return result, message
                end
            else
                local result, message = validateXml(v) -- recursively repeat the same procedure
                if result == false then
                    return result, message
                end
            end
        end
    else
        ngx.log(ngx.DEBUG, "VALUE " .. value)
    end

    return true, ""
end

------------------------------
-- Validator implementation --
------------------------------

function XmlValidator.execute(body,
    name_limits_element,
    name_limits_attribute,
    name_limits_namespace_prefix,
    name_limits_processing_instruction_target,
    structure_limits_node_depth,
    structure_limits_attribute_count_per_element,
    structure_limits_namespace_count_per_element,
    structure_limits_child_count,
    value_text,
    value_attribute,
    value_namespace_uri,
    value_comment,
    value_processing_instruction_data)

    nl_element = name_limits_element
    nl_attribute = name_limits_attribute
    nl_ns_prefix = name_limits_namespace_prefix
    nl_pit = name_limits_processing_instruction_target

    st_lnd = structure_limits_node_depth
    st_lacpe = structure_limits_attribute_count_per_element
    st_lnd = structure_limits_namespace_count_per_element
    st_lcc = structure_limits_child_count

    v_text = value_text
    v_attrib = value_attribute
    v_ns_uri = value_namespace_uri
    v_comment = value_comment
    v_pid = value_processing_instruction_data

    local parsedXml = xml.eval(body)

    return validateXml(parsedXml)
end

return XmlValidator
