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
local v_pid

----------------------
-- Utility function --
----------------------

function string.starts(String, Start)
    return string.sub(String, 1, string.len(Start)) == Start
end

function string.trim(s)
    return (s:gsub("^%s*(.-)%s*$", "%1"))
end

--------------------------
-- Validation functions --
--------------------------

local function validatePit(pit)
    local spacePos

    if nl_pit > 0 then -- Validate the processing instruction target length
        spacePos = string.find(pit, " ")
        if spacePos then
            local tag = string.sub(pit, 0, spacePos - 1)
            if #tag > nl_pit then
                return false, "XMLThreatProtection[PITargetExceeded]: Processing Instruction target length exceeded (" .. tag .. "), max " .. nl_pit .. " allowed, found " .. #tag .. "."
            end
        end
    end

    if v_pid > 0 then
        while spacePos do
            local quotePos = string.find(pit, '"', spacePos) -- find begin quote
            quotePos = string.find(pit, '"', quotePos + 1) -- find trailing quote

            if quotePos then
                local pid = string.trim(string.sub(pit, spacePos + 1, quotePos))
                if #pid > v_pid then
                    return false, "XMLThreatProtection[PIDataExceeded]: Processing Instruction data length exceeded (" .. pid .. "), max " .. v_pid .. " allowed, found " .. #pid .. "."
                end
            end

            spacePos = string.find(pit, " ", quotePos) -- find next space
        end
    end

    return true, ""
end

local function validateNamespace(ns, value)
    if nl_ns_prefix > 0 then

        -- Check if a namespace prefix is defined
        local pos = string.find(ns, ":")
        if pos then
            local prefix = string.sub(ns, pos + 1) -- also skip the ':'
            if #prefix > nl_ns_prefix then
                return false, "XMLThreatProtection[NSPrefixExceeded]: Namespace prefix length exceeded (" .. ns .. "), max " .. nl_ns_prefix .. " allowed, found " .. #prefix .. "."
            end
        end
    end

    if v_ns_uri > 0 then
        if #value > v_ns_uri then
            return false, "XMLThreatProtection[NSURIExceeded]: Namespace uri length exceeded (" .. value .. "), max " .. v_ns_uri .. " allowed, found " .. #value .. "."
        end
    end

    return true, ""
end

local function validateAttribute(attrib, value)
    if nl_attribute > 0 then
        if #attrib > nl_attribute then
            return false, "XMLThreatProtection[AttrNameExceeded]: Attribute name length exceeded (" .. attrib .. "), max " .. nl_attribute .. " allowed, found " .. #attrib .. "."
        end
    end

    if v_attrib > 0 then
        if #value > v_attrib then
            return false, "XMLThreatProtection[AttrValueExceeded]: Attribute value length exceeded (" .. value .. "), max " .. v_attrib .. " allowed, found " .. #value .. "."
        end
    end

    return true, ""
end

local function validateElement(element)
    if nl_element > 0 then
        if #element > nl_element then
            return false, "XMLThreatProtection[ElemNameExceeded]: Element name length exceeded (" .. tag .. "), max " .. nl_element .. " allowed, found " .. #element .. "."
        end
    end

    return true, ""
end

local function validateXml(value)
    if type(value) == "table" then
        -- Validate the child count
        if st_lcc > 0 then
            if #value > st_lcc then
                return false, "XMLThreatProtection[ChildCountExceeded]: Children count exceeded, max " .. st_lcc .. " allowed, found " .. #value .. "."
            end
        end

        local namespaceCount = 0
        local attributeCount = 0
        local children = 0

        for k,v in pairs(value) do
            if k == 0 then -- TAG
                local result, message = validateElement(v)
                if result == false then
                    return result, message
                end
            elseif type(k) == "string" then
                if string.starts(k, "xmlns") then
                    namespaceCount = namespaceCount + 1
                    if st_lncpe > 0 then  -- Validate the namespace count per element
                        if namespaceCount > st_lncpe then
                            return false, "XMLThreatProtection[NSCountExceeded]: Namespace count exceeded, max " .. st_lncpe .. " allowed, found " .. namespaceCount .. "."
                        end
                    end

                    local result, message = validateNamespace(k, value[k]) -- Validate the namespace name and value
                    if result == false then
                        return result, message
                    end
                else
                    attributeCount = attributeCount + 1
                    if st_lacpe > 0 then   -- Validate the attribute count per element
                        if attributeCount > st_lacpe then
                            return false, "XMLThreatProtection[AttrCountExceeded]: Attribute count exceed, max " .. st_lacpe .. " allowed, found " .. attributeCount .. "."
                        end
                    end

                    -- Validate the attribute name and value
                    local result, message = validateAttribute(k, value[k])
                    if result == false then
                        return result, message
                    end
                end
            else
                children = children + 1
                if st_lcc > 0 then
                    if children > st_lcc then
                        return false, "XMLThreatProtection[ChildCountExceeded]: Children count exceeded, max " .. st_lcc .. " allowed, found " .. children .. "."
                    end
                end

                -- recursively repeat the same procedure
                local result, message = validateXml(v)
                if result == false then
                    return result, message
                end
            end
        end
    else
        if v_text > 0 then
            if #value > v_text then
                return false, "XMLThreatProtection[TextExceeded]: Text length exceeded (" .. value .. "), max " .. v_text .. " allowed, found " .. #value .. "."
            end
        end
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
    value_processing_instruction_data)

    nl_element = name_limits_element
    nl_attribute = name_limits_attribute
    nl_ns_prefix = name_limits_namespace_prefix
    nl_pit = name_limits_processing_instruction_target

    st_lnd = structure_limits_node_depth
    st_lacpe = structure_limits_attribute_count_per_element
    st_lncpe = structure_limits_namespace_count_per_element
    st_lcc = structure_limits_child_count

    v_text = value_text
    v_attrib = value_attribute
    v_ns_uri = value_namespace_uri
    v_pid = value_processing_instruction_data

    if string.starts(body, "<?") then
        local position = string.find(body, "?>")
        local pit = string.sub(body, 3, position - 1)
        pit = string.trim(pit)

        local result, message = validatePit(pit)
        if result == false then
            return result, message
        end
    end

    local parsedXml = xml.eval(body)
    if not parsedXml then
        return true, ""
    end

    return validateXml(parsedXml)
end

return XmlValidator
