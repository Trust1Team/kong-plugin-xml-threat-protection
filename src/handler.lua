local stringy = require "stringy"
local responses = require "kong.tools.responses"
local xml_validator = require "kong.plugins.xml-threat-protection.xml_validator"
local BasePlugin = require "kong.plugins.base_plugin"

local XmlTheatProtectionHandler = BasePlugin:extend()

XmlTheatProtectionHandler.PRIORITY = 500

---------------
-- Constants --
---------------

local APPLICATION_XML = "application/xml"
local CONTENT_TYPE = "content-type"

----------------------
-- Utility function --
----------------------

local function get_content_type()
    local header_value = ngx.req.get_headers()[CONTENT_TYPE]
    if header_value then
        return stringy.strip(header_value):lower()
    end
    return nil
end

---------------------------
-- Plugin implementation --
---------------------------

function XmlTheatProtectionHandler:new()
    XmlTheatProtectionHandler.super.new(self, "XML Threat Protection")
end

function XmlTheatProtectionHandler:access(config)
    XmlTheatProtectionHandler.super.access(self)

    local is_xml = stringy.startswith(get_content_type(), APPLICATION_XML)
    if is_xml then
        ngx.req.read_body()
        local body = ngx.req.get_body_data()

        if not body then
            return responses.send_OK()
        end

        xml_validator.execute(body)
    end

    return responses.send_HTTP_OK()
end

return XmlTheatProtectionHandler

