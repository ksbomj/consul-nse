local shortport = require "shortport"
local http = require "http"
local stdnse = require "stdnse"
local string = require "string"
local vulns = require "vulns"

description = [[
Retrieves information from a listening HashiCorp Consul.
]]

---
-- @usage
-- nmap --script consul -p <port> <host>
--
-- @output
-- PORT    STATE SERVICE
-- 8500/tcp open  unknown
-- | consul:
-- |   Version: 1.65
-- |   API Version: API-2005-Oct-18
-- |   Authorization Required: 0
-- |   Admin E-mail: admin@acarsd
-- |   Clients Connected: 1
-- |_  Frequency: 131.7250 & 131.45
--

author = "Andrii Tarykin"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery"}

portrule = shortport.port_or_service(8500, "http", {"tcp"})

function genHttpReq(host, port, try_ssl)
    local vulnPath = '/v1/agent/self'
    local req = nil
  
    local finalUri = vulnPath
    if try_ssl == true then
        stdnse.debug(1, "Making HTTPS request")
        req = http.get("https://" .. host.ip, port, finalUri)
    else
        req = http.get(host, port, finalUri)
    end
  
    --stdnse.debug(1, ("Sending GET '%s%s' request"):format(host.ip, finalUri))
  
    return req
  end

action = function(host, port)
    local req = genHttpReq(host, port, false)
    if req.status == 200 and string.match(req.body, "Config") ~= nil then
        local vulnReport = vulns.Report:new(SCRIPT_NAME, host, port)
        local vuln = {
            title = "Consul API exposed",
            state = vulns.STATE.LIKELY_VULN
        }

        return vulnReport:make_output(vuln)
    end
end