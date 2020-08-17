-- The Head Section --
description =  "Script to detect MS15-034 on HTTP port"
author = "Prajwal Panchmahalkar based on script from billbillthebillbill"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = {"default", "safe"}

local shortport = require "shortport"
local http = require "http"
local nmap = require "nmap"
local stdnse = require "stdnse"
local string = require "string"

-- The Rule Section --
portrule = shortport.http

-- The Action Section --
action = function(host, port)
    local uri="/"
    local options = {header={}}
    options['header']['Host'] = "hostattack"
    options['header']['Range'] = "bytes=0-18446744073709551615"
    local response = http.get(host, port, uri, options)
    if (response.status == 416) then
            return "Host looks to be vulnerable to MS15-0034!!"
    end
end
