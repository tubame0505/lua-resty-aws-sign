-- generate amazon v4 authorization signature
-- Author: tubame
-- License: MIT
-- Base code: https://github.com/grosskur/lua-resty-aws


local resty_hmac = require('resty.hmac')
local resty_sha256 = require('resty.sha256')
local str = require('resty.string')

local _M = { _VERSION = '0.0.1' }

local function get_credentials ()
    local access_key = os.getenv('AWS_ACCESS_KEY_ID')
    local secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')
    local token = os.getenv('AWS_TOKEN')
    local region = os.getenv('AWS_REGION')
    return {
        access_key = access_key,
        secret_key = secret_key,
        token = token,
        region = region
    }
end

local function get_iso8601_basic(timestamp)
    return os.date('!%Y%m%dT%H%M%SZ', timestamp)
end
  
local function get_iso8601_basic_short(timestamp)
    return os.date('!%Y%m%d', timestamp)
end

local function sha256_digest_str(s)
    local h = resty_sha256:new()
    h:update(s or '')
    return str.to_hex(h:final())
end

local function get_headers(creds, host, timestamp)
    local headers_str = 'host:' .. host .. '\n'
    .. 'x-amz-date:' .. get_iso8601_basic(timestamp)
    if creds['token'] ~= nil and creds['token'] ~= '' then
        headers_str = headers_str .. '\n'
        .. 'x-amz-security-token:' .. creds['token']
    end
    return headers_str
end

local function get_signed_headers(creds, host, timestamp)
    if creds['token'] ~= nil and creds['token'] ~= '' then
        return 'host;x-amz-date;x-amz-security-token'
    end
    return 'host;x-amz-date'
end

local function get_creds_scope(creds, timestamp, service)
    return get_iso8601_basic_short(timestamp)
      .. '/' .. creds['region']
      .. '/' .. service
      .. '/aws4_request'
end


-- generate canonicalrequest hash, QueryString is not implemented.
local function get_canonicalrequest_hash(creds, timestamp, host, uri, canonical_query_string, request_method, request_body)
    local body_digest = sha256_digest_str(request_body)
    local request_str = request_method .. '\n'
      .. uri .. '\n'
      .. canonical_query_string .. '\n'
      .. get_headers(creds, host, timestamp) .. '\n\n'
      .. get_signed_headers(creds, host, timestamp) .. '\n'
      .. body_digest
    -- ngx.log(ngx.ERR, "canonical_str:" .. request_str .. "\n")
    return sha256_digest_str(request_str)
end

-- generate string to sign
local function get_string_to_sign(creds, timestamp, host, uri, service, canonical_query_string, request_method, request_body)
    return 'AWS4-HMAC-SHA256\n'
      .. get_iso8601_basic(timestamp) .. '\n'
      .. get_creds_scope(creds, timestamp, service) .. '\n'
      .. get_canonicalrequest_hash(creds, timestamp, host, uri, canonical_query_string, request_method, request_body)
end

-- generate sign key
local function get_sign_key(creds, timestamp, service)
    local k_d = resty_hmac:new('AWS4' .. creds['secret_key'], resty_hmac.ALGOS.SHA256):final(get_iso8601_basic_short(timestamp), false)
    local k_r = resty_hmac:new(k_d, resty_hmac.ALGOS.SHA256):final(creds['region'], false)
    local k_s = resty_hmac:new(k_r, resty_hmac.ALGOS.SHA256):final(service, false)
    local k_sign = resty_hmac:new(k_s, resty_hmac.ALGOS.SHA256):final('aws4_request', false)
    -- print("key:" .. 'AWS4' .. creds['secret_key'] .. "\ntime:" .. get_iso8601_basic_short(timestamp) .. "\nk_d:" .. str.to_hex(k_d))
    -- print("k_r:" .. str.to_hex(k_r))
    -- print("k_s:" .. str.to_hex(k_s))
    -- ngx.log(ngx.ERR, "k_sign:" .. str.to_hex(k_sign))
    return k_sign
end

-- get signature
local function get_signature_str(sign_key, string_to_sign)
    local auth = resty_hmac:new(sign_key, resty_hmac.ALGOS.SHA256):final(string_to_sign, false)
    return str.to_hex(auth)
end


local function _aws_get_headers(timestamp, host, uri, service, canonical_query_string, request_method, _request_body)
    local query_string = canonical_query_string or ''
    local request_body = _request_body or ''
    local creds = get_credentials()
    local sign_key = get_sign_key(creds, timestamp, service)
    local string_to_sign = get_string_to_sign(creds, timestamp, host, uri, service, query_string, request_method, request_body)
    local signature_str = get_signature_str(sign_key, string_to_sign)
    local authorization = 'AWS4-HMAC-SHA256 '
      .. 'Credential=' .. creds['access_key'] .. '/' .. get_creds_scope(creds, timestamp, service)
      .. ', SignedHeaders=' .. get_signed_headers(creds, host, timestamp)
      .. ', Signature=' .. signature_str
    return {
      authorization = authorization,
      host = host,
      amzdate = get_iso8601_basic(timestamp),
      token = creds['token']
    }
end


function _M.aws_get_headers(timestamp, host, uri, service, canonical_query_string, request_method, request_body)
    return _aws_get_headers(timestamp, host, uri, service, canonical_query_string, request_method, request_body)
end

function _M.aws_set_headers(timestamp, host, uri, service, canonical_query_string, request_method, request_body)
    local auth = _aws_get_headers(timestamp, host, uri, service, canonical_query_string, request_method, request_body)
    ngx.req.set_header('Authorization', auth['authorization'])
    ngx.req.set_header('Host', auth['host'])
    ngx.req.set_header('X-Amz-Date', auth['amzdate'])
    if auth['token'] ~= nil and auth['token'] ~= '' then
        ngx.req.set_header('X-Amz-Security-Token', auth['token'])
    end
    return auth
end

return _M
