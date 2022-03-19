# lua-resty-aws-sign
AWS signature V4 library for OpenResty

## Overview

This library implements request signing using the [AWS Signature
Version 4][aws4] specification. This signature scheme is used by
nearly all AWS services.

## Example
```nginx
# nginx.conf
env AWS_ACCESS_KEY_ID;
env AWS_SECRET_ACCESS_KEY;
env AWS_TOKEN;
env AWS_REGION;
```

```nginx
# default.conf
# proxy API Gateway (/api/{APIGW_ID}/path/to/your/api)
location /api/ {
    client_body_buffer_size 16k;

    set $api_prefix '^/api/';
    set $apigw_service 'execute-api';
    set $proxy_uri '';
    access_by_lua_block {
        -- AWS V4 Signature
        ngx.req.read_body()
        local body_data = ngx.req.get_body_data() or ""
        local target_uri = string.gsub(ngx.var.uri, ngx.var.api_prefix, "")  -- {APIGW_ID}/path/to/your/api
        local apigw_id = string.gsub(target_uri, "/.*", "")  -- {APIGW_ID}
        local apigw_host = apigw_id .. "." .. ngx.var.apigw_service .. "." .. os.getenv('AWS_REGION') .. ".amazonaws.com"  -- {APIGW_ID}.execute-api.your-region.amazonaws.com
        local api_uri = string.gsub(target_uri, apigw_id, "")  -- /path/to/your/api
        local auth = require("resty.aws-sign").aws_set_headers(tonumber(ngx.time()), apigw_host, api_uri, ngx.var.apigw_service, ngx.var.query_string, ngx.var.request_method, ngx.req.get_body_data())

        -- set Proxy URI
        ngx.var.proxy_uri = "https://" .. apigw_host .. api_uri .. ""
    }
    proxy_pass $proxy_uri$is_args$args;
}
```

[aws4]: http://docs.aws.amazon.com/general/latest/gr/signature-version-4.html
