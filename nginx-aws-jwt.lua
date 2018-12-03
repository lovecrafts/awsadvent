local http = require "resty.http"

local M = {}

function M.auth(options)

    if type(options.valid_domains) ~= "string" then
        options.valid_domains = 'mycorp.com,myparentcorp.com'
    end
    if type(options.auth_req) ~= "boolean" then
        options.auth_req = true
    end

    local data_header = ngx.var.http_x_amzn_oidc_data

    if data_header == nil and options.auth_req then
        ngx.log(ngx.INFO, "No X-Amzn-Oidc-Data header")
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    elseif data_header == nil then
        ngx.log(ngx.INFO, "No X-Amzn-Oidc-Data header")
        return
    end

    local httpc = http.new()
    httpc:set_timeouts(200, 200, 750) -- connect, send, read in ms
    local res, err = httpc:request_uri("http://127.0.0.1:8123/", {
        method = "GET",
        headers = {
            ["X-Amzn-Oidc-Data"] = data_header,
            ["X-LC-Valid-Domains"] = options.valid_domains,
            ["X-Real-Ip"] = ngx.var.remote_addr,
        }
    })
    if not res and options.auth_req then
        ngx.log(ngx.ERR, "Unable to validate X-Amzn-Oidc-Data header: ".. err)
        ngx.exit(ngx.HTTP_SERVICE_UNAVAILABLE)
    elseif not res then
        ngx.log(ngx.WARN, "Unable to validate X-Amz-Oidc-Data header: ".. err)
        return
    end
    if res.status == 200 then
        for k,v in pairs(res.headers) do
            ngx.log(ngx.INFO, "awsjwtauth header: "..k..": "..v)
            if string.find(k, 'X-Auth-') then
                ngx.req.set_header(k, v)
                ngx.log(ngx.INFO, "Set header on request: "..k)
            end
        end
    elseif options.auth_req then
        ngx.log(ngx.ERR, "Invalid user/data in  X-Amzn-Oidc-Data header: "..res.body)
        ngx.exit(ngx.HTTP_UNAUTHORIZED)
    else
        ngx.log(ngx.INFO, "Invalid user/data in  X-Amzn-Oidc-Data header: "..res.body)
    end
end

return M
