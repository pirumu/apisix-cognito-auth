local ngx = ngx
local type = type
local sub_str = string.sub
local http = require "resty.http"
local plugin_name = "cognito-auth"
local ngx_encode_base64 = ngx.encode_base64
local ngx_decode_base64 = ngx.decode_base64
local jwt = require("resty.jwt")
local core = require("apisix.core")

local schema = {
    type = "object",
    properties = {
        header = {
            type = "string",
            default = "authorization"
        },
        query = {
            type = "string",
            default = "access_token"
        },
        cookie = {
            type = "string",
            default = "access_token"
        }
    },
}

local consumer_schema = {
    type = "object",
    properties = {
        region = { type = "string" },
        pool_id = { type = "string" },
        white_list = {
            type = "array",
            items = {
                type = "object",
                properties = {
                    method = { type = "string" },
                    path = { type = "string" },
                },
                required = { "method", "path" },
            },
            uniqueItems = true,
            default = {}
        },
        timeout = { type = "integer", minimum = 1000, default = 3000 },
        keepalive = { type = "boolean", default = true },
        keepalive_timeout = { type = "integer", minimum = 1000, default = 60000 },
        cache_ttl_seconds = { type = "integer", minimum = 1, default = 24 * 60 * 60 },
        ssl_verify = { type = "boolean", default = false }
    },
    required = { "region", "pool_id" },
}

local _M = {
    version = 0.1,
    priority = 9000,
    type = 'auth',
    name = plugin_name,
    schema = schema,
    consumer_schema = consumer_schema
}

local wrap = ('.'):rep(64)

local envelope = "-----BEGIN %s-----\n%s\n-----END %s-----\n"

function _M.check_schema(conf, schema_type)
    local ok, err
    if schema_type == core.schema.TYPE_CONSUMER then
        ok, err = core.schema.check(consumer_schema, conf)
    else
        return core.schema.check(schema, conf)
    end

    if not ok then
        return false, err
    end

    return true
end

local function auth_cognito_cache_get(shared_type, key)
    local dict = ngx.shared[shared_type]
    local value
    if dict then
        value = dict:get(key)
    end
    return value
end

local function auth_cognito_cache_set(shared_type, key, value, exp)
    local dict = ngx.shared[shared_type]
    if dict and (exp > 0) then
        dict:set(key, value, exp)
    end
end

local function http_client_configure_timeouts(httpc, timeout)
    if timeout then
        if type(timeout) == "table" then
            httpc:set_timeouts(timeout.connect or 0, timeout.send or 0, timeout.read or 0)
        else
            httpc:set_timeout(timeout)
        end
    end
end

local function http_client_configure_proxy(httpc, proxy_opts)

    if httpc and proxy_opts and type(proxy_opts) == "table" then
        httpc:set_proxy_options(proxy_opts)
    end
end

local function http_client_configure_params(params, conf)
    if conf.keepalive then
        params.keepalive_timeout = conf.keepalive_timeout
        params.keepalive_pool = conf.keepalive_pool
    else
        params.keepalive = conf.keepalive
    end

    params.ssl_verify = conf.ssl_verify

    return conf.http_request_decorator and conf.http_request_decorator(params) or params
end

local function get_http_client(conf)
    local httpc = http.new()
    http_client_configure_timeouts(httpc, conf.timeout)
    http_client_configure_proxy(httpc, conf.proxy_opts)
    return httpc
end

local function auth_cognito_parse_json_response(response)
    local err
    local res

    if response.status ~= 200 then
        err = "response indicates failure, status=" .. response.status .. ", body=" .. response.body
    else
        res, err = core.json.decode(response.body)

        if not res then
            err = "JSON decoding failed: " .. err
        end
    end

    return res, err
end

local function auth_cognito_discover(conf)

    local shared_type = "discovery"
    local json, err
    local jwks = auth_cognito_cache_get(shared_type, conf.pool_id)

    if not jwks then

        local endpoint = "https://cognito-idp." .. conf.region .. ".amazonaws.com/" .. conf.pool_id .. "/.well-known/jwks.json"

        local httpc = get_http_client(conf)

        local params = http_client_configure_params({}, conf)

        local res, error = httpc:request_uri(endpoint, params)

        if not res then
            err = "Request (" .. endpoint .. ") failed: " .. error
        else
            json, err = auth_cognito_parse_json_response(res)
            if json then
                auth_cognito_cache_set(shared_type, conf.pool_id, core.json.encode(json),
                        conf.cache_ttl_seconds)
            else
                err = "Decode failed:" .. (err and (": " .. err) or '')
            end
        end
    else
        json = core.json.decode(jwks)
    end

    return json, err
end

local function auth_cognito_ensure_discovered_data(conf)
    local err
    if type(conf.pool_id) == "string" then
        local pool_id
        pool_id, err = auth_cognito_discover(conf)
        if not err then
            conf.pool_ido = pool_id
        end
    end
    return err
end

local function encode_length(length)
    if length < 0x80 then
        return string.char(length)
    elseif length < 0x100 then
        return string.char(0x81, length)
    elseif length < 0x10000 then
        return string.char(0x82, math.floor(length / 0x100), length % 0x100)
    end
    error("Can't encode lengths over 65535")
end

local function encode_binary_integer(bytes)
    if bytes:byte(1) > 127 then
        bytes = "\0" .. bytes
    end
    return "\2" .. encode_length(#bytes) .. bytes
end

local function encode_sequence(array, of)
    local encoded_array = array
    if of then
        encoded_array = {}
        for i = 1, #array do
            if array[i] then
                encoded_array[i] = of(array[i])
            end
        end
    end
    encoded_array = table.concat(encoded_array)

    return string.char(0x30) .. encode_length(#encoded_array) .. encoded_array
end

local function encode_sequence_of_integer(array)
    return encode_sequence(array, encode_binary_integer)
end

local function encode_bit_string(array)
    local s = "\0" .. array
    return "\3" .. encode_length(#s) .. s
end

local function der2pem(data, typ)
    typ = typ:upper() or "CERTIFICATE"
    data = ngx_encode_base64(data)
    return string.format(envelope, typ, data:gsub(wrap, '%0\n', (#data - 1) / 64), typ)
end

local function get_jwk(keys, kid)
    local rsa_keys = {}

    for _, value in pairs(keys) do
        if value.kty == "RSA" and (not value.use or value.use == "sig") then
            table.insert(rsa_keys, value)
        end
    end

    if kid == nil then
        if #rsa_keys == 1 then
            return rsa_keys[1], nil
        else
            return nil, "JWT doesn't specify kid but the keystore contains multiple RSA keys"
        end
    end

    for _, value in pairs(rsa_keys) do
        if value.kid == kid then
            return value, nil
        end
    end

    return nil, "RSA key with id " .. kid .. " not found"
end

local function base64_url_decode(input)
    local reminder = #input % 4
    if reminder > 0 then
        local padlen = 4 - reminder
        input = input .. string.rep('=', padlen)
    end
    input = input:gsub('%-', '+'):gsub('_', '/')
    return ngx_decode_base64(input)
end

local function get_pem_from_rsa_n_and_e(n, e)

    local der_key = {
        base64_url_decode(n), base64_url_decode(e)
    }

    local encoded_key = encode_sequence_of_integer(der_key)

    local pem = der2pem(encode_sequence({
        encode_sequence({
            "\6\9\42\134\72\134\247\13\1\1\1"
                    .. "\5\0"
        }),
        encode_bit_string(encoded_key)
    }), "PUBLIC KEY")

    core.log.debug("Generated pem key from n and e: " .. pem)
    return pem
end

local function get_pem_from_jwk(conf, kid)
    local shared_type = "discovery"

    local err = auth_cognito_ensure_discovered_data(conf)
    if err then
        return nil, err
    end

    local jwks_cache = core.json.decode(auth_cognito_cache_get(shared_type, conf.pool_id))

    local jwk

    jwk, err = get_jwk(jwks_cache["keys"], kid)
    if err then
        return nil, err
    end

    local pem

    if jwk['kty'] == "RSA" and jwk['n'] and jwk['e'] then
        pem = get_pem_from_rsa_n_and_e(jwk['n'], jwk['e'])
    else
        return nil, "don't know how to create RSA key/cert for " .. core.json.encode(jwk)
    end

    return pem
end

local function fetch_access_token(conf, ctx)
    local token = core.request.header(ctx, conf.header)
    if token then
        local prefix = sub_str(token, 1, 7)
        if prefix == 'Bearer ' or prefix == 'bearer ' then
            return sub_str(token, 8)
        end

        return token
    end

    token = ctx.var["arg_" .. conf.query]
    if token then
        return token
    end

    local val = ctx.var["cookie_" .. conf.cookie]
    if not val then
        return nil, "JWT not found in cookie"
    end
    return val
end

local function get_unauthorized_response(msg)
    return 401, { code = "api.unauthorized", meta = { message = msg, stack = null } }
end

local function will_check_auth(conf, ctx)
    if not conf.white_list then
        return true
    end

    for _, v in pairs(conf.white_list) do
        if ctx.var.request_method == v.method and string.match(ctx.var.request_uri, v.path) ~= nil then
            return false
        end
    end

    return true
end

local function auth(conf, ctx)
    local access_token, error = fetch_access_token(conf, ctx)

    if not access_token or error then
        return get_unauthorized_response("You must be logged in to perform this action")
    end

    local decoded_payload = jwt:load_jwt(access_token)

    if not decoded_payload.valid then
        return get_unauthorized_response("Auth Token invalid")
    end

    local auth_secret, ex = get_pem_from_jwk(conf, decoded_payload.header.kid)

    if ex then
        return get_unauthorized_response("You must be logged in to perform this action")
    end

    if not auth_secret then
        return get_unauthorized_response("You must be logged in to perform this action")
    end

    local res = jwt:verify_jwt_obj(auth_secret, decoded_payload)

    if not res.verified then
        return get_unauthorized_response("You must be logged in to perform this action")
    end

    core.request.set_header(ctx, "user", core.json.encode(res.payload))
end

function _M.rewrite(conf, ctx)
    if will_check_auth(conf, ctx) then
        return auth(conf, ctx)
    end
end

return _M