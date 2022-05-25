## Cognito Authentication APISIX Plugin 
### (base on: [zmartzone/lua-resty-openidc](https://github.com/zmartzone/lua-resty-openidc))
![folow](https://static.apiseven.com/202108/1643096414141-ccbc33c0-7899-445a-a2f8-b6d5341c44df.jpg)

## Config
```json
{
  "region": "ap-southeast-1",
  "pool_id": "ap-southeast-1_jkfRcWs0L",
  "white_list": [
    {
      "method": "GET",
      "path": "/stream/document"
    }
  ],
  "ssl_verify": false,
  "timeout": 3000,
  "cache_ttl_seconds": 86400,
  "keepalive": true,
  "keepalive_timeout": 60000,
}
```
## See more: [https://apisix.apache.org/docs/apisix/plugin-develop](https://apisix.apache.org/docs/apisix/plugin-develop)
