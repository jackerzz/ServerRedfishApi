curl  https://172.31.216.58/redfish/v1/AccountService/Accounts/12  -X  GET -k  -H  "Content-type:  application/json"  -H  "Authorization:  Basic  VVNFUklEOlBBU1NXMFJE"

curl  https://172.31.216.58/redfish/v1/SessionService/Sessions  -X  GET -k  -H  "Content-type:  application/json"  -H  "X-Auth-Token:  session-auth-token"
curl  https://172.31.216.58/redfish/v1/SessionService/Sessions  -X  POST -k  -H  "Content-type:  application/json"  -d '{"UserName":"USERID", "Password": "PASSW0RD"}'
curl  https://172.31.216.58/redfish/v1/SessionService/Sessions  -X  POST -k  -H  "Content-type:  application/json"  -d '{"UserName":"USERID", "Password": "PASSW0RD"}'





"Content-type:  application/json"  -H  "X-Auth-Toke:  CCE4E07BE5BABFCB97E6BB11C7320B07842CC318" -H "Authorization: Basic VVNFUklEOlBBU1NXMFJE" -H "server: XCC Web Server" -H "location: /redfish/v1/SessionService/Sessions/28" -H "Accept: */*" -H "x-xss-protection: 1; mode=block" -H "content-security-policy: default-src" -H "x-frame-options: DENY" -H "odata-version: 4.0"





{'x-xss-protection': '1; mode=block', 'content-security-policy': "default-src 'self'; connect-src *; script-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; font-src 'self' data:; child-src 'self'; object-src 'none'", 'content-language': 'en', 'transfer-encoding': 'chunked', 'strict-transport-security': 'max-age=31536000; includeSubDomains', 'x-auth-token': '61CBC541E247688DCACDAC05A2CAF54725FA7558', 'server': 'XCC Web Server', 'connection': 'keep-alive', 'etag': '"18b270d606be16ddb34cac266eabe35b"', 'location': '/redfish/v1/SessionService/Sessions/28', 'cache-control': 'no-store, no-cache, no-store, must-revalidate, private', 'date': 'Wed, 08 Dec 2021 01:52:10 GMT', 'odata-version': '4.0', 'x-frame-options': 'DENY', 'x-content-type-options': 'nosniff', 'content-type': 'application/json'}


curl  https://172.31.216.58/redfish/v1/AccountService/Accounts/12  -d '{"UserName":"appuser1", "Password": "Huawei12#$","PasswordChangeRequired":False,"Enabled":True}' -X  PATCH -k  -H  "Content-type:  application/json"  -H  "X-Auth-Toke:  CCE4E07BE5BABFCB97E6BB11C7320B07842CC318" -H "Authorization: Basic VVNFUklEOlBBU1NXMFJE" -H "server: XCC Web Server" -H "location: /redfish/v1/SessionService/Sessions/28" -H "Accept: */*" -H "x-xss-protection: 1; mode=block" -H "content-security-policy: default-src" -H "x-frame-options: DENY" -H "odata-version: 4.0" -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/83.0.4103.116 Safari/537.36" -H 'etag: "18b270d606be16ddb34cac266eabe35b"' -H "x-content-type-options: nosniff"


curl  https://172.31.216.58/redfish/v1/schemas/registries/ExtendedError.1.1.0.json  -X  GET -k  -H  "Content-type:  application/json"  -H  "X-Auth-Token:  CCE4E07BE5BABFCB97E6BB11C7320B07842CC318"

curl -k -u admin:admin https://172.31.208.11:8080/redfish/v1/SessionService/Sessions/1 -X POST

a0b850a8ab10510c8279048f0b8c9e38
9d09d6fca1a96581b7961ec002edaed8
Ldap