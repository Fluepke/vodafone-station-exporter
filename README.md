# Vodafone Station Exporter
Prometheus Exporter for the Vodafone Station CGA4233DE.

## Reverse Engineering the login mechanism
> I am not a Javascript engineer, but it works :man_shrugging:

Logging into the PHP application running on the CGA4233DE is made as complicated as possible.

From the console we see:
```bash
curl 'http://192.168.100.1/api/v1/session/login' \
  -H 'Connection: keep-alive' \
  -H 'Accept: */*' \
  -H 'X-CSRF-TOKEN: ' \
  -H 'X-Requested-With: XMLHttpRequest' \
  -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' \
  --data-raw 'username=admin&password=seeksalthash' \
  --compressed \
  --insecure
```

> CSRF seems broken, lol. Whatever - we don't care.

reply is
```json
{"error":"ok","salt":"<something>","saltwebui":"<something_else>"}
```

For the actual login a derived token derived from the actual password is used:
```
curl 'http://192.168.100.1/api/v1/session/login' \
  -H 'Connection: keep-alive' \
  -H 'Accept: */*' \
  -H 'X-CSRF-TOKEN: ' \
  -H 'X-Requested-With: XMLHttpRequest' \
  -H 'Content-Type: application/x-www-form-urlencoded; charset=UTF-8' \
  -H 'Cookie: <some PHP session cookie>' \
  --data-raw 'username=admin&password=<something that is not my password>' \
  --compressed \
  --insecure
```

Looking at the obfuscated JavaShit (`login.js`), we see something like follows:
```js
doPbkdf2NotCoded(doPbkdf2NotCoded("<password>", "<salt>"), "<saltwebui>")
```

quick check reveals: Yes, that returns the token used for the login. :heavy_check_mark:

Ok, so what does `doPbkdf2NotCoded` do?

```js
function doPbkdf2NotCoded(_0x365ad6, _0x470596) {
    var _0x51b261 = sjcl[_0x5bfa('0x10')][_0x5bfa('0x11')](_0x365ad6, _0x470596, 0x3e8, 0x80);
    var _0x279f24 = sjcl[_0x5bfa('0xc')][_0x5bfa('0x12')]['fromBits'](_0x51b261);
    return _0x279f24;
}
```
easy, isn't it? %)
Turns out, `sjcl` is not yet another obfuscated JS function, but this [thingie](https://github.com/bitwiseshiftleft/sjcl).

Translated to something slightly more human readable (using the JS console)
```js
function whatTheFuck(param1, param2) {
    //                                a,      b,      c,     d
    var temp = sjcl["misc"]["pbkdf2"](param1, param2, 0x3e8, 0x80)
    return sjcl["codec"]["hex"]["fromBits"](temp)
}
```

From here, I started the GoLang implementation.
