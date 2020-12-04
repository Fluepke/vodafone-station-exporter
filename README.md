# Vodafone Station Exporter
Prometheus Exporter for the Vodafone Station (`CGA4233DE`)

## Usage
```
Usage of ./vodafone-station-exporter:
  -log.level string
    	Logging level (default "info")
  -show-metrics
    	Show available metrics and exit
  -version
    	Print version and exit
  -vodafone.station-password string
    	Password for logging into the Vodafone station (default "How is the default password calculated? mhmm")
  -vodafone.station-url string
    	Vodafone station URL. For bridge mode this is 192.168.100.1 (note: Configure a route if using bridge mode) (default "http://192.168.0.1")
  -web.listen-address string
    	Address to listen on (default "[::]:9420")
  -web.telemetry-path string
    	Path under which to expose metrics (default "/metrics")
```

## Exported metrics
* `vodafone_station_login_success_bool`: 1 if the login was successfull
* `vodafone_station_login_message_info`: Login message returned by the web interface
  - Labels: `message`
* `vodafone_station_user_info`: User name as returned by the web interface
  - Labels: `username`
* `vodafone_station_uid_info`: User id as returned by the web interface
  - Labels: `uid`
* `vodafone_station_default_password_bool`: 1 if the default password is in use
* `vodafone_station_downstream_central_frequency_hertz`: Central frequency in hertz
  - Labels: `id`, `channel_id`, `fft`, `channel_type`
* `vodafone_station_downstream_power_dBmV`: Power in dBmV
  - Labels: `id`, `channel_id`, `fft`, `channel_type`
* `vodafone_station_downstream_snr_dB`: SNR in dB
  - Labels: `id`, `channel_id`, `fft`, `channel_type`
* `vodafone_station_downstream_snr_dB`: SNR in dB
  - Labels: `id`, `channel_id`, `fft`, `channel_type`
* `vodafone_station_ofdm_downstream_start_frequency_hertz`: Start frequency
  - Labels: `id`, `channel_id_ofdm`, `fft`, `channel_type`
* `vodafone_station_ofdm_downstream_end_frequency_hertz`: End frequency
  - Labels: `id`, `channel_id_ofdm`, `fft`, `channel_type`
* `vodafone_station_ofdm_downstream_central_frequency_hertz`: Central frequency
  - Labels: `id`, `channel_id_ofdm`, `fft`, `channel_type`
* `vodafone_station_ofdm_downstream_bandwidth_hertz`: Bandwidth
  - Labels: `id`, `channel_id_ofdm`, `fft`, `channel_type`
* `vodafone_station_ofdm_downstream_power_dBmV`: Power
  - Labels: `id`, `channel_id_ofdm`, `fft`, `channel_type`
* `vodafone_station_ofdm_downstream_snr_dB`: SNR
  - Labels: `id`, `channel_id_ofdm`, `fft`, `channel_type`
* `vodafone_station_ofdm_downstream_locked_bool`: Locking status
  - Labels: `id`, `channel_id_ofdm`, `fft`, `channel_type`
* `vodafone_station_upstream_central_frequency_hertz`: Central frequency
  - Labels: `id`, `channel_id_up`, `fft`, `channel_type`
* `vodafone_station_upstream_power_dBmV`: Power
  - Labels: `id`, `channel_id_up`, `fft`, `channel_type`
* `vodafone_station_upstream_ranging_status_info`: Ranging status
  - Labels: `id`, `channel_id_up`, `fft`, `channel_type`, `status`
* `vodafone_station_firewall_status_info`: Firewall status
  - Labels: `firewall_status`
* `vodafone_station_lan_ip4_info`: LAN IPv4 info
  - Labels: `lan_ip4`
* `vodafone_station_lan_mode_info`: LAN mode info
  - Labels: `mode`
* `vodafone_station_lan_gateway_info`: LAN gateway info
  - Labels: `lan_gateway`
* `vodafone_station_lan_dhcp_enabled_bool`: LAN DHCP enabled info
* `vodafone_station_lan_mac_address_info`: LAN MAC address
  - Labels: `mac_address`
* `vodafone_station_lan_port_up_bool`: LAN port status
  - Labels: `port`
* `vodafone_station_lan_port_speed_bits_per_second`: LAN port speed in bits/second
  - Labels: `port`
* `vodafone_station_wlan_enabled_bool`: WLAN enabled info
  - Labels: `frequency`
* `vodafone_station_wlan_channel`: WLAN channel
  - Labels: `frequency`
* `vodafone_station_wlan_bandwidth_hertz`: WLAN bandwidth in Hertz
  - Labels: `frequency`
* `vodafone_station_wlan_max_speed_bits_per_second`: Max WLAN speed in bits/seconds
  - Labels: `frequency`
* `vodafone_station_wlan_ssid_info`: SSID information
  - Labels: `frequency`, `ssid`
* `vodafone_station_wlan_mac_address_info`: WLAN MAC address
  - Labels: `frequency`, `mac_address`
* `vodafone_station_wlan_security_info`: WLAN security
  - Labels: `frequency`, `security_info`
* `vodafone_station_dns_entries_count`: DNS Entries count
* `vodafone_station_aftr_info`: AFTR gateway information
  - Labels: `aftr`
* `vodafone_station_serialnumber_info`: Serial number information
  - Labels: `serial_number`
* `vodafone_station_firmwareversion_info`: Firmware vresion information
  - Labels: `firmware_version`
* `vodafone_station_hardware_type_info`: Hardware type information
  - Labels: `hardware_type`
* `vodafone_station_uptime_seconds`: Uptime in seconds
* `vodafone_station_internet_ip4_info`: Internet IPv4
  - Labels: `ip4`
* `vodafone_station_delegated_prefix_info`: Delegated prefix information
  - Labels: `prefix`
* `vodafone_station_ip_address_rt_info`: IP address RT
  - Labels: `ip`
* `vodafone_station_ip_prefix_class_info`: IP prefix class info
  - Labels: `prefix_class`
* `vodafone_station_call_end_time_epoch`: Call endtime as unix epoch
  - Labels: `port`, `id`, `external_number`, `direction`, `type`
* `vodafone_station_call_start_time_epoch`: Call starttime as unix epoch
  - Labels: `port`, `id`, `external_number`, `direction`, `type`
* `vodafone_station_status_led_enabled_bool`: Status LEDs
* `vodafone_station_software_component_info`: Information about software components
  - Labels: `name`, `version`, `licsense`
* `vodafone_station_sip_line_status_info`: Information about SIP registration status
  - Labels: `port`, `status`
* `vodafone_station_sip_line_numbers_info`: Information about phone numbers associated with SIP registration
  - Labels: `port`, `number`
* `vodafone_station_logout_success_bool`: 1 if the logout was successfull
* `vodafone_station_logout_message_info`: Logout message returned by the web interface
  - Labels: `message`

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

From here, I started the GoLang implementation, which looks as follows:
```golang
// GetLoginPassword derives the password using the given salts
func GetLoginPassword(password, salt, saltWebUI string) string {
    return DoPbkdf2NotCoded(DoPbkdf2NotCoded(password, salt), saltWebUI)
}

// Equivalent to the JS doPbkdf2NotCoded (see README.md) 
func DoPbkdf2NotCoded(key, salt string) string {
    temp := pbkdf2.Key([]byte(key), []byte(salt), 0x3e8, 0x80, sha256.New)
    return hex.EncodeToString(temp[:16])
}
```

Oh BTW, Vodafone: Performing `pbkdf2` twice won't secure an HTTP (non TLS) login.
