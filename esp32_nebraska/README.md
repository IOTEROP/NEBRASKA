
# NEBRASKA client example

This Nebraska cleint exemple is simplified adaptation of one of the
[esp-idf](https://docs.espressif.com/projects/esp-idf/en/latest/esp32/get-started/) coap client
example (adapted from [libcoap](https://github.com/obgm/libcoap) examples).

NEBRASKA client example will connect your ESP32 device to the NEBRASKA server, send off a POST request (registration),
fetch the response data from NEBRASKA server, then publish to NEBRASKA (and so, MQTT broker) on PUT request.

If the URI is prefixed with coaps:// instead of coap://, then the CoAP client will attempt to use

Please refer to [Ioterop's Nebraska](https://ioterop.com/NEBRASKA/) for more details.

## How to use example

### Configure the project

```
idf.py menuconfig
```

Example Connection Configuration  --->
 * Set WiFi SSID under Example Configuration
 * Set WiFi Password under Example Configuration
NEBRASKA sample configuration  --->
 * Set CoAP Target Uri
 * If PSK, Set CoAP Preshared Key to use in connection to the server
 * If PSK, Set CoAP PSK Client identity (username)
 * Set the client Endpoint
 * Set the topic name
 * Set expected QoS, Keepalive and Retain flag values (-1 to skip)
Component config  --->
  CoAP Configuration  --->
    * Set encryption method definition, PSK (default) or PKI
    * Enable CoAP debugging if required

### Build and Flash

Build the project and flash it to the board, then run monitor tool to view serial output:

```
idf.py build
idf.py -p PORT flash monitor
```

(To exit the serial monitor, type ``Ctrl-]``.)

See the Getting Started Guide for full steps to configure and use ESP-IDF to build projects.

## Example Output
Prerequisite: you have to register the NEBRASKA instance on AWS. You also have to provision some devices on NEBRASKA server

and you could receive data from CoAP server if succeed,
such as the following log:

```
...
I (332) wifi: mode : sta (30:ae:a4:04:1b:7c)
I (1672) wifi: n:11 0, o:1 0, ap:255 255, sta:11 0, prof:1
I (1672) wifi: state: init -> auth (b0)
I (1682) wifi: state: auth -> assoc (0)
I (1692) wifi: state: assoc -> run (10)
I (1692) wifi: connected with huawei_cw, channel 11
I (1692) wifi: pm start, type: 1

I (2582) event: sta ip: 192.168.3.89, mask: 255.255.255.0, gw: 192.168.3.1
I (6677) example_connect: Connected to HOMEG34110
I (6687) example_connect: IPv4 address: 192.168.0.47
I (6687) example_connect: IPv6 address: fe80:0000:0000:0000:260a:c4ff:feae:83f4
I (6737) Nebraska_: DNS lookup succeeded. IP=13.48.209.162
I (6757) Nebraska_: === PDU registration ===
v:1 t:CON c:POST i:2d01 {} [ Uri-Path:mqtt, Uri-Query:ep=Nebraska_client_1, Uri-Query:t=/demo/test_1, Uri-Query:qos=0, Uri-Query:ka=120, Uri-Query:rf=1 ]
v:1 t:ACK c:0.00 i:2d01 {} [ ]
v:1 t:CON c:2.01 i:86f2 {} [ Location-Path:mqtt, Location-Path:NebR ]
v:1 t:ACK c:0.00 i:86f2 {} [ ]
v:1 t:CON c:2.01 i:86f2 {} [ Location-Path:mqtt, Location-Path:NebR ]
I (7517) Nebraska_: Registration OK 2.01

I (9517) Nebraska_: === PDU Publication ===
v:1 t:CON c:PUT i:2d02 {} [ Uri-Path:mqtt, Uri-Path:NebR, Content-Format:text/plain ] :: 'si=-48 - rnd:12'
v:1 t:ACK c:0.00 i:2d02 {} [ ]
v:1 t:CON c:2.04 i:86f3 {} [ ]
I (10427) Nebraska_: Publication OK 2.04
I (12437) Nebraska_: === PDU Publication ===
v:1 t:CON c:PUT i:2d03 {} [ Uri-Path:mqtt, Uri-Path:NebR, Content-Format:text/plain ] :: 'si=-47 - rnd:0'
v:1 t:ACK c:0.00 i:2d03 {} [ ]
v:1 t:CON c:2.04 i:86f4 {} [ ]
I (13377) Nebraska_: Publication OK 2.04
...
```
## Nebraska Documentation
(Available after subscription)
[https://nebraska.ioterop.com/dashboard/documentation](https://nebraska.ioterop.com/dashboard/documentation)

## libcoap Documentation
This can be found at https://libcoap.net/doc/reference/4.2.0/

## Troubleshooting
* Please make sure Target Url includes valid `host`, optional `port`,
optional `path`, and begins with `coap://`, `coaps://` or `coap+tcp://`
for a coap server that supports TCP

* CoAP logging can be enabled by running 'idf.py menuconfig -> Component config -> CoAP Configuration' and setting appropriate log level
