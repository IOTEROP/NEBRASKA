# NEBRASKA
NEBRASKA makes connecting NB-IoT solutions to Amazon's AWS IoT Core easy

[![NEBRASKA Logo](.images/Nebraska_200-1.png)](https://ioterop.com/nebraska/)

Nebraska is a secure, reliable bridge for connecting NB-IoT solutions to Amazon’s AWS IoT Core. Nebraska uses CoAP, an NB-IoT optimized transport protocol, minimizing bandwidth requirements easing integration with the internet.


![NEBRASKA Flow](.images/Neb-Diagram.png)

# What is Nebraska?

Nebraska is IoTerop's secure bridge for connecting IoT solutions to Amazon Web Services IoT Core using CoAP. *NEBRASKA is a subset of ALASKA, IoTerop's LwM2M device management platform*.

Devices can connect to NEBRASKA using any CoAP library.

(IOTEROP interlude)

*Developers can also simplify application development by using IOTEROP's IOWA SDK. IOWA is a C library allowing developers to quickly implement CoAP for data transport and DTLS 1.2 and connection identifiers (CID), providing a secure, efficient mechanism for transferring data. Please note CoAP implementations using IOWA provides the possibility of adding LwM2M device management features, such as bootstrapping and FOTA, future-proofing solutions*.

(End of IOTEROP's interlude)

# Samples

  * linux_libcoap: Simple client, based on LibCoAP, using PSK security.
  * NRF9160 client: code for the nRF9160DK reference board, using LTE modem
  * IOWA Nebraska client: client based on IOWA C library, with bootstrap (soon...)
  * simple_script.sh: linux script to show how to provision using API

# Getting started
## Requirements
* The first step is to register an AWS account: [https://aws.amazon.com/](https://aws.amazon.com/)
* On your AWS account, you have to go to the [AWS Marketplace's Nebaska page](https://aws.amazon.com/marketplace/pp/IoTerop-Nebraska/B08PPS33V5)
* When you validate your subscription, you will be redirected to [NEBRASKA main page](https://nebraska.ioterop.com/login), and be asked for a new account creation.
* Now, you are ready to play with devices...

**Important note regarding security schemes**:
Please keep in mind that the pair *PSK_Identity/PSK_Secret* is *GLOBAL* to the Nebraska Platform. It means that if you use a *pskIdentity* name already used by a different customer, your provisioning will be rejected unless the *pskSecret* is identical to the one defined by customer B
In few words: use a complex *pskIdentity* name...

## FAQ
This repo comprises a wiki with a NEBRASKA FAQ.

To view, click the [Wiki](https://github.com/IOTEROP/NEBRASKA/wiki) link above. Or proceed directly to the [NEBRASKA Technical FAQ](https://github.com/IOTEROP/NEBRASKA/wiki/FAQ).

## Initial steps
NEBRASKA main page is mostly an informational dashboard as all the action can/must be done using API.

 ```
 ** TOKEN
 curl -v https://nebraska.ioterop-apis.com/authentication/login \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=MyNBAccount@mycompany.com" \
  -d "client_secret=MyPassword" \
  -d "grant_type=client_credentials"
 ```
you will get a token:
```
"access_token":"abcdefghiaefefecdbeeOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6WyJyZWF12331124pdGUiXSwidGVuYW50SWQiOiI1ZmY0MzFkNDRiZjUzMTA5MTVmODdlM2UiLCJleHAiE2MDk4NTU1OTYsImp0aSI6IkNaaUFfZE9TeS0xUOGutzi1PMTdNazV2LS1mYyIsImNsaWVudF9pZCI6Im9ndWl0ZXJAZnJlZS5mciJ9.BmLF7l2SbO8jYhFsdNrhMwAbnCdEfGnak",
	"token_type":"bearer",
	"expires_in":899,
	"scope":"read write",
	"tenantId":"5cabddef00123456f87e3e",
	"jti":"ABcD_gOTy-1X4eb-O12ABb5v--fc"
```
Now, we will provision two devices, using a common security scheme (here we want PSK scheme):
```
{ "common":
  { "deviceSecurity":
     { "mode": "PSK",
        "pskIdentity": "MqttIdentity",
        "pskSecret": "YWJjZGVm"
        }
  },
  "devices": [
    {"identifier": "Nebraska_client_1", "topic": "/demo/test_1"},
    {"identifier": "Nebraska_client_2", "topic": "/demo/test_2"}
    ]
}
```
(please note that *pskSecret* is base64 encoded: "abcdef" => YWJjZGVm)

We provision:
```
curl -X POST   --header 'content-type: application/json' \
  --header 'authorization: Bearer abcdefghiaefefecdbeeOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6WyJyZWF12331124pdGUiXSwidGVuYW50SWQiOiI1ZmY0MzFkNDRiZjUzMTA5MTVmODdlM2UiLCJleHAiE2MDk4NTU1OTYsImp0aSI6IkNaaUFfZE9TeS0xUOGutzi1PMTdNazV2LS1mYyIsImNsaWVudF9pZCI6Im9ndWl0ZXJAZnJlZS5mciJ9.BmLF7l2SbO8jYhFsdNrhMwAbnCdEfGnak' \
  --data '{"common": {"deviceSecurity": {"mode": "PSK", "pskIdentity": "MqttIdentity", "pskSecret": "YWJjZGVm"}},"devices": [{"identifier": "Nebraska_client_1", "topic": "/demo/test_1"},{  "identifier": "Nebraska_client_2", "topic": "/demo/test_2"}]}' \
  --url https://nebraska.ioterop-apis.com/api/v1/mqtt/provisioning
```
We immediatly receive an *operationid* to follow the achievement of the provisioning process:
```
  /api/v1/mqtt/provisioning/operations/5fabcd4350ad753c040372fe
```

..and you can use this ID to
```
curl -X GET  --header 'content-type: application/json' \
  --header 'authorization: Bearer abcdefghiaefefecdbeeOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzY29wZSI6WyJyZWF12331124pdGUiXSwidGVuYW50SWQiOiI1ZmY0MzFkNDRiZjUzMTA5MTVmODdlM2UiLCJleHAiE2MDk4NTU1OTYsImp0aSI6IkNaaUFfZE9TeS0xUOGutzi1PMTdNazV2LS1mYyIsImNsaWVudF9pZCI6Im9ndWl0ZXJAZnJlZS5mciJ9.BmLF7l2SbO8jYhFsdNrhMwAbnCdEfGnak' \
   --url https://nebraska.ioterop-apis.com/api/v1/mqtt/provisioning/operations/5fabcd4350ad753c040372fe
   ```

   As you can see, your devices are now available on your dashboard:

   ![NEBRASKA dashboard](.images/dashboard0.png)

## Registering and Publishing

![NEBRASKA dashboard](.images/nebraska_Diagram.png)
The global mechanism of NEBRASKA is divided in 2 steps:
* Registration:

  Register the device against Nebraska's server, specifying some optional values (e.g.: QoS, ...). On Registration, the client receives a handle that will be used on Publication. (CoAP: POST /CON)

* Publication:

  The CoAP message (PUT/CON) only need the Path, the Handle... and the value to be published on the MQTT broker.


Take a look at the running client (Linux), using AWS MQTT Test broker: [NEBRASKA Demo video](https://f.hubspotusercontent20.net/hubfs/1727672/Nebraska/Nebraska_show.mp4)

For any question, feel free to contact us: [IoTerop Customer Support](mailto://support@ioterop.com?subject=[Github_NBK]Informations)
