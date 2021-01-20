# NEBRASKA
NEBRASKA makes connecting NB-IoT solutions to Amazon's AWS IoT Core easy

[![NEBRASKA Logo](.images/Nebraska_200-1.png)](https://ioterop.com/nebraska/)

Nebraska is a secure, reliable bridge for connecting NB-IoT solutions to Amazon’s AWS IoT Core. Nebraska uses CoAP, an NB-IoT optimized transport protocol, minimizing bandwidth requirements easing integration with the internet.



![NEBRASKA Flow](.images/Neb-Diagram.png)

# Using Nebraska?

NEBRASKA’s CoAP services have been developed by IoTerop on top of Amazon Web Services. NEBRASKA is a subset of ALASKA, IoTerop’s device management platform supporting LwM2M.

NEBRASKA can be use with or without IoTerop’s IOWA.

Creation of the CoAP client and data-feed may be done using IoTerop’s IOWA, a C library allowing developers to quickly implement CoAP for data transport as well as DTLS and connection identifiers (CID).
Code samples are available on the IOWA GitHub page.

Please note once the CoAP client has been implemented, IOWA may be used to add additional LwM2M device management features.

# Samples

  * linux_libcoap: Simple client, based on LibCoAP, using PSK security.
  * NRF9160 client: code for the nRF9160DK reference board, using LTE modem (soon...)
  * IOWA Nebraska client: client based on IOWA C library, with bootstrap (soon...)
