.. _nrf_coap_client_sample:

nRF9160: NEBRASKA Client
########################

.. contents::
   :local:
   :depth: 2

The NEBRASK Client sample demonstrates the communication between the NEBRASKA server and an nRF9160 SiP that acts as the NEBRASKA client ( `NEBRASKA site <https://ioterop.com/nebraska_release>`_ )

Overview
********

The NEBRASKA Client performs the following actions:

#. Connect to the configured NEBRASKA server (specified by the Kconfig parameters ``CONFIG_NEBRASKA_SERVER_HOSTNAME`` and ``CONFIG_NEBRASKA_SERVER_PORT``).
#. As, in this sample, we use a PSK scheme, the Identity and the key must be specified (``CONFIG_NEBRASKA_DEMO_PSK_IDENTITY`` and ``CONFIG_NEBRASKA_DEMO_PSK_KEY``).
#. Send an initial POST request on a specific Topic (``CONFIG_NEBRASKA_DEMO_TOPIC``), Endpoint Client (``CONFIG_NEBRASKA_DEMO_CLIENT``). Some additional (and optional) parameters are defined in the source code.
#. The NEBRASKA server replies with a handle
#. Then, we send periodic PUT request on the handle/path with a demo value
#. The  demo value can be seen on AWS MQTT test console.


Requirements
************
  #. AWS account: `<https://aws.amazon.com>`_
  #. Subscription to NEBRASKA service: `<https://aws.amazon.com/marketplace/pp/IoTerop-Nebraska/B08PPS33V5>`_
  #. Some provisioned devices on NEBRASKA: see here `README <https://github.com/IOTEROP/NEBRASKA/blob/main/README.md>`_
  #. nrf9160DK reference board
