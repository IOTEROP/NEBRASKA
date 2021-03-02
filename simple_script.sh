#!/bin/sh

# ----------------------------------------------------------
# Very simple script to provision devices on Nebraska using PSK
# (c) IoTerop 2021
# ! this script requires jq to process JSON request
#
# IMPORTANT:
# The pair PSK_Identity/PSK_Secret is global to the Nebraska Platform
# that's why you have to use your own identity/secret. If the PSK_Identity
# is already used (with a different secret), the provisioning request
# will return an error
# ----------------------------------------------------------

# Your Nebraska identifier
# TODO: change with your own credentials
user_login="YouNebraskaLogin"
user_password="YourNebraskaSecret"

# TODO: change with your own PSK Identity and Key
# ! psk_secret is base64-encoded !
psk_identity="MyGroupIdentity_3762"
psk_secret="YWJjZGVm"

site_url="https://nebraska.ioterop-apis.com"

#-------------------------------
# Get a valid token
echo "\nRetrieving token"
token=$(curl -s https://nebraska.ioterop-apis.com/authentication/login \
--header "Content-Type: application/x-www-form-urlencoded" \
--data-urlencode "client_id=$user_login" \
--data-urlencode "client_secret=$user_password" \
--data "grant_type=client_credentials" | jq -r '.access_token')

echo "-- Token ------------------"
if [ "$token" = "null" ]; then
  echo "The token is not valid - Maybe an invalid credential ?"
  exit 2
else
  echo $token
fi
echo "\n"

#-------------------------------
#Example: Get list of provisioned devices
devlist=$(curl -s https://nebraska.ioterop-apis.com/api/v1/mqtt/devices \
  --request GET \
  --header "Authorization: Bearer $token" \
  --header "accept: application/json")

echo " -- Provisioned devices -------------"
echo $devlist | jq '.'
echo "\n"


#-------------------------------
# Provision devices
provision_request=$(curl -s https://nebraska.ioterop-apis.com/api/v1/mqtt/provisioning \
  --request POST \
  --header "Authorization: Bearer $token" \
  --header "content-type: application/json" \
  --data "{\"common\": { \
    \"deviceSecurity\": {\"mode\": \"PSK\", \"pskIdentity\": \"$psk_identity\", \"pskSecret\": \"$psk_secret\"}}, \
    \"devices\": [ \
       {\"identifier\": \"MyAirSensor_1_35345\", \"topic\": \"/demo/test_1\"}, \
       {\"identifier\": \"MyAirSensor_2_234543\", \"topic\": \"/demo/test_1\"}  \
       ]}")

echo " -- Operation ID -------------"
echo $provision_request
echo "\n"

#-------------------------------
# Retrieve Operation status
provision_status=$(curl -s $site_url$provision_request
  --request GET \
  --header "Authorization: Bearer $token" \
  --header "content-type: application/json" )

echo " -- Operation Status -------------"
echo $provision_status | jq '.'
echo "\n"

exit 0
