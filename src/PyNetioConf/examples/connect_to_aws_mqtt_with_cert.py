from PyNetioConf import NetioManager
import requests
# import json # Only needed if reading MQTT configuration from a file

# Create an instance of the device we want to connect to the AWS IoT cloud.

DEVICE_IP = "192.168.1.17"
USERNAME = "admin"
PASSWORD = "admin"


nm = NetioManager()
netio_device = nm.init_device(DEVICE_IP, USERNAME, PASSWORD)

# To connect to AWS we're going to need valid certificates from AWS uploaded to the device first
# For this I'm going to assume the contents of the connect package you can download from AWS, but
# you can easily use the manually downloaded keys/certificates.

PRIVATE_KEY_PATH = "/path/to/private.key"
DEVICE_CERTIFICATE_PATH = "/path/to/device/cert.pem"
# ROOT_CA_CERTIFICATE_PATH = "/path/to/root/ca.pem" # Root CA can be downloaded directly from Amazon

# Upload the device key and certificate we get from the connection package
with open(PRIVATE_KEY_PATH, "rt") as private_key:
    key = private_key.read()
    netio_device.upload_mqtt_client_key(key)

with open(DEVICE_CERTIFICATE_PATH, "rt") as device_cert:
    certificate = device_cert.read()
    netio_device.upload_mqtt_client_certificate(certificate)

# To upload the Amazon CA certificate, we're going to download it from Amazon's cloud, but
# the same procedure as the device key/certificate could be used if you have the file downloaded
root_ca = requests.get("https://www.amazontrust.com/repository/AmazonRootCA1.pem").text
netio_device.upload_mqtt_ca_certificate(root_ca)

# Now that we have the certificates in place, we need to enable the MQTT protocol and set our configuration
# To do this we can either load a configuration from a file, or use on in place, for this example I'm going
# to use a dict, so it can be contained in a single file

# MQTT_CONFIG_PATH = "/path/to/config.json"
# device_config = json.load(MQTT_CONFIG_PATH) # Use this if you have a configuration file

MQTT_BROKER = "mqtt.broker.address.com"

# Please make sure that your configuration is valid, and that the clientid and topics match your policies
# if you have any policies active on AWS.
device_config = {
  "broker": {
    "clientid": "netio${DEVICE_SN}",
    "keepalive": 30,
    "password": "",
    "port": 8883,
    "protocol": "mqtt",
    "ssl": True,
    "type": "generic",
    "url": MQTT_BROKER,
    "username": "",
    "clientcert": True
  },
  "publish": [
    {
      "events": [
        {
          "source": "OUTPUTS/1/STATE",
          "type": "change"
        }
      ],
      "payload": "${INOUT_STATUS}",
      "qos": 0,
      "retain": False,
      "topic": "devices/${DEVICE_NAME}/messages/devicebound/"
    }
  ],
  "subscribe": [
    {
      "action": "${payload}",
      "qos": 0,
      "target": "REST_JSON",
      "topic": "devices/${DEVICE_NAME}/messages/events/"
    }
  ]
}

# Now we upload the config to the device and enable the MQTT protocol
netio_device.set_mqttflex_state(True, device_config)

# That's it, we now have a device connected to Amazon's IoT cloud
