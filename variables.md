# yealink variables

## variable

| variable          | description |
|-------------------|-------------|
| $mac              | The MAC address of the IPphone. |
| $ip               | The IP address of the IP phone. |
| $model            | The IP phone model. |
| $firmware         | The firmware version of the IP phone. |
| $active_url       | The SIP URI of the current account when the IP phone places a call, receives an incoming call or establishes a call. |
| $active_user      | The user part of the SIP URI for the current account when the IP phone places a call, receives an incoming call or establishes a call. |
| $active_host      | The host part of the SIP URI for the current account when the IP phone places a call, receives an incoming call or establishes a call. |
| $local            | The SIP URI of the caller when the IP phone places a call. The SIP URI of the callee when the IP phone receives an incoming call. |
| $remote           | The SIP URI of the callee when the IP phone places a call. The SIP URI of the caller when the IP phone receives an incoming call. |
| $display_local    | The display name of the caller when the IP phone places a call. The display name of the callee when the IP phone receives an incoming call. |
| $display_remote   | The display name of the callee when the IP phone places a call. The display name of the caller when the IP phone receives an incoming call. |
| $call_id          | The call-id of the active call. |
| $callerID         | The display name of the caller when the IP phone receives an incoming call. |
| $calledNumber     | The phone number of the callee when the IP phone places a call. |
| $exp_number       | The number of connected expansion modules. |
| $ehs_number       | The number of connected EHS. |
| $udisk_number     | The number of connected USB flashdrives. |
| $usbheadset_number| The number of connected USB headset devices.|
| $wifi_number      | The number of connected Wi-Fi dongles. |
| $bluetooth_number | The number of connected Bluetooth dongles. |
| $vpn_ip           | The phone IP address assigned by the VPNserver. |
| $cfg_all          | The CFG configuration file contains all current configurations of the IP phone. Note: The valid URI is: `http://<serverIPAddress>/<filename>/?variablename=$variable value`. Example: `http://10.82.21.10/Upload/?Cfg=$cfg_all`|
| $cfg_local        | The CFG configuration file contains all non-static parameters made via the phone user interface and web user interface. Note: It works only if “static.auto_provision.custom.protect” is set to 1 (Enabled). The valid URI is: `http://<serverIPAddress>/<filename>/?variablename=$variable value`. Example: `http://10.82.21.10/Upload/?Cfg=$cfg_local` |

## ressouces

Yealink_SIP-T2_Series_T4_Series_T5_Series_CP920_IP_Phones_Administrator_Guide_V84_80.pdf

