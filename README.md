# Omegle-Scapy-Geolocate

This tool uses scapy and a local Maximind db to sniff for IPs over Omegle via the STUN requests made during video chats.

Requires the Maximind Geolite2-City.mmdb file in order to geolocate the user.

#Usage

`python sniff.py /path/to/Geolite2-City.mmdb 192.168.1.2 eth0`
This can be done on Windows as well.

Argument 1 points to the Geolite2-City.mmdb file

Argument 2 points towards your local IP on your interface being used.

Argument 3 points towards your internet adapter being used.

## DO NOT USE MY CODE FOR MALICIOUS PURPOSES
