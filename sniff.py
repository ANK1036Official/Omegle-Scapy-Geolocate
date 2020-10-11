import sys
from scapy.all import *
import geoip2
from binascii import hexlify
import geoip2.database

#georeader = geoip2.database.Reader(geodata)
stunxor = ' 01 01 00 2C ' # Omegle appeared to have a consistant set of hex bytes during its STUN negotiations.
geodb = sys.argv[1] # Argument 1 points to the Geolite2-City.mmdb file
localip = str(sys.argv[2]) # Argument 2 points towards your local IP on your interface being used.
adapter = sys.argv[3] # Argument 3 points towards your internet adapter being used.

def print_summary(pkt):
	try:
		hexpkt = hexstr(pkt, onlyhex=1)
		#print(hexpkt)
		if hexpkt.find(stunxor) != -1:
			try:
				#print(pkt[IP].src)
				geodata = reader.city(pkt[IP].src)
				if geodata is not None:
					#print(geodata)
					print(f"""
-----------------------------------------------
IP: {pkt[IP].src}
Country: {geodata.country.iso_code} ({geodata.country.name})
City: {geodata.city.name}
Subdivision: {geodata.subdivisions.most_specific.name}
""")
			except:
				pass
	except:
		pass
with geoip2.database.Reader(geodb) as reader:
	sniff(filter=f"src not {localip} and udp and host {localip}", prn=print_summary, iface=adapter)
