import sys
from scapy.all import *
import geoip2
from binascii import hexlify
import geoip2.database

#georeader = geoip2.database.Reader(geodata)
stunxor = ' 01 01 00 2C ' # Omegle appeared to have a consistant set of hex bytes during its STUN negotiations.
geodb = sys.argv[1]
localip = str(sys.argv[2])

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
	sniff(filter=f"src not {localip} and udp and host {localip}", prn=print_summary, iface='Ethernet')
