#!/usr/bin/env python

from scapy.all import *
import binascii
from hashlib import sha1
import hmac


rtls_psk = "SECRET"
rtls_port = 1212
rtls_sta_rep_size = 44
capture_interface = "eth0"
capture_filter = "udp and dst port %i" % rtls_port




# Define the custom RTLS layer
class RTLS (Packet):
	name = "RTLS"

	fields_desc = 	[
			XBitField ("msg_type", None, 16),
			XBitField ("msg_id", None, 16),
			XBitField ("version_major", None, 8),
			XBitField ("version_minor", None, 8),
			LenField ("data_len", None),
			MACField ("ap_mac", None),
			XBitField ("padding", None, 16),
			ConditionalField (FieldLenField ("msg_nbr", None, count_of = "data"), lambda pkt: pkt.data_len > 0),
			ConditionalField (XBitField ("reserved", None, 16), lambda pkt: pkt.data_len > 0),
			ConditionalField (FieldListField ("data", None, StrFixedLenField ("station_report", None, rtls_sta_rep_size), count_from = lambda pkt: pkt.msg_nbr), lambda pkt: pkt.data_len > 0),
			StrFixedLenField ("signature", None, 21)
			]


# Bind the custom RTLS layer to UDP port 1212
bind_layers (UDP, RTLS, dport = rtls_port)
bind_layers (UDP, RTLS, sport = rtls_port)



def handle_rtls_pkt (pkt):

	# If the receive RTLS packet is a compound report, parse it
	if pkt[RTLS].msg_type == 0x14:
		parse_ar_compound (pkt)

	# If the received RTLS packet is a notification, send a ack
	elif pkt[RTLS].msg_type == 0x15:
		send_ar_ack (pkt)



def parse_ar_compound (pkt):

	# Foreach AR_STATION_REPORT
	for i in range (0, pkt[RTLS].msg_nbr):

		msg_type = pkt[RTLS].data[i].encode ("hex")[0:4]
		msg_id = pkt[RTLS].data[i].encode ("hex")[4:8]
		version_major = pkt[RTLS].data[i].encode ("hex")[8:10]
		version_minor = pkt[RTLS].data[i].encode ("hex")[10:12]
		data_length = pkt[RTLS].data[i].encode ("hex")[12:16]
		ap_mac = pkt[RTLS].data[i].encode ("hex")[16:28]
		padding = pkt[RTLS].data[i].encode ("hex")[28:32]
		mac = pkt[RTLS].data[i].encode ("hex")[32:44]
		noise_floor = pkt[RTLS].data[i].encode ("hex")[44:46]
		data_rate = pkt[RTLS].data[i].encode ("hex")[46:48]
		channel = pkt[RTLS].data[i].encode ("hex")[48:50]
		rssi = pkt[RTLS].data[i].encode ("hex")[50:52]
		type = pkt[RTLS].data[i].encode ("hex")[52:54]
		associated = pkt[RTLS].data[i].encode ("hex")[54:56]
		radio_bssid = pkt[RTLS].data[i].encode ("hex")[56:68]
		mon_bssid = pkt[RTLS].data[i].encode ("hex")[68:80]
		age = pkt[RTLS].data[i].encode ("hex")[80:88]



		print ("msg_type:\t%s" % msg_type)
		print ("msg_id:\t\t%s" % msg_id)
		print ("version_major:\t%s" % version_major)
		print ("version_minor:\t%s" % version_minor)
		print ("data_length:\t%s" % data_length)
		print ("ap_mac:\t\t%s" % ap_mac)
		print ("padding:\t%s" % padding)
		print ("mac:\t\t%s" % mac)
		print ("noise_floor:\t%s" % noise_floor)
		print ("data_rate:\t%s" % data_rate)
		print ("channel:\t%s" % channel)
		print ("rssi:\t\t%s" % rssi)
		print ("type:\t\t%s" % type)
		print ("associated:\t%s" % associated)
		print ("radio_bssid:\t%s" % radio_bssid)
		print ("mon_bssid:\t%s" % mon_bssid)
		print ("age:\t\t%s" % age)

		if (i == pkt[RTLS].msg_nbr - 2):
			print ("################################")


	print ("##############################################################")



# Forge a RTLS packet header using a received RTLS packet and a custom message type
def forge_rtls_header (pkt, msg_type):

	pkt[Ether].src, pkt[Ether].dst = pkt[Ether].dst, pkt[Ether].src
	del (pkt_ack[Ether].chksum)

	pkt_ack[IP].src, pkt_ack[IP].dst = pkt_ack[IP].dst, pkt_ack[IP].src
	del (pkt_ack[UDP].chksum)

	pkt_ack[UDP].sport, pkt_ack[UDP].dport = pkt_ack[UDP].dport, pkt_ack[UDP].sport
	del (pkt_ack[IP].chksum)

	pkt_ack[RTLS].msg_type = msg_type

	return (pkt)


	
# Send a RTLS AR_ACK corresponding to a received AR_AP_NOTIFICATION
def send_ar_ack (pkt):

	# First generate the correct RTLS header using the received AR_AP_NOTIFICATION
	pkt_ack = forge_rtls_header (pkt, 0x10)

	# TODO use pkt[RTLS] stuffs to extract the RTLS header data to sign
	# Calculate the hmac-sha1 signature of the RTLS header	
	pkt_ack[RTLS].signature = str (binascii.unhexlify (hmac.new (rtls_psk, str (pkt)[42:58], sha1).hexdigest ()))

	# Send the forged RTLS ACK
	sendp (pkt_ack, iface = capture_interface)

	return (0)






# Sniff RTLS notifications
sniff (iface = capture_interface, prn = handle_rtls_pkt, filter = capture_filter, store = 0)
