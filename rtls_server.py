#!/usr/bin/env python

from scapy.all import *
import binascii
import hmac
from hashlib import sha1
from time import time
from threading import Thread
from Queue import Queue
import MySQLdb
import sys


# TO DO: could be fine to parse a JSON file to fetch the value of those parameters
rtls_psk = "SECRET"
rtls_sta_rep_size = 44
rtls_port = 1212

# Set the capture parameters
capture_interface = "eth0"
capture_filter = "udp and dst port %i" % rtls_port

# DB connection setup stuff
db_user = 'rtls'
db_pass = 'SECRET'
db_data = 'rtls'
db_con = MySQLdb.connect (user = db_user, passwd = db_pass, db = db_data)
db_cur = db_con.cursor ()



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



# Convert a HEX data rate into it's numeric value
def convert_data_rate (hex_dr):

	d_match = 	{
				'00': '1',
				'01': '2',
				'02': '5.5',
				'03': '6',
				'04': '9',
				'05': '11',
				'06': '12',
				'07': '18',
				'08': '24',
				'09': '36',
				'0a': '48',
				'0b': '54',
				'ff': 'Meh?'
			}
	
	return (d_match[hex_dr])



def handle_rtls_pkt (pkt):

	# If the receive RTLS packet is a compound report, parse it
	if pkt[RTLS].msg_type == 0x14:
		parse_ar_compound (pkt)

	# If the received RTLS packet is a notification, send a ack
	elif pkt[RTLS].msg_type == 0x15:
		send_ar_ack (pkt)



def parse_ar_compound (pkt):

	timestamp = time ()

	# Foreach AR_STATION_REPORT
	for i in range (0, pkt[RTLS].msg_nbr):

		d_connection = {}
		d_ap = {}

		d_connection['timestamp'] = int (timestamp)
		d_connection['data_length'] = pkt[RTLS].data[i].encode ("hex")[12:16]
		d_connection['ap_mac'] = pkt[RTLS].data[i].encode ("hex")[16:28]
		d_ap['mac'] = pkt[RTLS].data[i].encode ("hex")[16:28]
		d_connection['padding'] = pkt[RTLS].data[i].encode ("hex")[28:32]
		d_connection['client_mac'] = pkt[RTLS].data[i].encode ("hex")[32:44]
		d_connection['noise_floor'] = int (pkt[RTLS].data[i].encode ("hex")[44:46], 16) - 256
		d_connection['data_rate'] = convert_data_rate (pkt[RTLS].data[i].encode ("hex")[46:48])
		d_connection['channel'] = int (pkt[RTLS].data[i].encode ("hex")[48:50], 16)
		d_connection['rssi'] = int (pkt[RTLS].data[i].encode ("hex")[50:52], 16) - 256
		d_connection['associated'] = int (pkt[RTLS].data[i].encode ("hex")[54:56], 16) % 2
		d_ap['radio_bssid'] = pkt[RTLS].data[i].encode ("hex")[56:68]
		d_ap['mon_bssid'] = pkt[RTLS].data[i].encode ("hex")[68:80]
		d_connection['age'] = int (pkt[RTLS].data[i].encode ("hex")[80:88], 16)

		# TODO: find a better way to handle dictionaries for SQL insert statements
		insert_db ("INSERT INTO ap (mac, radio_bssid, mon_bssid) VALUES (%(mac)s, %(radio_bssid)s, %(mon_bssid)s)", d_ap)
		insert_db ("INSERT INTO connection (timestamp, client_mac, ap_mac, age, associated, channel, data_rate, rssi, noise_floor) VALUES (%(timestamp)s, %(client_mac)s, %(ap_mac)s, %(age)s, %(associated)s, %(channel)s, %(data_rate)s, %(rssi)s, %(noise_floor)s)", d_connection)

	db_con.commit ()
	return (0)


def insert_db (sql, dict):

		try:
			db_cur.execute (sql, dict)

		# TODO: properly handle mySQL exceptions
		except Exception as e:
			pass



# Forge a RTLS packet header using a received RTLS packet and a custom message type
def forge_rtls_header (pkt, msg_type):

	pkt[Ether].src, pkt[Ether].dst = pkt[Ether].dst, pkt[Ether].src
	del (pkt[Ether].chksum)

	pkt[IP].src, pkt[IP].dst = pkt[IP].dst, pkt[IP].src
	del (pkt[UDP].chksum)

	pkt[UDP].sport, pkt[UDP].dport = pkt[UDP].dport, pkt[UDP].sport
	del (pkt[IP].chksum)

	pkt[RTLS].msg_type = msg_type

	return (pkt)


	
# Send a RTLS AR_ACK corresponding to a received AR_AP_NOTIFICATION
def send_ar_ack (pkt):

	# First generate the correct RTLS header using the received AR_AP_NOTIFICATION
	pkt_ack = forge_rtls_header (pkt, 0x10)

	# TODO use pkt[RTLS] stuffs to extract the RTLS header data to sign
	# Calculate the hmac-sha1 signature of the RTLS header	
	pkt_ack[RTLS].signature = str (binascii.unhexlify (hmac.new (rtls_psk, str (pkt)[42:58], sha1).hexdigest ()))

	# Send the forged RTLS ACK
	print ("[*]\tSending ACK to %s" % pkt_ack[IP].dst)
	sendp (pkt_ack, iface = capture_interface)

	return (0)



def main (args):

	print ("[*]\tSniffing for RTLS packets")

	# Sniff RTLS notifications
	sniff (iface = capture_interface, prn = handle_rtls_pkt, filter = capture_filter, store = 0)



if __name__ == '__main__':

	try:
		main (sys.argv)

	except KeyboardInterrupt:
		print ("[!]\tCaught a SIGINT, exiting...")
		db_con.commit ()
		db_con.close ()
		sys.exit (0)
