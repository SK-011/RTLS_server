# RTLS_server
Basic RTLS (Real Time Location System) server using scapy


Sniff for RTLS AP_NOTIFICATION, and send a a forged ACK in order to initiate the flow.
In the mean time, sniff for COUMPOUND_MESSAGES_REPORT, parse it and simply store the STATION_REPORT data in a MySQL DB.
Contains a embeded RTLS scapy dissector in order to parse the data in a efficient, and somewhat user friendly way.
Kinda crappy, but works pretty well with aruba APs.
Not yet tested on other RTLS implementation.

# TO DO

Find a clever way to handle the data, store it and use it.
Make this pile of crappy code looks like something.
