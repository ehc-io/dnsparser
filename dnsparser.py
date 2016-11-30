#!/usr/bin/python
from scapy.all import *
from scapy.layers.dns import DNS, DNSQR
import datetime
import sys
import argparse
import time

def convertunixtime(timestamp):
	time = (datetime.datetime.fromtimestamp(int(timestamp)).strftime('%Y-%m-%d %H:%M:%S'))
	return(time)

def main(target):
	types = {0: 'ANY', 255: 'ALL',1: 'A', 2: 'NS', 3: 'MD', 4: 'MD', 5: 'CNAME',
			 6: 'SOA', 7:  'MB',8: 'MG',9: 'MR',10: 'NULL',11: 'WKS',12: 'PTR',
			 13: 'HINFO',14: 'MINFO',15: 'MX',16: 'TXT',17: 'RP',18: 'AFSDB',
			 28: 'AAAA', 33: 'SRV',38: 'A6',39: 'DNAME'}
	
	for capture_file in target:
		print capture_file
		if not os.path.isfile(capture_file):
			print '%s is not a valid capture file' % file
			continue
		try:
			dns_packets = PcapReader(capture_file)
		except:
			print '%s is not a valid capture file' % file
			continue

		for packet in dns_packets:
			if packet.haslayer(DNS) and packet.haslayer(IP):
				src = packet[IP].src
				dst = packet[IP].dst
				rec_type = packet[DNSQR].qtype
				fqdn = packet[DNSQR].qname
				time = packet.time
				try:
					print(convertunixtime(time),src,dst, fqdn, types[rec_type])
				except:
					print(convertunixtime(time),src,dst, fqdn)

if __name__ == '__main__':
		parser = argparse.ArgumentParser(prog='dnsparser.py' , description='dns parser for pcap files')
		parser.add_argument("target", help=('target filename ou folder'))
		# parser.add_argument('-f' , '--filename', nargs='?', const='dynamic' , default='auto')
		# parser.add_argument('-d' , '--directory', action="store_true" , help=('directory folders'))
		# parser.add_argument('-f' , '--filename', action="store_true" , help=('directory folders'))
		args = parser.parse_args()
		#
		if os.path.isfile(args.target):
			target = [args.target]
			main(target)
		if os.path.isdir(args.target):
			array_capture_files = []
			for first_level_folder in os.listdir(args.target):
				folder = os.path.join(args.target,first_level_folder)
				# if len(folders) == 0 :  continue
				files = os.listdir(folder)
				for file in files:
					array_capture_files.append(os.path.join(folder,file))

		# for item in array_capture_files : print item
		print 'analyzing %s files' % str(len(array_capture_files))
		time.sleep(3)
		main(array_capture_files)
		print ' Thank you '