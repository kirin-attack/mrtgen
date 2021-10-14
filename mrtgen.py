#!/usr/bin/python3

import sys
import bz2
import time
import argparse
from ryu.lib import mrtlib
from ryu.lib.packet import bgp
from ryu.lib.packet import afi
from ryu.lib.packet import safi

# parse CLI args
p = argparse.ArgumentParser(
	description='Generate MRT RIB files (TABLE_DUMP_V2 format)',
	formatter_class=argparse.ArgumentDefaultsHelpFormatter)
p.add_argument('target', metavar='TARGET', type=str, help='target file')
p.add_argument('--me', type=str, default='192.168.99.3', help='my BGP identifier')
p.add_argument('--id', type=str, default='192.168.99.1', help='peer BGP identifier')
p.add_argument('--ip', type=str, default='192.168.99.1', help='peer IP address')
p.add_argument('--asn', type=int, default=65001, help='peer ASN')
p.add_argument('--aspath', type=int, nargs='+', default=[65001], help='AS_PATH attribute')
p.add_argument('--nh4', type=str, default='192.168.99.1', help='Next-Hop IPv4 address')
p.add_argument('--nh6', type=str, default='fc00::1', help='Next-Hop IPv6 address')

args = p.parse_args()

# open target file for writing
if args.target.endswith(".bz2"):
	fh = bz2.BZ2File(args.target, 'wb')
else:
	fh = open(args.target, 'wb')
writer = mrtlib.Writer(fh)
now = int(time.time())

# peer list: one peer of myself
peer1 = mrtlib.MrtPeer(args.id, args.ip, args.asn)
msg = mrtlib.TableDump2PeerIndexTableMrtMessage(args.me, peer_entries=[peer1])
writer.write(mrtlib.TableDump2MrtRecord(msg))

# prepare RIB entry templates for v4/v6
via4 = mrtlib.MrtRibEntry(0, now, [
	bgp.BGPPathAttributeOrigin(0),
	bgp.BGPPathAttributeAsPath([args.aspath], '!I'),
	bgp.BGPPathAttributeNextHop(args.nh4),
])
via6 = mrtlib.MrtRibEntry(0, now, [
	bgp.BGPPathAttributeOrigin(0),
	bgp.BGPPathAttributeAsPath([args.aspath], '!I'),
	# this must be last
	bgp.BGPPathAttributeMpReachNLRI(afi.IP6, safi.UNICAST, [args.nh6], []),
])

# write RIB entries
seq = 0
for line in sys.stdin:
	line = line.strip()
	
	try:
		addr, slash, plen = line.partition("/")

		if ":" in addr:
			prefix = bgp.IP6AddrPrefix(int(plen), addr)
			via6.bgp_attributes[-1].nlri = [prefix]
			msg = mrtlib.TableDump2RibIPv6UnicastMrtMessage(seq, prefix, [via6])
		else:
			prefix = bgp.IPAddrPrefix(int(plen), addr)
			msg = mrtlib.TableDump2RibIPv4UnicastMrtMessage(seq, prefix, [via4])
	except Exception as e:
		print("'%s': %s" % (line, e))
		continue

	writer.write(mrtlib.TableDump2MrtRecord(msg))
	seq += 1

# flush
writer.close()
