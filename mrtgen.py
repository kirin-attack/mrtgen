#!/usr/bin/env python3

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
p.add_argument('--aspath', action="append", help='AS_PATH attribute; specify multiple times to alternate announcements')
p.add_argument('--nh4', type=str, default='192.168.99.1', help='Next-Hop IPv4 address')
p.add_argument('--nh6', type=str, default='fc00::1', help='Next-Hop IPv6 address')
p.add_argument('--comm', action="store_true", help='add a unique COMMUNITY attribute to each announcement')
p.add_argument('--aggr', action="store_true", help='add a unique AGGREGATOR attribute to each announcement')

args = p.parse_args()

# set default aspath (does not properly work with append action)
if not args.aspath:
	args.aspath = [ "65001" ]

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
via4 = []
via6 = []
for aspath in args.aspath:
	# convert to list of integers
	aspath = [int(x) for x in aspath.split(",")]

	attr4 = [
		bgp.BGPPathAttributeNextHop(args.nh4),
		bgp.BGPPathAttributeOrigin(0),
		bgp.BGPPathAttributeAsPath([aspath], '!I'),
	]

	attr6 = [
		bgp.BGPPathAttributeMpReachNLRI(afi.IP6, safi.UNICAST, [args.nh6], []), # must be first
		bgp.BGPPathAttributeOrigin(0),
		bgp.BGPPathAttributeAsPath([aspath], '!I'),
	]

	if args.aggr:
		attr = bgp.BGPPathAttributeAggregator(as_number=0, addr=args.id)
		attr4.append(attr)
		attr6.append(attr)

	if args.comm:
		attr = bgp.BGPPathAttributeCommunities([])
		attr4.append(attr)
		attr6.append(attr)

	via4.append(mrtlib.MrtRibEntry(0, now, attr4))
	via6.append(mrtlib.MrtRibEntry(0, now, attr6))

# write RIB entries
seq = 0
comm = (args.asn << 16) + 1
for line in sys.stdin:
	line = line.strip()

	try:
		addr, slash, plen = line.partition("/")
		last = -1
		if ":" in addr:
			prefix = bgp.IP6AddrPrefix(int(plen), addr)

			via = via6[seq%len(via6)]
			via.bgp_attributes[0].nlri = [prefix]

			if args.comm:
				via.bgp_attributes[last].communities = [comm]
				last -= 1
			if args.aggr:
				via.bgp_attributes[last].as_number = seq + 1

			msg = mrtlib.TableDump2RibIPv6UnicastMrtMessage(seq, prefix, [via])
		else:
			prefix = bgp.IPAddrPrefix(int(plen), addr)

			via = via4[seq%len(via4)]
			if args.comm:
				via.bgp_attributes[last].communities = [comm]
				last -= 1
			if args.aggr:
				via.bgp_attributes[last].as_number = seq + 1

			msg = mrtlib.TableDump2RibIPv4UnicastMrtMessage(seq, prefix, [via])

	except Exception as e:
		print("'%s': %s" % (line, e))
		continue

	writer.write(mrtlib.TableDump2MrtRecord(msg))
	seq += 1
	comm += 1

# flush
writer.close()
