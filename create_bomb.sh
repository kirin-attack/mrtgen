#!/bin/bash

MY_BGP_ID=10.0.0.2
PEER_BGP_ID=10.0.0.1
PEER_IP=2001:0DB8:0:10::1
PEER_ASN=64512
AS_PATH1=64513,3701
AS_PATH2=64513,3702
NEXT_HOP_IPV6=2001:0DB8:0:10::2

source venv/bin/activate

INPUT="$1"
shift

cat "$INPUT" | ./mrtgen.py \
    --me $MY_BGP_ID --id $PEER_BGP_ID --ip $PEER_IP --asn $PEER_ASN \
    --aspath $AS_PATH1 --aspath $AS_PATH2 --nh6 $NEXT_HOP_IPV6 \
    "$@"
