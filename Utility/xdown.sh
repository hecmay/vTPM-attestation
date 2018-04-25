#!/bin/sh 
# 
# Script to bring down and delete bridge br0 when QEMU exits 
# 
# Bring down $IFNAME and br0 
#

ETH0IPADDR=10.0.2.15
MASK=255.255.255.0
GATEWAY=10.0.2.1
BROADCAST=10.0.2.255
IFNAME=enp0s3

/sbin/ifdown $IFNAME
/sbin/ifdown br0
/sbin/ifconfig br0 down 
# 
# Delete the bridge
#
/sbin/brctl delbr br0 
# 
# bring up $IFNAME in "normal" mode 
#
/sbin/ifconfig $IFNAME -promisc
/sbin/ifup $IFNAME 
#
# delete the tap device
#
/usr/sbin/openvpn --rmtun --dev $1
/usr/sbin/openvpn --rmtun --dev $2
#
# start firewall again
# 
# /sbin/service firestarter start 

dhclient $1
dhclient $2
#/sbin/ifconfig $IFNAME $ETH0IPADDR netmask $MASK broadcast $BROADCAST
#/sbin/route add default gw $GATEWAY
