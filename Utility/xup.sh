#!/bin/sh 
# 
# script to bring up the tun device in QEMU in bridged mode 
# first parameter is name of tap device (e.g. tap0)
#
# some constants specific to the local host - change to suit your host
#
ETH0IPADDR=192.168.199.152
MASK=255.255.255.0
GATEWAY=192.168.199.1
BROADCAST=192.168.199.255

IFNAME=enp0s3
#
# First take eth0 down, then bring it up with IP address 0.0.0.0 
#
/sbin/ifdown $IFNAME
/sbin/ifconfig $IFNAME 0.0.0.0 promisc up
#
# Bring up the tap device (name specified as first argument, by QEMU)
#
res=`ifconfig | grep $1`

if test -z "$res"
then
    /usr/sbin/openvpn --mktun --dev $1 --user `id -un`
fi

re=`ifconfig | grep $2`

if test -z "$re"
then
    /usr/sbin/openvpn --mktun --dev $2 --user `id -un`
fi

/sbin/ifconfig $1 0.0.0.0 promisc up
/sbin/ifconfig $2 0.0.0.0 promisc up
#
# create the bridge between eth0 and the tap device
#
res=`ifconfig | grep br0`
if test -n "$res"
then
    /sbin/ifdown br0
    /sbin/ifconfig br0 down
    /sbin/brctl delbr br0
fi
echo "addbr br0..." $IFNAME $1
/sbin/brctl addbr br0
sleep 1
/sbin/brctl addif br0 $IFNAME
/sbin/brctl addif br0 $1
/sbin/brctl addif br0 $2
# 
# only a single bridge so loops are not possible, turn off spanning tree protocol
#
/sbin/brctl stp br0 off 
# 
# Bring up the bridge with ETH0IPADDR and add the default route 
#
echo "ifconfig br0..."
dhclient br0
#/sbin/ifconfig br0 $ETH0IPADDR netmask $MASK broadcast $BROADCAST
#/sbin/route add default gw $GATEWAY

#
# stop firewall - comment this out if you don't use Firestarter
#
# /sbin/service firestarter stop 
