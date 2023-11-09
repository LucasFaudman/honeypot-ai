#!/bin/bash

### RUN AS ROOT ###
if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi


# Enter Dir for Zeek Logs 
#cd zeeklogs 2>/dev/null || mkdir zeeklogs && cd zeeklogs

# Check if /opt/zeek exists
if [ -d "/opt/zeek" ]; then
    PREFIX="/opt/zeek"
# Check if /usr/local/zeek exists
elif [ -d "/usr/local/zeek" ]; then
    PREFIX="/usr/local/zeek"
else
    echo "Neither /opt/zeek nor /usr/local/zeek exist. Exiting."
    exit 1
fi


# List available network interfaces using ifconfig
echo "Available network interfaces:"
ifconfig -a | grep -o '^[^ ]*' | sed s/://g

# Prompt the user to select an interface
read -p "Enter the name of the interface you want to use: " INTERFACE

# Check if the  corresponds to an available interface
if ifconfig | grep -q "^$INTERFACE"; then
    echo "Interface $INTERFACE selected."
else
    echo "Invalid interface name. Exiting."
    exit 1
fi


# Set the interface in node.cfg
sed -i "s/interface=eth0/interface=$INTERFACE/g" $PREFIX/etc/node.cfg

# Set the Zeek Port in zeekctl.cfg
echo "#Set Zeek Port from 47760 to 27760
ZeekPort = 27760" >> $PREFIX/etc/zeekctl.cfg


# Start Zeek with zeekctl
zeekctl deploy

# Check if Zeek is running
zeekctl status

