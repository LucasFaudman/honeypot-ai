#!/bin/bash

### RUN AS ROOT ###
if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi

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

# Enter Dir for Zeek Service Logs 
cd /srv/zeek/logs 2>/dev/null || mkdir -p /srv/zeek/logs && cd /srv/zeek/logs

# Installation-wide salt value that is used in some digest hashes, e.g., for
# the creation of file IDs. Please change this to a hard to guess value.
# Change salt in local.zeek -> redef digest_salt = "Please change this value.";
random_salt=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
sed -i "s/redef digest_salt = \"Please change this value.\";/redef digest_salt = \"$random_salt\";/" ${PREFIX}/share/zeek/site/local.zeek

# read -p "Enter local subnets as comma separated CIDRs (ie: 192.168.0.0/16, 10.0.0.0/8, 172.31.0.0/16) :" LOCAL_SUBNETS 
# echo "
# # Define local network subnets
# Site::local_nets += { $LOCAL_SUBNETS };
# " >> ${PREFIX}/share/zeek/site/local.zeek

# #TODO - Add option to add additional scripts
# read -p "Enter IPs/CIDRs to exclude from Zeek logs as comma separated CIDRs (ie: 192.168.0.0/16, 10.0.0.0/8, 172.31.0.0/16) :" EXCLUDE_IPS
# #Create exclude_traffic.zeek file
# echo "@load base/protocols/conn

# # Define the IP address or CIDR block you want to exclude
# redef exclude_ips += { $EXCLUDE_IPS };

# event zeek_init()
# {
#     for (ip in exclude_ips)
#     {
#         Conn::block_net(ip);
#     }
# }
# " > ${PREFIX}/share/zeek/site/exclude_traffic.zeek

# #Add exclude_traffic.zeek to local.zeek
# echo "
# @load ./exclude_traffic.zeek
# " >> ${PREFIX}/share/zeek/site/local.zeek


# Create .service file for zeek with the selected interface
echo "
[Unit]
Description=Zeek Network Security Monitor

[Service]
Type=simple
User=root
Group=root
ExecStart=${PREFIX}/bin/zeek -i ${INTERFACE} -C ${PREFIX}/share/zeek/site/local.zeek
ExecStop=pkill zeek
WorkingDirectory=/srv/zeek/logs
Restart=always

[Install]
WantedBy=multi-user.target

" > /etc/systemd/system/zeek.service

#Reload systemd daemon
systemctl daemon-reload

#Enable zeek and start zeek service
systemctl enable zeek
systemctl start zeek
systemctl status zeek





