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
read -p "Enter the name of the interface you want to use (default: eth0): " INTERFACE
[ -z "$INTERFACE" ] && INTERFACE=eth0

# Check if the  corresponds to an available interface
if ifconfig | grep -q "^$INTERFACE"; then
    echo "Interface $INTERFACE selected."
else
    echo "Invalid interface name. Exiting."
    exit 1
fi

read -p "Enter the location for Zeek logs (default: /srv/zeek/logs): " ZEEK_LOGS_DIR
[ -z "$ZEEK_LOGS_DIR" ] && ZEEK_LOGS_DIR=/srv/zeek/logs


# Enter Dir for Zeek Service Logs 
cd "$ZEEK_LOGS_DIR/aggregate/../" 2>/dev/null || mkdir -p "$ZEEK_LOGS_DIR/aggregate" && cd "$ZEEK_LOGS_DIR"


# Installation-wide salt value that is used in some digest hashes, e.g., for
# the creation of file IDs. Please change this to a hard to guess value.
# Change salt in local.zeek -> redef digest_salt = "Please change this value.";
random_salt=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
sed -i "s/redef digest_salt = \"Please change this value.\";/redef digest_salt = \"$random_salt\";/" ${PREFIX}/share/zeek/site/local.zeek

#Disable geo-data to prevent crashing zeek
sed -i '/^@load protocols\/ssh\/geo-data/s/^/# /' ${PREFIX}/share/zeek/site/local.zeek


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


# read -p "How Long Should Zeek Run Before Aggregating Logs (in seconds) (default: 21600 (6hrs)): " ZEEK_RUN_TIME
# [ -z "$ZEEK_RUN_TIME" ] && ZEEK_RUN_TIME=21600

# read -p "Where should the run-zeek-aggregate-logs.sh be created (default: ${PREFIX}/bin): " ZEEK_RUN_SCRIPT_DIR
# [ -z "$ZEEK_RUN_SCRIPT_DIR" ] && ZEEK_RUN_SCRIPT_DIR=${PREFIX}/bin


# #Create run-zeek-aggregate-logs.sh script
# echo "
# #Kill zeek before aggregating logs
# pkill zeek

# #Aggregate logs
# for file in \$(find $ZEEK_LOGS_DIR -maxdepth 1 -name '*.log'); do
#     cat \$file >> ${ZEEK_LOGS_DIR}/aggregate/\$(basename \$file)
#     rm -v \$file
# done

# #Start zeek
# ${PREFIX}/bin/zeek -i ${INTERFACE} -C ${PREFIX}/share/zeek/site/local.zeek &

# #Sleep for ZEEK_RUN_TIME seconds
# sleep $ZEEK_RUN_TIME
# #Once this sleep is done this process will exit and systemd will restart run this script again to aggregate logs and restart zeek
# " > $ZEEK_RUN_SCRIPT_DIR/run-zeek-aggregate-logs.sh

# #Make run-zeek-aggregate-logs.sh executable
# chmod +x $ZEEK_RUN_SCRIPT_DIR/run-zeek-aggregate-logs.sh

# Create .service file for zeek with the selected interface
echo "
[Unit]
Description=Zeek Network Security Monitor
After=network.target

[Service]
Type=simple
User=root
Group=root
ExecStart=${PREFIX}/bin/zeek -i ${INTERFACE} -C ${PREFIX}/share/zeek/site/local.zeek
ExecStop=pkill zeek
WorkingDirectory=${ZEEK_LOGS_DIR}
Restart=always

[Install]
WantedBy=multi-user.target

" > /etc/systemd/system/zeek.service

#CHANGE ABOVE EXECSTART TO USE run-zeek-aggregate-logs.sh $ZEEK_RUN_SCRIPT_DIR/run-zeek-aggregate-logs.sh

#Reload systemd daemon
systemctl daemon-reload

#Enable zeek and start zeek service
systemctl enable zeek
systemctl start zeek
systemctl status zeek

