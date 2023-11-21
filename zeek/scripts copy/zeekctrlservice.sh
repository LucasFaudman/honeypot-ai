#!/bin/bash

function review_file(){
    read -p "Review/Edit $1? (y/n): " answer
        if [ "$answer" == "y" ]; then
            vim $1
        fi
}



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

##BEGIN Local Site Config

# Installation-wide salt value that is used in some digest hashes, e.g., for
# the creation of file IDs. Please change this to a hard to guess value.
# Change salt in local.zeek -> redef digest_salt = "Please change this value.";
random_salt=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 32 | head -n 1)
sed -i "s/redef digest_salt = \"Please change this value.\";/redef digest_salt = \"$random_salt\";/" ${PREFIX}/share/zeek/site/local.zeek
echo "Salt set to $random_salt in local.zeek"

# read -p "Enter local subnets as comma separated CIDRs (ie: 192.168.0.0/16, 10.0.0.0/8, 172.31.0.0/16) :" LOCAL_SUBNETS 
# echo "
# # Define local network subnets
# Site::local_nets += { $LOCAL_SUBNETS };
# " >> ${PREFIX}/share/zeek/site/local.zeek


read -p "Add Zeek Scripts? (y/n): " ADD_SCRIPTS
if [ "$ADD_SCRIPTS" == "y" ]; then
    read -p "Enter Zeek Scripts to add as comma separated list (ie: intel, notice, smb, ssh, x509) :" ZEEK_SCRIPTS
    echo "
    #Add Zeek Scripts
    @load $ZEEK_SCRIPTS
    " >> ${PREFIX}/share/zeek/site/local.zeek
fi

review_file ${PREFIX}/share/zeek/site/local.zeek
#END Local Site Config

#BEGIN Zeekctrl Config

# Set the interface in node.cfg
sed -i "s/interface=.*/interface=$INTERFACE/g" $PREFIX/etc/node.cfg
echo "Interface set to $INTERFACE in node.cfg"
review_file $PREFIX/etc/node.cfg

# Ask for Zeek Port
read -p "Enter Zeek Port (default 27760): " ZEEK_PORT
[ -z "$ZEEK_PORT" ] && ZEEK_PORT=27760


read -p "Enter Admin IP to allow access Zeek Port: " ADMIN_IP
grep Zeek /etc/network/iptables || echo "# START: allow access to Zeek ports
-A INPUT -i $INTERFACE -s ${ADMIN_IP} -p tcp --dport ${ZEEK_PORT} -j ACCEPT
" >>/etc/network/iptables
echo "Admin IP $ADMIN_IP added to iptables"
review_file /etc/network/iptables


# Set the Zeek Port in zeekctl.cfg
if grep -q "ZeekPort" $PREFIX/etc/zeekctl.cfg ; then
    sed -i "s/ZeekPort = .*/ZeekPort = $ZEEK_PORT/" $PREFIX/etc/zeekctl.cfg
else
    echo "#Set Zeek Port from 47760 to 27760
ZeekPort = $ZEEK_PORT" >> $PREFIX/etc/zeekctl.cfg
fi

read -p "Enter Zeek Log Location (default /srv/zeek/logs): " ZEEK_LOGS_DIR
[-z "$ZEEK_LOGS_DIR" ] && ZEEK_LOGS_DIR="/srv/zeek/logs"

sed -i "s/LogDir = .*/LogDir = $ZEEK_LOGS_DIR/" $PREFIX/etc/zeekctl.cfg

review_file $PREFIX/etc/zeekctl.cfg



# Create .service file for zeek with the selected interface
echo "
[Unit]
Description=Zeek Network Security Monitor

[Service]
Type=forking
User=root
Group=root
ExecStart=${PREFIX}/bin/zeekctl start
ExecStop=/usr/bin/zeekctl stop
WorkingDirectory=/srv/zeek/logs
Restart=always
[Install]
WantedBy=multi-user.target


" > /etc/systemd/system/zeekctl.service
echo "Zeekctl service file created at /etc/systemd/system/zeekctl.service"
review_file /etc/systemd/system/zeekctl.service

#Reload systemd daemon
systemctl daemon-reload

#Enable zeek and start zeek service
systemctl enable zeekctl
systemctl start zeekctl

# Print the PID of the Zeek process
systemctl status zeekctl
echo "Zeek process ID: $(pgrep zeek)"

