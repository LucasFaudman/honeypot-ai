#!/bin/bash

### RUN AS ROOT ###
if [ "$(id -u)" != "0" ]; then
    echo "This script must be run as root" 1>&2
    exit 1
fi


echo "Please select your OS from the list below:"
echo "1. 15.5"
echo "2. CentOS_7"
echo "3. Debian_11"
echo "4. Debian_12"
echo "5. Debian_Testing"
echo "6. Fedora_37"
echo "7. Fedora_38"
echo "8. openSUSE_Leap_15.4"
echo "9. openSUSE_Tumbleweed"
echo "10. Raspbian_11"
echo "11. xUbuntu_20.04"
echo "12. xUbuntu_22.04"
echo "13. xUbuntu_23.04"

read -p "Enter the number corresponding to your OS: " OS_number

case $OS_number in
    1) OS="15.5";;
    2) OS="CentOS_7";;
    3) OS="Debian_11";;
    4) OS="Debian_12";;
    5) OS="Debian_Testing";;
    6) OS="Fedora_37";;
    7) OS="Fedora_38";;
    8) OS="openSUSE_Leap_15.4";;
    9) OS="openSUSE_Tumbleweed";;
    10) OS="Raspbian_11";;
    11) OS="xUbuntu_20.04";;
    12) OS="xUbuntu_22.04";;
    13) OS="xUbuntu_23.04";;
    *) echo "Invalid input. Please enter a number between 1 and 13."; exit 1;;
esac

echo "You have selected $OS."


# add the relevant OBS package repository to your system
echo "deb http://download.opensuse.org/repositories/security:/zeek/${OS}/ /" | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/${OS}/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null


# Install dependencies
apt-get update -y
apt-get install cmake make gcc g++ flex bison libpcap-dev libssl-dev python3 python3-dev swig zlib1g-dev -y

# Install zeek
apt update -y
apt install zeek-lts -y

# Create symbolic links to zeek binary
ln -s /opt/zeek/bin/zeek /usr/bin/zeek
ln -s /opt/zeek/bin/zeek-cut /usr/bin/zeek-cut
ln -s /opt/zeek/bin/zeekctl /usr/bin/zeekctl


echo "Zeek has been installed successfully."

