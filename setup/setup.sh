#!/bin/bash

function review_file(){
    read -p "Review/Edit $1? (y/n): " answer
        if [ "$answer" == "y" ]; then
            vim $1
        fi
}

echo "Beginning honeypot-ai setup"

# Setup venv and install requirements
if [ -d "honeypot-ai-venv" ]; then
    echo "Venv already exists. Skipping venv setup."
else
    echo "Setting up venv"
    python3 -m venv honeypot-ai-venv
    source honeypot-ai-venv/bin/activate
    pip3 install -r setup/requirements.txt
    echo "Venv setup complete"
fi


# Get config variables
read -p "What is the EXTERNAL/PUBLIC IP of your Honeypot?" HONEYPOT_EXTERNAL_IP
[ -z "$HONEYPOT_EXTERNAL_IP" ] && echo "No Honeypot EXTERNAL IP provided. You must add your Honeypot EXTERNAL IP to config.json before using Honeypot AI." || echo "Honeypot EXTERNAL IP $HONEYPOT_EXTERNAL_IP will be added to sync-logs.sh and config.json"

read -p "What is the INTERNAL IP of your Honeypot?" HONEYPOT_INTERNAL_IP
[ -z "$HONEYPOT_INTERNAL_IP" ] && echo "No Honeypot INTERNAL IP provided. You must add your Honeypot INTERNAL IP to config.json before using Honeypot AI." || echo "Honeypot INTERNAL IP $HONEYPOT_INTERNAL_IP will be added to sync-logs.sh and config.json"

read -p "What is the admin port of your Honeypot? (default: 12222)" ADMIN_PORT
[ -z "$ADMIN_PORT" ] && ADMIN_PORT=12222 && echo "No admin Port provided. Defaulting to port 12222." || echo "Admin Port $ADMIN_PORT will be added to sync-logs.sh and config.json"

read -p "What is your Honeypot username? (default: ubuntu)" USER
[ -z "$USER" ] && USER=ubuntu && echo "No Honeypot username provided. Defaulting to ubuntu." || echo "Honeypot username $USER will be added to sync-logs.sh"

read -p "What is the path to your Honeypot keyfile? (Leave blank to use password authentication)" KEYFILE
[ -z "$KEYFILE" ] && echo "No Honeypot keyfile provided. Defaulting to password authentication" || echo "Honeypot keyfile $KEYFILE will be added to sync-logs.sh"


read -p "What is the path to the Firewall logs on your Honeypot? (default: $FIREWALL_REMOTE_PATH)" FIREWALL_REMOTE_PATH
[ -z "$FIREWALL_REMOTE_PATH" ] && FIREWALL_REMOTE_PATH=/var/log && echo "No Firewall logs path provided. Defaulting to $FIREWALL_REMOTE_PATH." || echo "Firewall logs path $FIREWALL_REMOTE_PATH will be added to sync-logs.sh"

read -p "What is the path to the Web logs on your Honeypot? (default: $WEBLOGS_REMOTE_PATH)" WEBLOGS_REMOTE_PATH
[ -z "$WEBLOGS_REMOTE_PATH" ] && WEBLOGS_REMOTE_PATH=/srv/db && echo "No Web logs path provided. Defaulting to $WEBLOGS_REMOTE_PATH." || echo "Web logs path $WEBLOGS_REMOTE_PATH will be added to sync-logs.sh"

read -p "What is the path to the Cowrie logs on your Honeypot? (default: $COWRIE_REMOTE_PATH)" COWRIE_REMOTE_PATH
[ -z "$COWRIE_REMOTE_PATH" ] && COWRIE_REMOTE_PATH=/srv/cowrie/var/log/cowrie && echo "No Cowrie logs path provided. Defaulting to $COWRIE_REMOTE_PATH." || echo "Cowrie logs path $COWRIE_REMOTE_PATH will be added to sync-logs.sh"

read -p "What is the path to the Malware downloads on your Honeypot? (default: $MALWARE_REMOTE_PATH)" MALWARE_REMOTE_PATH
[ -z "$MALWARE_REMOTE_PATH" ] && MALWARE_REMOTE_PATH=/srv/cowrie/var/lib/cowrie && echo "No Malware downloads path provided. Defaulting to $MALWARE_REMOTE_PATH." || echo "Malware downloads path $MALWARE_REMOTE_PATH will be added to sync-logs.sh"

read -p "What is the path to the Zeek logs on your Honeypot? (default: $ZEEK_REMOTE_PATH)" ZEEK_REMOTE_PATH
[ -z "$ZEEK_REMOTE_PATH" ] && ZEEK_REMOTE_PATH=/srv/zeek/logs/aggregate && echo "No Zeek logs path provided. Defaulting to $ZEEK_REMOTE_PATH." || echo "Zeek logs path $ZEEK_REMOTE_PATH will be added to sync-logs.sh"


# Get Path Config Variables
read -p "Where should logs be stored locally? (default: ./logs): " LOGS_PATH
[ -z "$LOGS_PATH" ] && LOGS_PATH=./logs 

read -p "Where should Attack directories be created locally? (default: ./attacks): " ATTACKS_PATH
[ -z "$ATTACKS_PATH" ] && ATTACKS_PATH=./attacks

read -p "Where should reports be stored locally? (default: ./reports): " REPORTS_PATH
[ -z "$REPORTS_PATH" ] && REPORTS_PATH=./reports

read -p "Where should analyzer data be stored locally? (default: ./db): " DB_PATH
[ -z "$DB_PATH" ] && DB_PATH=./db

# read -p "Where should resources be stored? (default: ./resources): " RESOURCES_PATH
# [ -z "$RESOURCES_PATH" ] && RESOURCES_PATH=./resources

echo "Configuring sync-logs.sh"
cp setup/sync-logs.sh sync-logs.sh
sed -i "s/<USER>/$USER/" sync-logs.sh
sed -i "s/<HONEYPOT_IP>/$HONEYPOT_EXTERNAL_IP/" sync-logs.sh
sed -i "s/<SSH_PORT>/$ADMIN_PORT/" sync-logs.sh
sed -i "s/<KEYFILE>/$KEYFILE/" sync-logs.sh

sed -i "s|<FIREWALL_REMOTE_PATH>|$FIREWALL_REMOTE_PATH|" sync-logs.sh
sed -i "s|<WEBLOGS_REMOTE_PATH>|$WEBLOGS_REMOTE_PATH|" sync-logs.sh
sed -i "s|<COWRIE_REMOTE_PATH>|$COWRIE_REMOTE_PATH|" sync-logs.sh
sed -i "s|<MALWARE_REMOTE_PATH>|$MALWARE_REMOTE_PATH|" sync-logs.sh
sed -i "s|<ZEEK_REMOTE_PATH>|$ZEEK_REMOTE_PATH|" sync-logs.sh
sed -i "s|<LOGS_PATH>|$LOGS_PATH|" sync-logs.sh

chmod +x sync-logs.sh
echo "Done configuring sync-logs.sh. You can now use this script to sync logs from your Honeypot to your local machine."
review_file sync-logs.sh

echo "Configuring setup/install-zeek-on-honeypot.sh."
cp setup/install-zeek-on-honeypot.sh install-zeek-on-honeypot.sh
sed -i "s/<USER>/$USER/" install-zeek-on-honeypot.sh
sed -i "s/<HONEYPOT_IP>/$HONEYPOT_EXTERNAL_IP/" install-zeek-on-honeypot.sh
sed -i "s/<SSH_PORT>/$ADMIN_PORT/" install-zeek-on-honeypot.sh
sed -i "s/<KEYFILE>/$KEYFILE/" install-zeek-on-honeypot.sh

chmod +x install-zeek-on-honeypot.sh
echo "Done configuring setup/install-zeek-on-honeypot.sh. You can now use this script to install Zeek on your Honeypot."
review_file install-zeek-on-honeypot.sh


read -p "Would you like to run install-zeek-on-honeypot.sh now? (y/n): " RUN_INSTALL_ZEEK
[ "$RUN_INSTALL_ZEEK" == "y" ] && ./install-zeek-on-honeypot.sh


read -p "Would you like to use OpenAI? (y/n): " OPENAI
[ -z "$OPENAI" ] && OPENAI=n
if [ "$OPENAI" == "y" ]; then
    read -p "What is your OpenAI API Key? (Get from https://platform.openai.com/api-keys): " OPENAI_API_KEY
    [ -z "$OPENAI_API_KEY" ] && echo "No OpenAI API Key provided. You must add your API key to config.json before using OpenAI." || echo "OpenAI API Key will be added to config.json"
fi

read -p "Would you like to use download Chomedriver to use with Selenium? (y/n): " SELENIUM
[ -z "$SELENIUM" ] && SELENIUM=y
if [ "$SELENIUM" == "y" ]; then
    python3 setup/download_chromedriver.py
fi

echo "Running main.py to setup config.json. (Ignore no loading method warning)"

python3 main.py -u --logs-path $LOGS_PATH --attacks-path $ATTACKS_PATH --reports-path $REPORTS_PATH --db-path $DB_PATH \
    --honeypot-external-ip $HONEYPOT_EXTERNAL_IP --honeypot-internal-ip $HONEYPOT_INTERNAL_IP

echo "Setup complete. You can now run main.py to start Honeypot AI."

read -p "Show help for main.py? (y/n): " SHOW_HELP
[ "$SHOW_HELP" == "y" ] && python3 main.py -h

exit 0
