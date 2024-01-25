#!/bin/bash

function review_file(){
    read -p "Review/Edit $1? (y/n): " answer
        if [ "$answer" == "y" ]; then
            vim $1
        fi
}

printf "\nBeginning honeypot-ai setup"

# Setup venv and install requirements
if [ -d "honeypot-ai-venv" ]; then
    printf "\nVenv already exists. Skipping venv setup.\n"
else
    printf "\nSetting up venv"
    python3 -m venv honeypot-ai-venv
    source honeypot-ai-venv/bin/activate
    pip3 install -r setup/requirements.txt
    printf "\nVenv setup complete\n"
fi


# Get config variables
printf "\nWhat is the EXTERNAL/PUBLIC IP of your Honeypot?\n"
read -p "Enter HONEYPOT_EXTERNAL_IP: " HONEYPOT_EXTERNAL_IP
[ -z "$HONEYPOT_EXTERNAL_IP" ] && printf "\nNo Honeypot EXTERNAL IP provided. You must add your Honeypot EXTERNAL IP to config.json before using Honeypot AI.\n" || printf "\nHoneypot EXTERNAL IP $HONEYPOT_EXTERNAL_IP will be added to sync-logs.sh and config.json.\n"

printf "\nWhat is the INTERNAL IP of your Honeypot?\n"
read -p "Enter HONEYPOT_INTERNAL_IP: " HONEYPOT_INTERNAL_IP
[ -z "$HONEYPOT_INTERNAL_IP" ] && printf "\nNo Honeypot INTERNAL IP provided. You must add your Honeypot INTERNAL IP to config.json before using Honeypot AI.\n" || printf "\nHoneypot INTERNAL IP $HONEYPOT_INTERNAL_IP will be added to sync-logs.sh and config.json.\n"

printf "\nWhat is the admin port of your Honeypot? (default: 12222):\n"
read -p "Enter ADMIN_PORT: " ADMIN_PORT
[ -z "$ADMIN_PORT" ] && ADMIN_PORT=12222 && printf "\nNo admin Port provided. Defaulting to port 12222.\n" || printf "\nAdmin Port $ADMIN_PORT will be added to sync-logs.sh and config.json.\n"

printf "\nWhat is your Honeypot username? (default: ubuntu):\n"
read -p "Enter USER: " USER
[ -z "$USER" ] && USER=ubuntu && printf "\nNo Honeypot username provided. Defaulting to ubuntu.\n" || printf "\nHoneypot username $USER will be added to sync-logs.sh\n"

printf "\nWhat is the path to your Honeypot keyfile? (Leave blank to use password authentication):\n"
read -p "Enter KEYFILE: " KEYFILE
[ -z "$KEYFILE" ] && printf "\nNo Honeypot keyfile provided. Defaulting to password authentication.\n" || printf "\nHoneypot keyfile $KEYFILE will be added to sync-logs.sh\n"

zeek_remote_logs_dir="/srv/zeek/logs/aggregate"
web_remote_logs_dir="/srv/db"
cowrie_remote_logs_dir="/srv/cowrie/var/log/cowrie"
firewall_remote_logs_dir="/var/log"
malware_remote_logs_dir="/srv/cowrie/var/lib/cowrie"
printf "\nWhat is the path to the Firewall logs on your Honeypot? (default: /var/log ):\n"
read -p "Enter FIREWALL_REMOTE_PATH: " FIREWALL_REMOTE_PATH
[ -z "$FIREWALL_REMOTE_PATH" ] && FIREWALL_REMOTE_PATH=/var/log && printf "\nNo Firewall logs path provided. Defaulting to $FIREWALL_REMOTE_PATH.\n" || printf "\nFirewall logs path $FIREWALL_REMOTE_PATH will be added to sync-logs.sh\n"

printf "\nWhat is the path to the Web logs on your Honeypot? (default: /srv/db ):\n"
read -p "Enter WEBLOGS_REMOTE_PATH: " WEBLOGS_REMOTE_PATH
[ -z "$WEBLOGS_REMOTE_PATH" ] && WEBLOGS_REMOTE_PATH=/srv/db && printf "\nNo Web logs path provided. Defaulting to $WEBLOGS_REMOTE_PATH.\n" || printf "\nWeb logs path $WEBLOGS_REMOTE_PATH will be added to sync-logs.sh\n"

printf "\nWhat is the path to the Cowrie logs on your Honeypot? (default: /srv/cowrie/var/log/cowrie ):\n"
read -p "Enter COWRIE_REMOTE_PATH: " COWRIE_REMOTE_PATH
[ -z "$COWRIE_REMOTE_PATH" ] && COWRIE_REMOTE_PATH=/srv/cowrie/var/log/cowrie && printf "\nNo Cowrie logs path provided. Defaulting to $COWRIE_REMOTE_PATH.\n" || printf "\nCowrie logs path $COWRIE_REMOTE_PATH will be added to sync-logs.sh\n"

printf "\nWhat is the path to the Malware downloads on your Honeypot? (default: /srv/cowrie/var/lib/cowrie/downloads ):\n"
read -p "Enter MALWARE_REMOTE_PATH: " MALWARE_REMOTE_PATH
[ -z "$MALWARE_REMOTE_PATH" ] && MALWARE_REMOTE_PATH=/srv/cowrie/var/lib/cowrie/downloads && printf "\nNo Malware downloads path provided. Defaulting to $MALWARE_REMOTE_PATH.\n" || printf "\nMalware downloads path $MALWARE_REMOTE_PATH will be added to sync-logs.sh\n"

printf "\nWhat is the path to the Zeek logs on your Honeypot? (default: /srv/zeek/logs/aggregate ):\n"
read -p "Enter ZEEK_REMOTE_PATH: " ZEEK_REMOTE_PATH
[ -z "$ZEEK_REMOTE_PATH" ] && ZEEK_REMOTE_PATH=/srv/zeek/logs/aggregate && printf "\nNo Zeek logs path provided. Defaulting to $ZEEK_REMOTE_PATH.\n" || printf "\nZeek logs path $ZEEK_REMOTE_PATH will be added to sync-logs.sh\n"

# Get Path Config Variables
printf "\nWhere should logs be stored locally? (default: ./logs ):\n"
read -p "Enter LOGS_PATH: " LOGS_PATH
[ -z "$LOGS_PATH" ] && LOGS_PATH=./logs 

printf "\nWhere should Attack directories be created locally? (default: ./attacks ):\n"
read -p "Enter ATTACKS_PATH: " ATTACKS_PATH
[ -z "$ATTACKS_PATH" ] && ATTACKS_PATH=./attacks

printf "\nWhere should reports be stored locally? (default: ./reports ):\n"
read -p "Enter REPORTS_PATH: " REPORTS_PATH
[ -z "$REPORTS_PATH" ] && REPORTS_PATH=./reports

printf "\nWhere should analyzer data be stored locally? (default: ./db ):\n"
read -p "Enter DB_PATH: " DB_PATH
[ -z "$DB_PATH" ] && DB_PATH=./db

# read -p "Where should resources be stored? (default: ./resources ):\n"
# [ -z "$RESOURCES_PATH" ] && RESOURCES_PATH=./resources

printf "\nConfiguring sync-logs.sh\n"
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
printf "\nDone configuring sync-logs.sh. You can now use this script to sync logs from your Honeypot to your local machine.\n"
review_file sync-logs.sh

printf "\nConfiguring setup/install-zeek-on-honeypot.sh.\n"
cp setup/install-zeek-on-honeypot.sh install-zeek-on-honeypot.sh
sed -i "s/<USER>/$USER/" install-zeek-on-honeypot.sh
sed -i "s/<HONEYPOT_IP>/$HONEYPOT_EXTERNAL_IP/" install-zeek-on-honeypot.sh
sed -i "s/<SSH_PORT>/$ADMIN_PORT/" install-zeek-on-honeypot.sh
sed -i "s/<KEYFILE>/$KEYFILE/" install-zeek-on-honeypot.sh

chmod +x install-zeek-on-honeypot.sh
printf "\nDone configuring setup/install-zeek-on-honeypot.sh. You can now use this script to install Zeek on your Honeypot.\n"
review_file install-zeek-on-honeypot.sh

printf "\n"
read -p "Would you like to run install-zeek-on-honeypot.sh now? (y/n): " RUN_INSTALL_ZEEK
[ "$RUN_INSTALL_ZEEK" == "y" ] && ./install-zeek-on-honeypot.sh

printf "\n"
read -p "Would you like to use OpenAI? (y/n): " OPENAI
[ -z "$OPENAI" ] && OPENAI=n
if [ "$OPENAI" == "y" ]; then
    OPENAI_ARG="--use-openai"
    printf "\nWhat is your OpenAI API Key? (Get from https://platform.openai.com/api-keys)"
    read -p "Enter OPENAI_API_KEY: " OPENAI_API_KEY 
    [ -z "$OPENAI_API_KEY" ] && printf "\nNo OpenAI API Key provided. You must add your API key to config.json before using OpenAI.\n" || printf "\nOpenAI API Key will be added to config.json.\n"
fi

printf "\n"
read -p "Would you like to use download Chomedriver to use with Selenium? (y/n): " SELENIUM
[ -z "$SELENIUM" ] && SELENIUM=y
if [ "$SELENIUM" == "y" ]; then
    python3 setup/download_chromedriver.py
else
    printf "\nSkipping download of Chromedriver.\n"
    printf "\nSetting USE_IPANALYZER to False in config.json. Edit config.json or use --ip-analyzer -u to change this.\n"
fi

printf "\nRunning main.py to setup config.json. (Ignore no loading method warning)\n"

python3 main.py -u --logs-path $LOGS_PATH --attacks-path $ATTACKS_PATH --reports-path $REPORTS_PATH --db-path $DB_PATH \
    --honeypot-external-ip $HONEYPOT_EXTERNAL_IP --honeypot-internal-ip $HONEYPOT_INTERNAL_IP \
    $OPENAI_ARG --openai-api-key $OPENAI_API_KEY

printf "\nSetup complete. You can now run main.py to start Honeypot AI.\n"

read -p "Show help for main.py? (y/n): " SHOW_HELP
[ "$SHOW_HELP" == "y" ] && python3 main.py -h

exit 0


