#!/bin/bash

function review_file(){
    read -p "Review/Edit $1 in vim? (y/n): " answer
        if [ "$answer" == "y" ]; then
            vim $1
        fi
}



printf "\nBeginning honeypot-ai setup"
# Get the directory of the script
HONEYPOT_AI_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CURRENT_PATH="$(pwd)"
printf "\nHoneypot AI Path: $HONEYPOT_AI_PATH\n"
printf "\nCurrent Path: $CURRENT_PATH\n"

# Setup venv and install requirements
if [ -d "$HONEYPOT_AI_PATH/honeypot-ai-venv" ]; then
    printf "\nVenv already exists. Skipping venv setup.\n"
else
    printf "\nSetting up venv"
    python3 -m venv "$HONEYPOT_AI_PATH/honeypot-ai-venv"
    source "$HONEYPOT_AI_PATH/honeypot-ai-venv/bin/activate"
    pip3 install -r "$HONEYPOT_AI_PATH/setup/requirements.txt"
    printf "\nVenv setup complete\n"
fi

# Get IP Address of local machine
printf "\nGetting IP Address of local machine from ifconfig.me\n"
USER_IP="$(curl ifconfig.me)"
printf "\nYour IP Address is $USER_IP\n"
printf "\nYour IP Address will be added to config.json.\nYou can add other IPs you use to access your honeypot to exclude from analysis to the USER_IPS list \n"

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

# Get Remote Path Config Variables
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

# Get Local Path Config Variables
printf "\nWhere should logs be stored locally? (default: $CURRENT_PATH/logs ):\n"
read -p "Enter LOGS_PATH: " LOGS_PATH
[ -z "$LOGS_PATH" ] && LOGS_PATH="$CURRENT_PATH/logs"

printf "\nWhere should Attack directories be stored locally? (default: $CURRENT_PATH/attacks ):\n"
read -p "Enter ATTACKS_PATH: " ATTACKS_PATH
[ -z "$ATTACKS_PATH" ] && ATTACKS_PATH="$CURRENT_PATH/attacks"

printf "\nWhere should reports be stored locally? (default: $CURRENT_PATH/reports ):\n"
read -p "Enter REPORTS_PATH: " REPORTS_PATH
[ -z "$REPORTS_PATH" ] && REPORTS_PATH="$CURRENT_PATH/reports"

printf "\nWhere should analyzer data be stored locally? (default: $CURRENT_PATH/db ):\n"
read -p "Enter DB_PATH: " DB_PATH
[ -z "$DB_PATH" ] && DB_PATH="$CURRENT_PATH/db"

printf "\nWhere should resources be stored? (default: $HONEYPOT_AI_PATH/resources ):\n"
read -p "Enter RESOURCES_PATH: " RESOURCES_PATH
[ -z "$RESOURCES_PATH" ] && RESOURCES_PATH="$HONEYPOT_AI_PATH/resources"


printf "\nConfiguring sync-logs.sh\n"
cp "$HONEYPOT_AI_PATH/setup/sync-logs.sh" "$HONEYPOT_AI_PATH/sync-logs.sh"
# Using sed -i"$SAFE_TO_DELETE_EXT" -e <command> <file> to work on both Linux and MacOS
# mac always generates a backup file when using sed -i so we need to delete it 
# and use unique extension to prevent deleting files other than the backups
# Note to self: Alternative solution to this problem is (sed -e "s|<USER>|$USER|"  sync-logs.sh|tee|tee sync-logs.sh) 1>/dev/null    
SAFE_TO_DELETE_EXT="-$((RANDOM % 90000 + 1000000)).bak"
sed -i"$SAFE_TO_DELETE_EXT" -e "s|<USER>|$USER|" "$HONEYPOT_AI_PATH/sync-logs.sh"
sed -i"$SAFE_TO_DELETE_EXT" -e "s|<HONEYPOT_IP>|$HONEYPOT_EXTERNAL_IP|" "$HONEYPOT_AI_PATH/sync-logs.sh"
sed -i"$SAFE_TO_DELETE_EXT" -e "s|<SSH_PORT>|$ADMIN_PORT|" "$HONEYPOT_AI_PATH/sync-logs.sh"
sed -i"$SAFE_TO_DELETE_EXT" -e "s|<KEYFILE>|$KEYFILE|" "$HONEYPOT_AI_PATH/sync-logs.sh"
sed -i"$SAFE_TO_DELETE_EXT" -e "s|<FIREWALL_REMOTE_PATH>|$FIREWALL_REMOTE_PATH|" "$HONEYPOT_AI_PATH/sync-logs.sh"
sed -i"$SAFE_TO_DELETE_EXT" -e "s|<WEBLOGS_REMOTE_PATH>|$WEBLOGS_REMOTE_PATH|" "$HONEYPOT_AI_PATH/sync-logs.sh"
sed -i"$SAFE_TO_DELETE_EXT" -e "s|<COWRIE_REMOTE_PATH>|$COWRIE_REMOTE_PATH|" "$HONEYPOT_AI_PATH/sync-logs.sh"
sed -i"$SAFE_TO_DELETE_EXT" -e "s|<MALWARE_REMOTE_PATH>|$MALWARE_REMOTE_PATH|" "$HONEYPOT_AI_PATH/sync-logs.sh"
sed -i"$SAFE_TO_DELETE_EXT" -e "s|<ZEEK_REMOTE_PATH>|$ZEEK_REMOTE_PATH|" "$HONEYPOT_AI_PATH/sync-logs.sh"
sed -i"$SAFE_TO_DELETE_EXT" -e "s|<LOGS_PATH>|$LOGS_PATH|" "$HONEYPOT_AI_PATH/sync-logs.sh"
rm "$HONEYPOT_AI_PATH/"*"$SAFE_TO_DELETE_EXT"

chmod +x "$HONEYPOT_AI_PATH/sync-logs.sh"
printf "\nDone configuring "$HONEYPOT_AI_PATH/sync-logs.sh". \nYou can now use this script to sync logs from your Honeypot to your local machine.\n"
review_file "$HONEYPOT_AI_PATH/sync-logs.sh"

printf "\nConfiguring $HONEYPOT_AI_PATH/setup/install-zeek-on-honeypot.sh.\n"
cp "$HONEYPOT_AI_PATH/setup/install-zeek-on-honeypot.sh" "$HONEYPOT_AI_PATH/install-zeek-on-honeypot.sh"
sed -i"$SAFE_TO_DELETE_EXT" -e "s|<USER>|$USER|" "$HONEYPOT_AI_PATH/install-zeek-on-honeypot.sh"
sed -i"$SAFE_TO_DELETE_EXT" -e "s|<HONEYPOT_IP>|$HONEYPOT_EXTERNAL_IP|" "$HONEYPOT_AI_PATH/install-zeek-on-honeypot.sh"
sed -i"$SAFE_TO_DELETE_EXT" -e "s|<SSH_PORT>|$ADMIN_PORT|" "$HONEYPOT_AI_PATH/install-zeek-on-honeypot.sh"
sed -i"$SAFE_TO_DELETE_EXT" -e "s|<KEYFILE>|$KEYFILE|" "$HONEYPOT_AI_PATH/install-zeek-on-honeypot.sh"
rm "$HONEYPOT_AI_PATH/"*"$SAFE_TO_DELETE_EXT"

chmod +x "$HONEYPOT_AI_PATH/install-zeek-on-honeypot.sh"
printf "\nDone configuring setup/install-zeek-on-honeypot.sh. \nYou can now use this script to install Zeek on your Honeypot.\n"
review_file "$HONEYPOT_AI_PATH/install-zeek-on-honeypot.sh"

printf "\n"
read -p "Would you like to run install-zeek-on-honeypot.sh now? (y/n): " RUN_INSTALL_ZEEK
[ "$RUN_INSTALL_ZEEK" == "y" ] && "$HONEYPOT_AI_PATH/install-zeek-on-honeypot.sh"

printf "\n"
read -p "Would you like to use OpenAI? (y/n): " OPENAI
[ -z "$OPENAI" ] && OPENAI=n
if [ "$OPENAI" == "y" ]; then
    USE_OPENAI_ARG="--use-openai"
    printf "\nWhat is your OpenAI API Key? (Get from https://platform.openai.com/api-keys)\n"
    read -p "Enter OPENAI_API_KEY: " OPENAI_API_KEY 
    [ -z "$OPENAI_API_KEY" ] && printf "\nNo OpenAI API Key provided. You must add your API key to config.json before using OpenAI.\n" \
    || printf "\nOpenAI API Key will be added to config.json.\n" && OPENAI_API_KEY_ARG="--openai-api-key  $OPENAI_API_KEY"
fi

printf "\n"
read -p "Would you like to use download Chomedriver to use with Selenium? (y/n): " SELENIUM
[ -z "$SELENIUM" ] && SELENIUM=y
if [ "$SELENIUM" == "y" ]; then
    python3 "$HONEYPOT_AI_PATH/setup/getchromedriver.py" "$RESOURCES_PATH"
    unzip "$RESOURCES_PATH"/*.zip -d "$RESOURCES_PATH"
    CHROMEDRIVER_PATH=$(find "$RESOURCES_PATH" -type f -name 'chromedriver' -print -quit)
else
    printf "\nSkipping download of Chromedriver.\n"
    printf "\nSetting USE_IPANALYZER to False in config.json. Edit config.json or use --ip-analyzer -u to change this.\n"
    IP_ANALYZER_ARG="--no-ip-analyzer"
fi

printf "\nRunning main.py to setup config.json. (Ignore no loading method warning)\n"

python3 "$HONEYPOT_AI_PATH/main.py" -u \
    --logs-path $LOGS_PATH --attacks-path $ATTACKS_PATH --reports-path $REPORTS_PATH --db-path $DB_PATH \
    --resources-path $RESOURCES_PATH --webdriver-path $CHROMEDRIVER_PATH \
    --honeypot-external-ip $HONEYPOT_EXTERNAL_IP --honeypot-internal-ip $HONEYPOT_INTERNAL_IP --user-ip $USER_IP \
    $USE_OPENAI_ARG $OPENAI_API_KEY_ARG $IP_ANALYZER_ARG


printf "\nConfiguring $HONEYPOT_AI_PATH/run.sh.\n"
echo "#!/bin/bash
source $HONEYPOT_AI_PATH/honeypot-ai-venv/bin/activate
python3 $HONEYPOT_AI_PATH/main.py \$@
deactivate
" > "$HONEYPOT_AI_PATH/run.sh" 
chmod +x "$HONEYPOT_AI_PATH/run.sh"


printf "\nSetup complete.\n\nYou can now run:\n"
printf " ./sync-logs.sh to sync logs from your Honeypot to your local machine.\n"
printf " ./install-zeek-on-honeypot.sh to install/update Zeek on your Honeypot.\n"
printf " python3 $HONEYPOT_AI_PATH/main.py\nOR\n $HONEYPOT_AI_PATH/run.sh \nto run Honeypot AI.\n"


read -p "Run sync-logs.sh now? (y/n): " RUN_SYNC_LOGS
[ "$RUN_SYNC_LOGS" == "y" ] && "$HONEYPOT_AI_PATH/sync-logs.sh" && read -p "List attacks now? (y/n): " LIST_NOW 
[ "$LIST_NOW" == "y" ] && python3 "$HONEYPOT_AI_PATH/main.py" -lfl --list-attacks

read -p "Show help for main.py? (y/n): " SHOW_HELP
[ "$SHOW_HELP" == "y" ] && python3 "$HONEYPOT_AI_PATH/main.py" -h

exit 0