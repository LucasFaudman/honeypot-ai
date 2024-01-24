#!/bin/bash

USER="<USER>"
HONEYPOT_IP="<HONEYPOT_IP>"
SSH_PORT="<SSH_PORT>"
KEYFILE="<KEYFILE>"


ZEEK_REMOTE_PATH="<ZEEK_REMOTE_PATH>"
WEBLOGS_REMOTE_PATH="<WEBLOGS_REMOTE_PATH>"
COWRIE_REMOTE_PATH="<COWRIE_REMOTE_PATH>"
FIREWALL_REMOTE_PATH="<FIREWALL_REMOTE_PATH>"
MALWARE_REMOTE_PATH="<MALWARE_REMOTE_PATH>"


LOGS_PATH="<LOGS_PATH>"
ZEEK_LOCAL_PATH="${LOGS_PATH}/zeek"
WEBLOGS_LOCAL_PATH="${LOGS_PATH}/web"
COWRIE_LOCAL_PATH="${LOGS_PATH}/cowrie"
FIREWALL_LOCAL_PATH="${LOGS_PATH}/firewall"
MALWARE_LOCAL_PATH="${LOGS_PATH}/malware"


# Create local directories if they don't exist
mkdir -p "$ZEEK_LOCAL_PATH"
mkdir -p "$WEBLOGS_LOCAL_PATH"
mkdir -p "$COWRIE_LOCAL_PATH"
mkdir -p "$FIREWALL_LOCAL_PATH"
mkdir -p "$MALWARE_LOCAL_PATH/downloads"


if [ ! -z "$KEYFILE" ]; then
    KEYFILE="-i $KEYFILE"
else
    KEYFILE="" 
    echo "No keyfile provided. Using password authentication."
fi

# Sync the logs from the remote server to the local machine 
scp -P "$SSH_PORT" "$KEYFILE" "$USER@$HONEYPOT_IP:$ZEEK_REMOTE_PATH/*.log" "$ZEEK_LOCAL_PATH" &
scp -P "$SSH_PORT" "$KEYFILE" "$USER@$HONEYPOT_IP:$WEBLOGS_REMOTE_PATH/*.json" "$WEBLOGS_LOCAL_PATH" &
scp -P "$SSH_PORT" "$KEYFILE" "$USER@$HONEYPOT_IP:$COWRIE_REMOTE_PATH/*cowrie*" "$COWRIE_LOCAL_PATH" &
scp -P "$SSH_PORT" "$KEYFILE" "$USER@$HONEYPOT_IP:$FIREWALL_REMOTE_PATH/dshield*" "$FIREWALL_LOCAL_PATH" &

# Sync the auth_random.json and cowrie downloaded files from the remote server to the local machine
scp -P "$SSH_PORT" "$KEYFILE" "$USER@$HONEYPOT_IP:$MALWARE_REMOTE_PATH/*.json" "$LOGS_PATH" &
scp -P "$SSH_PORT" "$KEYFILE" "$USER@$HONEYPOT_IP:$MALWARE_REMOTE_PATH/downloads/*" "$MALWARE_LOCAL_PATH/downloads" &

# Wait for all the scp processes to finish
wait


# Gunzip all the gzipped files
for file in $(find "$LOGS_PATH" -type f -name "*.gz");
do
    gunzip -vf "$file" &
done

# Rename so extension is at end and pretty print all the json files
for file in $(find "$LOGS_PATH" -type f -name "*.json*"); 
do
    if [[ ! "$file" =~ \.json$ ]]; then
        standard_extenstion_name=$(echo $file | sed 's/\.json//').json
        mv -v "$file" "$standard_extenstion_name"
        file="$standard_extenstion_name"
    fi
    (jq . -rc "$file" > "$file-pretty.json"; \
    mv "$file-pretty.json" "$file" \
    && echo "Pretty printed $file") &
    
done

# Rename all the cowrie .log files so extension is at end
for file in $(find "$COWRIE_LOCAL_PATH" -type f -name "*.log*"); 
do
    if [[ ! "$file" =~ \.log$ ]]; then
        standard_extenstion_name=$(echo $file | sed 's/\.log//').log
        mv -v "$file" "$standard_extenstion_name" &
        
    fi  
done


# Wait for all the gunzip and jq processes to finish 
wait

# Combine all the dshield files into one file and delete the individual files
dshield_files=$(find "$FIREWALL_LOCAL_PATH" -type f -name "dshield*")
cat $(printf "%s\n" "${dshield_files[@]}" | sort -t. -r -k4,4) >> "$FIREWALL_LOCAL_PATH/combined-dshield.log"
rm -v $(printf "%s" "${dshield_files[@]}")
mv -v "$FIREWALL_LOCAL_PATH/combined-dshield.log" "$FIREWALL_LOCAL_PATH/dshield.log"


# Print disk usage on remote server
ssh "$KEYFILE" -p $SSH_PORT $USER@$HONEYPOT_IP "df -h /"

exit 0


