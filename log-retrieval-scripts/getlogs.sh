#!/bin/bash

user="ubuntu"
remote_server="54.67.87.80"
ssh_port="12222"
keyfile="dshield.pem"


logdir_path="/Users/lucasfaudman/Documents/SANS/internship/tests/logs"
zeek_local_path="${logdir_path}/zeek"
web_local_path="${logdir_path}/web"
cowrie_local_path="${logdir_path}/cowrie"
firewall_local_path="${logdir_path}/firewall"
malware_local_path="${logdir_path}/malware"

zeek_remote_logs_dir="/srv/zeek/logs/aggregate"
web_remote_logs_dir="/srv/db"
cowrie_remote_logs_dir="/srv/cowrie/var/log/cowrie"
firewall_remote_logs_dir="/var/log"
malware_remote_logs_dir="/srv/cowrie/var/lib/cowrie"



mkdir -p "$zeek_local_path"
mkdir -p "$web_local_path"
mkdir -p "$cowrie_local_path"
mkdir -p "$firewall_local_path"
mkdir -p "$malware_local_path"
mkdir -p "$malware_local_path/downloads"


# Sync the logs from the remote server to the local machine 
scp -P "$ssh_port" -i "$keyfile" "$user@$remote_server:$zeek_remote_logs_dir/*.log" "$zeek_local_path" &
scp -P "$ssh_port" -i "$keyfile" "$user@$remote_server:$web_remote_logs_dir/*.json" "$web_local_path" &
scp -P "$ssh_port" -i "$keyfile" "$user@$remote_server:$cowrie_remote_logs_dir/*cowrie*" "$cowrie_local_path" &
scp -P "$ssh_port" -i "$keyfile" "$user@$remote_server:$firewall_remote_logs_dir/dshield*" "$firewall_local_path" &

# Sync the malware files from the remote server to the local machine
scp -P "$ssh_port" -i "$keyfile" "$user@$remote_server:$malware_remote_logs_dir/*.json" "$logdir_path" &
scp -P "$ssh_port" -i "$keyfile" "$user@$remote_server:$malware_remote_logs_dir/downloads/*" "$malware_local_path/downloads" &

wait


#TIMESTAMP=$(date +%s)
ssh -i $keyfile -p $ssh_port $user@$remote_server "df -h /"




# function rename_cowrie_logs() {
#     for file in $(find "$cowrie_local_path" -type f -name "*$extension*" 2> /dev/null); 
#     do
#         if [[ ! "$file" =~ cowrie\$extension$ ]]; then
#             name_on_honeypot=$(echo $file | sed 's/\$extension//' | sed s/cowrie/cowrie\$extension/)
#             mv -v "$file" "$name_on_honeypot"
#         fi  
#     done
# }
# # Rename cowrie logs to prevent wasteful IO during rsync
# rename_cowrie_logs .json
# rename_cowrie_logs .log