
local_logs_path="/Users/lucasfaudman/Documents/SANS/internship/logs"
local_attacks_path="/Users/lucasfaudman/Documents/SANS/internship/zattacks"


zeek_remote_logs_dir="/srv/zeek/logs"
zeek_local_destination="${local_logs_path}/zeek"

web_remote_logs_dir="/srv/db/"
web_local_destination="${local_logs_path}/weblogs"

cowrie_remote_logs_dir="/srv/cowrie/var/log/cowrie/"
cowrie_local_destination="${local_logs_path}/cowrie/"

firewall_remote_logs_dir="/var/log/"
firewall_local_destination="${local_logs_path}/firewall/"

malware_remote_logs_dir="/srv/cowrie/var/lib/cowrie"
malware_local_destination="${local_logs_path}/malware/"


maleware_hashes=$(ls $malware_local_destination/downloads/)



for hash in $maleware_hashes; do
    attack_dir="$local_attacks_path/$hash" 
    mkdir -p $attack_dir 
    cd $attack_dir

    files_containing_hash=$(grep -l "$hash" -R "$local_logs_path")
    for file in $files_containing_hash; do
        echo "File $file contains hash $hash"

        logs_by_hash_file="$attack_dir/hash-$(basename $file)"

        grep -a "$hash" "$file" > "$logs_by_hash_file"
    
        if [[ "$file" =~ \.json$ ]]; then
            src_ips=$(jq -r '.src_ip' "$logs_by_hash_file")
            #echo "Source IPs: $src_ip"
            session_ids=$(jq -r '.session' "$logs_by_hash_file")
            #echo "Session IDs: $session_id"

            for src_ip in $src_ips; do
                files_containing_src_ip=$(grep -l "$src_ip" -R "$local_logs_path")
                
                for file in $files_containing_src_ip; do

                    logs_by_src_file="$attack_dir/$src_ip-$(basename $file)"
                    
                    if [[ ! "$file" =~ auth_random ]]; then
                        #echo $file is not auth-random.json
                        grep -a "$src_ip" "$file" > "$logs_by_src_file"
                    else
                        jq -r '.['\"$src_ip\"']' "$file" > "$logs_by_src_file"                        
                    fi
                
                done

            done

            for session_id in $session_ids; do

                files_containing_session_id=$(grep -l "$session_id" -R "$local_logs_path")
                
                for file in $files_containing_session_id; do
                    logs_by_session_file="$attack_dir/$session_id-$(basename $file)"
                    grep -a "$session_id" "$file" > "$logs_by_session_file"
                done
            
            done

        fi

    done

done