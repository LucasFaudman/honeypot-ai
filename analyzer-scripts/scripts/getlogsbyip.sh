
attack_dir="tests/attacks"
logs_dir="tests/logs"
ip=$1

if [[ ! -d "$attack_dir/$ip-logs" ]]; then
    mkdir -p "$attack_dir/$ip-logs"
fi

for file_with_ip in $(grep -l "$ip" -R "$logs_dir"); do
    echo "File $file_with_ip contains IP $ip"

    logs_by_ip_file="$attack_dir/$ip-logs/$(basename $file_with_ip)"

    if [[ "$file_with_ip" =~ "zeek" ]]; then
        # Add headers to .zeek files
        head -n8 "$file_with_ip" > "$logs_by_ip_file"
        grep -a "$ip" "$file_with_ip" >> "$logs_by_ip_file"

    elif [[ ! "$file_with_ip" =~ auth_random ]]; then
        #echo $file is not auth-random.json or .zeek
        grep -a "$ip" "$file_with_ip" > "$logs_by_ip_file"

    else
        #Get result for ip from auth_random.json
        jq -r '.['\"$ip\"']' "$file_with_ip" > "$logs_by_ip_file"                        
    fi

done