
attack_dir="tests/attacks"
logs_dir="tests/logs"
ip=$1

if [[ ! -d "$attack_dir/$ip" ]]; then
    mkdir -p "$attack_dir/$ip"
fi

for file_with_ip in $(grep -l "$ip" -R "$logs_dir"); do
    echo "File $file_with_ip contains IP $ip"

    logs_by_ip_file="$attack_dir/$ip/$(basename $file_with_ip)"

    if [[ ! "$file_with_ip" =~ auth_random ]]; then
        #echo $file is not auth-random.json
        grep -a "$ip" "$file_with_ip" > "$logs_by_ip_file"
    else
        jq -r '.['\"$ip\"']' "$file_with_ip" > "$logs_by_ip_file"                        
    fi

done