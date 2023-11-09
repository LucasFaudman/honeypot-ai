#/bin/bash
logdir_local_path="/Users/lucasfaudman/Documents/SANS/internship/tests/logs"

zeek_local_path="${logdir_local_path}/zeek"
web_local_path="${logdir_local_path}/weblogs"
cowrie_local_path="${logdir_local_path}/cowrie"
firewall_local_path="${logdir_local_path}/firewall"
malware_local_path="${logdir_local_path}/malware"


for file in $(find "$logdir_local_path" -type f -name "*.json*"); 
do
    if [[ ! "$file" =~ \.json$ ]]; then
        standard_extenstion_name=$(echo $file | sed 's/\.json//').json
        mv -v "$file" "$standard_extenstion_name"
        file="$standard_extenstion_name"
    fi
    jq . -rc "$file" > pretty.json && mv pretty.json "$file"
    #echo "Pretty printed $file"

done


for file in $(find "$cowrie_local_path" -type f -name "*.log*"); 
do
    if [[ ! "$file" =~ \.log$ ]]; then
        standard_extenstion_name=$(echo $file | sed 's/\.log//').log
        mv -v "$file" "$standard_extenstion_name"
        file="$standard_extenstion_name"
    fi  
done

for file in $(find "$logdir_local_path" -type f -name "*.gz");
do
    gunzip -vf "$file"
done


