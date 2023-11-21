user="ubuntu"
remote_server="54.67.87.80"
ssh_port="12222"
keyfile="dshield.pem"

scp -i $keyfile  -P $ssh_port  -r "./zeek/scripts" "$user@$remote_server:/home/ubuntu/zeek/"
ssh -i $keyfile $user@$remote_server -p $ssh_port 'sudo chmod +x ./zeek/scripts/*.sh'

#scp -i $keyfile  -P $ssh_port  -r "$user@$remote_server:/opt/zeek/share/zeek/site/local.zeek" "zeek/local.zeek"