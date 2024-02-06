USER="ubuntu"
HONEYPOT_IP="54.67.87.80"
SSH_PORT="12222"
KEYFILE="dshield.pem"

if [ ! -z "$KEYFILE" ]; then
    KEYFILE="-i$KEYFILE"
else
    KEYFILE="" 
    echo "No keyfile provided. Using password authentication."
fi

scp -P "$SSH_PORT" "$KEYFILE" -r "setup/zeek-setup" "$USER@$HONEYPOT_IP:/home/$USER/zeek-setup"
ssh -p "$SSH_PORT" "$KEYFILE" "$USER@$HONEYPOT_IP" "cd zeek-setup && chmod +x *.sh && sudo ./install-zeek. && sudo ./run-zeek-as-service.sh"