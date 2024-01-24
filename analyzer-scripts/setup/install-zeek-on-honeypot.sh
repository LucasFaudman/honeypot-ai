USER="<USER>"
HONEYPOT_IP="<HONEYPOT_IP>"
SSH_PORT="<SSH_PORT>"
KEYFILE="<KEYFILE>"

scp -P "$SSH_PORT" "$KEYFILE" -r "setup/zeek-setup" "$USER@$HONEYPOT_IP:/home/$USER/zeek-setup"
ssh -p "$SSH_PORT" "$KEYFILE" "$USER@$HONEYPOT_IP" "cd zeek-setup && chmod +x *.sh && sudo ./install-zeek. && sudo ./run-zeek-as-service.sh"