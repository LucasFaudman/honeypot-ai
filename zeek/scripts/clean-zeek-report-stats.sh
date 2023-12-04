
echo "DISK USAGE BEFORE:"
df -h /
echo "\nSYSTEM USAGE BEFORE:"
echo "System load: $(uptime | awk -F 'load average: ' '{print $2}' | cut -d, -f1)"
echo "Usage of /: $(df -h / | awk 'NR==2 {print $5}') of $(df -h / | awk 'NR==2 {print $2}')"
echo "Users logged in: $(who | wc -l)"
echo "Memory usage: $(free -m | awk 'NR==2 {print $3/$2*100}')%"
echo "IPv4 address for eth0: $(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+')"
echo "Swap usage: $(free | awk 'NR==4 {print $3/$2*100}')%"

echo "\nDeleting zeek logs"
for file in /srv/zeek/logs/*.log; do sed -i '$!d' $file; done
echo "Done"

echo "DISK USAGE AFTER:"
df -h /
# echo "\nSYSTEM USAGE AFTER:"
echo "System load: $(uptime | awk -F 'load average: ' '{print $2}' | cut -d, -f1)"
echo "Usage of /: $(df -h / | awk 'NR==2 {print $5}') of $(df -h / | awk 'NR==2 {print $2}')"
echo "Users logged in: $(who | wc -l)"
echo "Memory usage: $(free -m | awk 'NR==2 {print $3/$2*100}')%"
echo "IPv4 address for eth0: $(ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+\.\d+\.\d+\.\d+')"
echo "Swap usage: $(free | awk 'NR==4 {print $3/$2*100}')%"

