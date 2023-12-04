What is the goal of this attack?
The goal of this attack was to **spawn a shell on the remote system** so the attacker could gain access to the system and perform further actions.
This is evident by the fact that the script redirects the file descriptors for `stdin`, `stdout`, and `stderr` to the socket file descriptor and attempts to spawn a shell on the remote system using the `pty` module .
The attacker ran the malware script with the arguments `-l 100.100.101.101 -p 4444` which means the attacker was trying to connect to the attacker system with IP address `100.100.101.101` on port `4444`.
If the attacker was successful in spawning a shell on the remote system they would be able to execute commands on the remote system and gain access to the system.
The attacker could then use the shell to perform further actions such as downloading and executing additional malware on the system and using the system to attack other systems on the network.