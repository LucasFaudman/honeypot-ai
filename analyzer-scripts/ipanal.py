import os
import pathlib
import json

local_logs_path = pathlib.Path("/Users/lucasfaudman/Documents/SANS/internship/logs")
local_attacks_path = pathlib.Path("/Users/lucasfaudman/Documents/SANS/internship/pattacks")

zeek_local_destination = local_logs_path / "zeek"
web_local_destination = local_logs_path / "weblogs"
cowrie_local_destination = local_logs_path / "cowrie"
firewall_local_destination = local_logs_path / "firewall"
malware_local_destination = local_logs_path / "malware"
maleware_hashes = os.listdir(malware_local_destination / "downloads")

all_logs = list(local_logs_path.rglob("*")) 

