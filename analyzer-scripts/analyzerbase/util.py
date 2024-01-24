from .common import *
from .baseobjects import SetReprOrderedSet

from hashlib import sha256
from pprint import pprint
from io import StringIO
from urllib.parse import urlparse

import subprocess
import shlex


def run_command_with_shlex(command, args, subprocess_kwargs={"shell": True}):
    if isinstance(args, (list, tuple, set)):
        args = [command] + [shlex.quote(str(arg)) for arg in args]
    else: 
        args = [command, shlex.quote(args)]
        
    result = subprocess.run(args, capture_output=True, text=True, **subprocess_kwargs)
    return result.stdout


def split_commands(commands):
    split_cmds = []
    block_regex = re.compile(r"if .+?; then.+?fi;?|(?:for|while) .+?; do.+?done;?|case .+?esac;?")
    

    for command in commands:
        
        while match := block_regex.search(command):

            split_cmd = block_regex.split(command, 1)
            #split_cmds.extend(cmd_part for cmd_part in split_cmd[0].split(";") if cmd_part.strip())
            split_cmds.extend(split_commands([split_cmd[0],]))
        
            if split_cmd[1] and split_cmd[1].strip()[0] in ("<", ">", "|"):
                split_cmds.append(match.group(0) + split_cmd[1])
                command = ""
            else:
                split_cmds.append(match.group(0))
                command = split_cmd[1].strip()

        #TODO FIX awk
        if ";" in command and not 'awk' in command:
            split_cmds.extend(cmd_part.strip() for cmd_part in command.split(";") if cmd_part.strip())
        elif command:
            split_cmds.append(command)
    
    return split_cmds



def standardize_by_regexes(string, regexes, replacement_str="X"):
    #replacement_str = replacement_str if isinstance(string, str) else replacement_str.encode()
    replacement_str = replacement_str.encode() if isinstance(string, bytes) and isinstance(replacement_str, str) else replacement_str 
    replacement_str = replacement_str.decode() if isinstance(string, str) and isinstance(replacement_str, bytes) else replacement_str

    for regex in regexes:    
        for match in regex.finditer(string):
            random_str = match.group(1)
            string = string.replace(random_str, replacement_str)
    
    return string


def standardize_cmdlog(command):
    regexes = [
        re.compile(r"/bin/busybox (\w+)"),
        re.compile(r"/tmp/([\w\d]+)"),
        re.compile(r"/tmp/[\w\d]+ ([\w/\+]+)"),
        re.compile(r"(\d+\.\d+\.\d+\.\d+[:/]\d+)")
    ]

    return standardize_by_regexes(command, regexes)


def standardize_malware(malware_source_code: bytes):
    malware_source_code = remove_null_bytes(malware_source_code)

    regexes = [
        re.compile(rb"C0755 4745 (\S+)"),
    ]
    return standardize_by_regexes(malware_source_code, regexes)


def remove_null_bytes(string):
    if isinstance(string, str):
        return string.replace("\x00", "")
    
    return string.replace(b"\x00", b"")



def extract_ips(string):
    ipv4_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    extracted_ips = set(ipv4_pattern.findall(string))
    extracted_ips.difference_update(("127.0.0.1", "8.8.8.8"))
    return extracted_ips



def extract_urls(string):
    regex = re.compile(r"((?:https?://)([\w\d][\w\d\-/]+\.)+([\w\-]{2,}))")
    urls = {}
    for match in regex.finditer(string):
        url = match.group(1)
        parsed_url = urlparse(url)
        urls[url] = parsed_url

    return urls


def extract_hosts_from_parsed_urls(parsed_urls):
    hosts = SetReprOrderedSet(parsed_url.hostname for parsed_url in parsed_urls)
    return hosts




def print_diff_lines(string1, string2):
    lines1 = string1.split("\n")
    lines2 = string2.split("\n")

    for n, lines in enumerate(zip(lines1, lines2)):
        if lines[0] != lines[1]:
            print(f"Line {n}: {lines[0]} != {lines[1]}")    


### SHORTCUTS ###

def sha256hex(string):
    if not isinstance(string, (bytes, bytearray)):
        string = string.encode()
    
    return sha256(string).hexdigest()


def pprint_str(*args, **kwargs):
    """Pretty Print to StringIO and return the string"""
    output_buffer = StringIO()
    kwargs["stream"] = output_buffer
    pprint(*args, **kwargs)
    return output_buffer.getvalue()


def recursive_pop(d={}, 
                  keep_keys=[], 
                  remove_keys=[], 
                  replace_keys={},
                  remove_values=[None, "", {}, [], set(), tuple()],
                  replace_values={}
                  ):
    """
    Recursively remove keys from a dict.
    If remove_keys is empty, keep_keys is used instead and all other keys are removed.
    """
    
    if isinstance(d, dict):
        if remove_keys:
            for key in remove_keys:
                d.pop(key, None)

        if keep_keys:
            for key in set(d.keys()) - set(keep_keys):
                d.pop(key, None)
        
        for key, value in list(d.items()):
            value = recursive_pop(value, keep_keys, remove_keys, replace_keys, remove_values, replace_values)

            if value in list(replace_values.keys()):
                d[key] = replace_values.get(value)
                value = d[key]

            if value in remove_values:
                d.pop(key, None)
                continue
            
            elif key in replace_keys:
                new_key = replace_keys[key]
                d[new_key] = d.pop(key)
                key = new_key

            
    elif isinstance(d, (list, tuple, set, SetReprOrderedSet)):
        for item in d:
            recursive_pop(item, keep_keys, remove_keys, replace_keys, remove_values, replace_values)


    return d


if __name__ == "__main__":
    pass