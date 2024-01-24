from .common import *
from .baseobjects import SetReprOrderedSet

from hashlib import sha256
from pprint import pprint
from io import StringIO
from urllib.parse import urlparse

import subprocess
import shlex


def sha256hex(string):
    """Returns hexdigest of sha256 hash of string"""
    if not isinstance(string, bytes):
        string = string.encode()
    return sha256(string).hexdigest()


def pprint_str(*args, **kwargs):
    """Pretty Print to StringIO and return the string"""
    output_buffer = StringIO()
    kwargs["stream"] = output_buffer
    pprint(*args, **kwargs)
    return output_buffer.getvalue()


def run_command_with_shlex(command, args, subprocess_kwargs={"shell": True}):
    """Runs command with shlex.quote() on args and returns stdout"""
    if isinstance(args, (list, tuple, set)):
        args = [command] + [shlex.quote(str(arg)) for arg in args]
    else: 
        args = [command, shlex.quote(args)]
        
    result = subprocess.run(args, capture_output=True, text=True, **subprocess_kwargs)
    return result.stdout



def standardize_by_regexes(string, regexes, replacement_string="X"):
    """Replaces all capturing groups in regexes with replacement_string and returns the string"""
    
    if isinstance(string, bytes) and isinstance(replacement_string, str):
        replacement_string = replacement_string.encode()
        if isinstance(string, memoryview):
            raise NotImplementedError("Memoryview not supported")   

    elif isinstance(string, str) and isinstance(replacement_string, bytes):
        replacement_string = replacement_string.decode()
        if isinstance(replacement_string, memoryview):
            raise NotImplementedError("Memoryview not supported")

    groups = [group for regex in regexes for match in regex.finditer(string) for group in match.groups() if group]    
    for group in groups:
        string = string.replace(group, replacement_string) # type: ignore

    return string


def remove_null_bytes(string):
    """Removes null bytes from string"""
    if isinstance(string, str):
        return string.replace("\x00", "")
    else:
        return string.replace(b"\x00", b"")


def extract_ips(string):
    """Extracts all ipv4 addresses from string and returns a set"""
    ipv4_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    extracted_ips = SetReprOrderedSet(ipv4_pattern.findall(string))
    extracted_ips.difference_update(("127.0.0.1", "8.8.8.8"))
    return extracted_ips


def extract_urls(string):
    """Extracts all urls from string and returns a dict of parsed urls"""
    regex = re.compile(r"((?:https?://)([\w\d][\w\d\-/]+\.)+([\w\-]{2,}))")
    urls = {}
    for match in regex.finditer(string):
        url = match.group(1)
        parsed_url = urlparse(url)
        urls[url] = parsed_url

    return urls


def extract_hosts_from_parsed_urls(parsed_urls):
    """Extracts all hosts from parsed urls and returns an OrderedSet"""
    hosts = SetReprOrderedSet(parsed_url.hostname for parsed_url in parsed_urls)
    return hosts


def print_diff_lines(string1, string2):
    """Prints the lines that differ between string1 and string2"""
    lines1 = string1.split("\n")
    lines2 = string2.split("\n")

    for n, lines in enumerate(zip(lines1, lines2)):
        if lines[0] != lines[1]:
            print(f"Line {n}: {lines[0]} != {lines[1]}")    


def recursive_pop(d={}, 
                  keep_keys=[], 
                  remove_keys=[], 
                  replace_keys={},
                  remove_values=[None, "", {}, [], set(), tuple()],
                  replace_values={}
                  ):
    """
    Recursively remove keys from a dict.
    If keep_keys is set, only keep_keys are kept.
    If remove_keys is set, remove_keys are removed.
    If replace_keys is set and a key is in replace_keys, the key is replaced with the value in replace_keys.
    If remove_values is set, all keys whose value is in remove_values are removed.
    If replace_values is set and a value is in replace_values, the value is replaced with the value in replace_values.
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