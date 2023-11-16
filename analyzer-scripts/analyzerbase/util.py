from .common import *

def standardize_cmdlog(command):
    regexes = [
        re.compile(r"/bin/busybox (\w+)"),
        re.compile(r"/tmp/([\w\d]+)"),
        re.compile(r"/tmp/[\w\d]+ ([\w/\+]+)"),
        re.compile(r"(\d+\.\d+\.\d+\.\d+[:/]\d+)")
    ]

    for regex in regexes:
        
        for match in regex.finditer(command):
            random_str = match.group(1)
            replacement_str = "X" #* len(random_str)
            command = command.replace(random_str, replacement_str)
    
    return command

def extract_ips(string):
    regex = re.compile(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})")
    return set(regex.findall(string))

def extract_urls(string):
    regex = re.compile(r"(([\w\d\-]+\.)+([\w\d\-]+))")
    urls = {}
    for match in regex.finditer(string):
        url = match.group(1)
        extract = tldextract.extract(url)
        if extract.suffix and extract.suffix != "sh":
            urls [url] = extract 

    return urls