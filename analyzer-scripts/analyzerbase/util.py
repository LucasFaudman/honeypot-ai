from .common import *


def split_commands(commands):
    split_commands = []
    ifor_regex = re.compile(r"if .+?; then.+?fi;?|for .+?; do.+?done;?")


    for command in commands:
        
        while match := ifor_regex.search(command):

            split_cmd = ifor_regex.split(command, 1)
            split_commands.extend(cmd_part for cmd_part in split_cmd[0].split(";") if cmd_part.strip())
            split_commands.append(match.group(0))
            command = split_cmd[1].strip()

        #TODO FIX awk
        if ";" in command and not 'awk' in command:
            split_commands.extend(cmd_part.strip() for cmd_part in command.split(";") if cmd_part.strip())
        elif command:
            split_commands.append(command)
    
    return split_commands



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
    return string.replace(b"\x00", b"")



def extract_ips(string):
    ipv4_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    #ipv4_pattern = re.compile(r"(\b25[0-5]|\b2[0-4][0-9]|\b[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}")
    return set(ipv4_pattern.findall(string))


def parse_tlds(public_suffix_list_file="public_suffix_list.dat.txt"):
    #TODO WRITE W REWQUESTS https://publicsuffix.org/list/public_suffix_list.dat
    tlds = set()
    with open(public_suffix_list_file) as f:
        for line in f:
            line = line.strip()
            if "." in line:
                end = line.split(".")[-1]
                if end.isalpha() and end !="sh":
                    tlds.update((end.lower(),))
                
    with open("tlds.txt", "w+") as f:
        for tld in sorted(tlds):
            f.write(tld + "\n")

    return tlds



def read_tlds(tlds_file="tlds.txt"):
    with open(tlds_file) as f:
        tlds = set(line.strip() for line in f)
    return tlds



def find_urls_and_ips(text):
    url_pattern = re.compile(r'https?://\S+|www\.\S+')
    ipv4_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    ipv6_pattern = re.compile(r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b')

    urls = url_pattern.findall(text)
    ipv4_addresses = ipv4_pattern.findall(text)
    ipv6_addresses = ipv6_pattern.findall(text)

    return urls, ipv4_addresses, ipv6_addresses



def extract_urls(string,tlds=set(read_tlds())):
    regex = re.compile(r"(([\w\d\-]+\.)+([\w\d\-]+))") #17.82s
    urls = {}
    for match in regex.finditer(string):
        url = match.group(1)
        parsed_url = urlparse(url)

        
        if not tlds or set((parsed_url.netloc.split(".")[-1], parsed_url.path.split(".")[-1])).intersection(tlds): 
           urls [url] = parsed_url

        # if parsed_url.netloc.split(".")[-1] in tlds or parsed_url.path.split(".")[-1] in tlds: 
        #     urls [url] = parsed_url

    return urls



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
    
    return hashlib.sha256(string).hexdigest()


def rprint(*args, **kwargs):
    """Print and return the string"""
    print(*args, **kwargs)
    return kwargs.get("sep", " ").join(str(arg) for arg in args) + kwargs.get("end", "\n")



def rpprint(*args, **kwargs):
    """Pretty Print and return the string"""
    pprint(*args, **kwargs)
    return kwargs.get("sep", " ").join(str(arg) for arg in args) + kwargs.get("end", "\n")








if __name__ == "__main__":
    pass