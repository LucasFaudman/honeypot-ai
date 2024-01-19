from analyzerbase import *


class LogParser:
    def __init__(self, logs_path=Path('./logs')):
        
        self.logs_path = Path(logs_path)        
        self._all_log_filepaths = []
        self._logs = []
        

    def set_logs_path(self, logs_path):
        self.logs_path = Path(logs_path)
        self._all_log_filepaths = []
        self._logs = []


    def find_log_filepaths(self, 
                           start_path: Union[str, Path]="",
                           pattern="*", 
                           sort_fn=None, 
                           max_depth=None,
                           depth=0                           
                           ):
        """Yields all log filepaths matching pattern in start_path and its subdirectories.
        If sort_fn is provided, sorts the filepaths by sort_fn and yields them in sorted order.
        If max_depth is provided, only searches up to max_depth levels deep.
        """


        if callable(sort_fn):
            # Recursively calls itself with sort_fn=None and other params unchanged to get unsorted list of filepaths, 
            # then it sorts list by sort_fn and yields each filepath from the sorted list
            yield from sorted(list(self.find_log_filepaths(start_path, pattern, None, max_depth, depth)), 
                              key=sort_fn)
        else:
            # If sort_fn is not provided, recursively yields filepaths from start_path and its subdirectories
            start_path  = self.logs_path / start_path if isinstance(start_path, str) else start_path
            
            if max_depth is None:
                # rglob searches all subdirectories recursively when max_depth is None
                for file in start_path.rglob(pattern):
                    if file.is_file():
                        yield file
            else:
                # glob only searches one level deep when max_depth is not None
                for file in start_path.glob(pattern):
                    if file.is_dir() and (not max_depth or depth < max_depth):
                        # Recursively calls itself with start_path=file and depth=depth+1 to search subdirectory
                        yield from self.find_log_filepaths(file, pattern, None, max_depth, depth+1)


    def load_json_logs(self, file):
        with file.open() as f:
            for n, line in enumerate(f):
                try:
                    yield json.loads(line)
                except json.decoder.JSONDecodeError:
                    print(f"Error decoding: {line}\n(line {n} of {file})")
    

    # def standardize(self, event):
    #     # Implement this in a subclass
    #     return event
    
    
    def logs(self):
        # Implement this in a subclass
        return (NotImplementedError,)

    
    def all_log_filepaths(self):
        if not self._all_log_filepaths:
            self._all_log_filepaths = list(self.find_log_filepaths())
        return self._all_log_filepaths
        #yield from self._all_log_filepaths


    def nlogs(self, limit=0):

        for n, event in enumerate(self.logs()):
            if n >= limit:
                break
            yield event



class CowrieParser(LogParser):
    TIMESTAMP_EXAMPLE = "2023-11-05T00:18:22.144852Z"
    TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%S.%fZ"
    """
{"eventid":"cowrie.session.connect","src_ip":"120.194.142.48","src_port":57364,"dst_ip":"172.31.5.68","dst_port":2223,"session":"e4c5fd9d8965","protocol":"telnet","message":"New connection: 120.194.142.48:57364 (172.31.5.68:2223) [session: e4c5fd9d8965]","sensor":"","timestamp":"2023-11-05T01:48:52.248601Z"}
{"eventid":"cowrie.session.closed","duration":30.96518325805664,"message":"Connection lost after 30 seconds","sensor":"","timestamp":"2023-11-05T01:49:23.213678Z","src_ip":"120.194.142.48","session":"e4c5fd9d8965"}
    """

    @staticmethod
    def sort_cowrie_log_names(file):
        if "-" in file.name:
            yr, mo, day = map(int, file.name.split(".")[1].split("-")[:3])
            return (yr, mo, day)
        else:
            return (9999, 99, 99)


    
    def logs(self):
        for file in self.find_log_filepaths("cowrie", "*.json*", sort_fn=self.sort_cowrie_log_names):
            yield from map(self.standardize, self.load_json_logs(file))
            

    @property
    def auth_random(self):
        if not hasattr(self, "_auth_random"):
            self._auth_random = json.loads((self.logs_path / "auth_random.json").read_bytes())
        return self._auth_random
                

    def standardize(self, event):
        event["timestamp"] = datetime.strptime(event["timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ")
        return event



class WebLogParser(LogParser):
    """
    EXAMPLE LOG: 
    {"time": "2023-10-25T20:40:18.979518", "headers": {"host": "13.52.76.92:8080", "user-agent": "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)", "accept": "*/*", "accept-encoding": "gzip"}, "sip": "162.142.125.12", "dip": "13.52.76.92", "method": "GET", "url": "/", "data": null, "useragent": ["Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)"], "version": "HTTP/1.1", "response_id": {"comment": null, "headers": {"Server": "Apache/3.2.3", "Access-Control-Allow-Origin": "*", "content-type": "text/plain"}, "status_code": 200}, "signature_id": {"max_score": 72, "rules": [{"attribute": "method", "condition": "equals", "value": "GET", "score": 2, "required": false}, {"attribute": "headers", "condition": "absent", "value": "user-agents", "score": 70, "required": false}]}}
  
    """
    TIMESTAMP_FORMAT = "2023-10-25T21:59:41.922314"

    @staticmethod
    def sort_weblog_names(file):
        if "-" in file.name:
            yr, mo, day = map(int, file.name.split(".")[0].split("-")[1:4])
            return (yr, mo, day)
        else:
            return (9999, 99, 99)


    
    def logs(self):
        for file in self.find_log_filepaths("web", "*.json", sort_fn=self.sort_weblog_names):
            #yield file
            yield from map(self.standardize, self.load_json_logs(file))

    def standardize(self, event):
        event["timestamp"] = datetime.strptime(event.pop("time"), "%Y-%m-%dT%H:%M:%S.%f")
        event["src_ip"] = event.pop("sip")
        event["dst_ip"] = event.pop("dip")
        return event



class DshieldParser(LogParser):
    """
    EXAMPLE LOG: 
    1699144322 BigDshield kernel:[39210.572534]  DSHIELDINPUT IN=eth0 OUT= MAC=06:a6:67:a1:06:97:06:47:24:e8:0b:15:08:00 SRC=162.216.150.90 DST=172.31.5.68 LEN=44 TOS=0x00 PREC=0x00 TTL=244 ID=54321 PROTO=TCP SPT=52388 DPT=50001 WINDOW=65535 RES=0x00 SYN URGP=0 
    """

    
    def logs(self):
        for file in self.find_log_filepaths("firewall", "dshield*.log*"):
            with file.open() as f:
                for line in f:
                    yield self.parse_dshield_line(line)
            


    def parse_dshield_line(self, line):
        parts = line.split()
        event = {}

                
        event["timestamp"] = datetime.fromtimestamp(int(parts.pop(0)))
        for part in parts:
            if "=" in part:
                k, v = part.split("=")
                if k == "SRC":
                    k = "src_ip"
                elif k == "DST":
                    k = "dst_ip"
                elif k == "SPT":
                    k = "src_ip"
                elif k == "DPT":
                    k = "dst_ip"

                if v.isdigit():
                    v = int(v)

                event[k] = v
            else:
                continue
                
        return event
    

class ZeekParser(LogParser):
    """
#separator \x09
#set_separator	,
#empty_field	(empty)
#unset_field	-
#path	http
#open	2023-12-03-13-38-52
#fields	ts	uid	id.orig_h	id.orig_p	id.resp_h	id.resp_p	trans_depth	method	host	uri	referrer	version	user_agent	origin	request_body_len	response_body_len	status_code	status_msg	info_code	info_msg	tags	username	password	proxied	orig_fuids	orig_filenames	orig_mime_types	resp_fuids	resp_filenames	resp_mime_types	cookie_vars	uri_vars
#types	time	string	addr	port	addr	port	count	string	string	string	string	string	string	string	count	count	count	string	count	string	set[enum]	string	string	set[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]	vector[string]
1701610732.952279	C57bIgUaQUd7GBmI8	172.31.5.68	38580	169.254.169.254	80	1	PUT	169.254.169.254	/latest/api/token	-	1.0	aws-sdk-go/1.44.260 (go1.20.7; linux; amd64)	-	0	56	200	OK	-	-	(empty)	-	-	-	-	-	-	FKN4Ld2lnN48Scfdk	-	text/plain	-	/latest/api/token
1701610732.953904	C7CrTo4tyLsay89Hg6	172.31.5.68	38590	169.254.169.254	80	1	GET	169.254.169.254	/latest/meta-data/instance-id	-	1.0	aws-sdk-go/1.44.260 (go1.20.7; linux; amd64)	-	0	19	200	OK	-	-	(empty)	-	-	-	-	-	-	FzCHPt49yKEXSgYV29	-	text/plain	-	/latest/meta-data/instance-id
1701610732.955381	CERCKo14FaIWqP1vYa	172.31.5.68	38602	169.254.169.254	80	1	GET	169.254.169.254	/latest/dynamic/instance-identity/document	-	1.0	aws-sdk-go/1.44.260 (go1.20.7; linux; amd64)	-	0	475	200	OK	-	-	(empty)	-	-	-	-	-	-	FLPquZ35AVvP0uIQTd	-	text/json	-	/latest/dynamic/instance-identity/document
1701610733.056330	CpbR0q4JbNuEfXLakb	172.31.5.68	38612	169.254.169.254	80	1	GET	169.254.169.254	/latest/meta-data/instance-id	-	1.0	aws-sdk-go/1.44.260 (go1.20.7; linux; amd64)	-	0	19	200	OK	-	-	(empty)	-	-	-	-	-	-	FTXhNdHSXScCMFei6	-	text/plain	-	/latest/meta-data/instance-id
    """
    TIMESTAMP_FORMAT = "2023-10-25T21:59:41.922314"

    #  zeek_log_types=("http", "conn", "dns", "ssl", "dhcp", "weird", "files", "ftp", "smtp", "smb", "tunnel", "x509")
    def __init__(self, 
                 logs_path=Path("./logs"), 
                 zeek_log_ext=".log", 
                 zeek_log_types=("http", "conn"), 
                 keep_empty_fields=True, 
                 keep_unset_fields=False
                 ):
        super().__init__(logs_path)
        self.zeek_log_ext = zeek_log_ext
        self.zeek_log_types = zeek_log_types
        self.keep_empty_fields = keep_empty_fields
        self.keep_unset_fields = keep_unset_fields

    
    def convert_zeek_to_json(self, file, write_json=False):
        file_info = {}
        headers = []
        data_types = {}
        
        #To store log for writing if write_json is True
        json_log = []

        handle_as_str_types = ("string", "enum", "addr", "subnet", "interval", 
                               "function", "event", "hook", "file", "opaque", "any")

        with file.open() as f:
            for line in f:
                if line.startswith("#"):
                    key, val = line[1:].split(None, 1)
                    val = val.encode().decode('unicode_escape').rstrip("\n")

                    file_info[key] = val
                    
                    if key == "fields":
                        headers = val.split(file_info["separator"])
                    elif key == "types":
                        data_types = val.split(file_info["separator"])

                    
                else:
                    try:
                        event = {}
                        values = line.rstrip("\n").split(file_info["separator"])

                        for header, data_type, value in zip(headers, data_types, values):
                            if value == file_info["empty_field"]:
                                if not self.keep_empty_fields:
                                    continue
                                value = ""
                            elif value == file_info["unset_field"]:
                                if not self.keep_unset_fields:
                                    continue
                                value = None
                            elif data_type == "bool":
                                value = bool(value)
                            elif data_type in ("int", "count", "port"):
                                value = int(value)
                            elif data_type in ("double", "time", "duration"):
                                value = float(value)
                            
                            elif "[" in data_type:
                                outer_type, inner_type = data_type.rstrip("]").split("[")
                                if inner_type in handle_as_str_types:
                                    value = value.split(file_info["set_separator"])
                                # if outer_type == "set":
                                #     value = set(value)

                            elif data_type in handle_as_str_types:
                                value = value
                            else:
                                print(f"Unknown data type: {data_type}")
                                value = value



                            event[header] = value

                        event["protocol"] = event.get('service', file.stem)
                        event["eventid"] = f"zeek.{file.stem}.log.event"
                        yield event
                    
                        # Store event for writing if write_json is True
                        if write_json:
                            json_log.append(event) 
                
                    except Exception as e:
                        print(f"Error parsing line: {line}\n{e}")
                        continue

        if write_json:
            json_file = file.with_suffix(".json")
            with json_file.open("w+") as f:
                for event in json_log:
                    f.write(json.dumps(event) + "\n")

            print(f"Converted {file} to {json_file}")
        

            
    def logs(self, only_log_types=()):
        only_log_types = only_log_types or self.zeek_log_types
        for file in self.find_log_filepaths("zeek", "*" + self.zeek_log_ext):
            if file.stem in only_log_types:
                if self.zeek_log_ext == ".log":
                    yield from map(self.standardize, self.convert_zeek_to_json(file))
                elif self.zeek_log_ext == ".json":
                    yield from map(self.standardize, self.load_json_logs(file))

    

    def standardize(self, event):
        event["timestamp"] = datetime.fromtimestamp(event.pop("ts", 0))
        event["session"] = event.pop("uid", None)
        replace_keys = {
            "src_ip" : "id.orig_h",
            "src_port" : "id.orig_p",
            "dst_ip" : "id.resp_h",
            "dst_port" : "id.resp_p",
        }

        for k, v in replace_keys.items():
            v = event.pop(v, None)
            if v:
                event[k] = v

        return event
    

LOG_PARSERS = {
    "cowrie" : CowrieParser,
    "web" : WebLogParser,
    "dshield" : DshieldParser,
    "zeek" : ZeekParser,
}




