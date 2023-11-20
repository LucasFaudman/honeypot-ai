from analyzerbase import *


class LogParser:
    def __init__(self, log_path=test_logs_path, attacks_path=test_attacks_path, remove_ips=MYIPS, overwrite=True):
        
        self.log_path = pathlib.Path(log_path)
        self.attacks_path = pathlib.Path(attacks_path)
        self.overwrite = overwrite
        self.remove_ips = remove_ips
        
        self._all_logs = []
        


    def find_log_filepaths(self, start_path="", pattern="*", sort_fn=None):
        if callable(sort_fn):
            yield from sorted(list(self.find_log_filepaths(start_path, pattern)), key=sort_fn)

        else:
            start_path  = self.log_path / start_path
            for file in start_path.rglob(pattern):
                if file.is_file():
                    yield file


    def load_json_logs(self, file):
        for n, line in enumerate(file.open()):
            try:
                event = json.loads(line)
                #event["line"] = line
                yield self.standardize(event)
            except json.decoder.JSONDecodeError:
                print(f"Error decoding: {line}\n(line {n} of {file})")
    
    def standardize(self, event):
        # Implement this in a subclass
        return event
    
    @property
    def all_logs(self):
        if not self._all_logs:
            self._all_logs = list(self.find_log_filepaths())
        yield from self._all_logs

    def get_matching_lines(self, filepath, pattern, flags=0):
        # read_mode = "r" if isinstance(pattern, str) else "rb"
        read_mode = "rb"
        cmpld_pattern = re.compile(pattern, flags) if not isinstance(pattern, re.Pattern) else pattern
        
        with open(filepath, read_mode) as f:
            for line in f:
                if cmpld_pattern.search(line):
                    yield line


    def write_matching_lines(self, from_file, to_file, pattern, flags=0):
        #write_mode = "w+" if isinstance(pattern, str) else "wb+"
        write_mode = "wb+"
        with open(to_file, write_mode) as f:
            for line in self.get_matching_lines(from_file, pattern, flags):
                f.write(line)
    


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



    @property
    def logs(self):
        for file in self.find_log_filepaths("cowrie", "*.json*", sort_fn=self.sort_cowrie_log_names):
            #yield file
            yield from self.load_json_logs(file)


    def standardize(self, event):
        event["timestamp"] = datetime.strptime(event["timestamp"], "%Y-%m-%dT%H:%M:%S.%fZ")
        #event["sip"] = event.pop("src_ip")
        #event["dip"] = event.pop("dst_ip")
        #event["sport"] = event.pop("src_port")
        #event["dport"] = event.pop("dst_port")
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


    @property
    def logs(self):
        for file in self.find_log_filepaths("weblogs", "*.json", sort_fn=self.sort_weblog_names):
            #yield file
            yield from self.load_json_logs(file)

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
    @property
    def logs(self):
        for file in self.find_log_filepaths("firewall", "dshield*.log*"):
            for line in file.open():
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
    

if __name__ == "__main__":
    cr = CowrieParser()
    for log in cr.logs:
        print(log)

    wr = WebLogParser()
    for log in wr.logs:
        print(log)
