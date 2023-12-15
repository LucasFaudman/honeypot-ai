from analyzerbase import *

from loganalyzers.logparser import WebLogParser


class WebLogAnalyzer:
    """Processes web logs to create WebAttack object (NOT IMPLEMENTED YET)"""

    def __init__(self, parser: WebLogParser, 
                 remove_ips=MYIPS, 
                 attacks_path=test_attacks_path):

        self.parser = parser
        self.events = defaultdict(list)
        self.requests = defaultdict(Counter)
        self.urls = defaultdict(Counter)
        self.useragents = defaultdict(Counter)
        self.attacks_path = Path(attacks_path)
        self.remove_ips = remove_ips



    def process(self, ip_list=[]):
        for event in self.parser.logs:
            if event["src_ip"] in ip_list or not ip_list:
                

                request = {
                    "version": event["version"],
                    "method": event["method"],
                    "url": event["url"],
                    "headers": event["headers"],
                    "data": event["data"],
                    "response": event["response_id"],
                }
                self.events[event["src_ip"]].append(event)
                self.requests[event["src_ip"]].update((str(request),))
                self.urls[event["src_ip"]].update((event["url"],))
                self.useragents[event["src_ip"]].update((event["headers"].get("useragent"),))
    

    def analyze(self):
        #TODO: implement this

        self.print_requests()
        self.print_urls()
        self.print_useragents()


    def print_requests(self):
        for ip, requests in self.requests.items():
            print(f"IP: {ip}")
            print(f"Total requests: {sum(requests.values())}")
            print(f"Unique requests: {len(requests)}")
            print("Count\tRequest")   
            for request, count in requests.items():
                print(f"{count}\t{request}")
                print()

            
    def print_urls(self):
        for ip, urls in self.urls.items():
            print(f"IP: {ip}")
            print(f"Total urls: {sum(urls.values())}")
            print(f"Unique urls: {len(urls)}")
            print("Count\tURL")   
            for url, count in urls.items():
                print(f"{count}\t{url}")
                print()
    

    def print_useragents(self):
        for ip, useragents in self.useragents.items():
            print(f"IP: {ip}")
            print(f"Total useragents: {sum(useragents.values())}")
            print(f"Unique useragents: {len(useragents)}")
            print("Count\tUseragent")   
            for useragent, count in useragents.items():
                print(f"{count}\t{useragent}")
                print()
    

    def write_events(self):
        for ip, events in self.events.items():
            events = sorted(events, key=lambda x: x["timestamp"])
            for event in events:
                event["timestamp"] = str(event["timestamp"])

            with open(self.attacks_path / f"{ip}.json", "w") as f:
                json.dump(events, f, indent=4)




if __name__ == "__main__":
    pass