from analyzerbase import *
from .soupscraper import *

import requests
# from time import sleep

class IPAnalyzer:
    def __init__(self, db_path=str(test_logs_path).replace("logs", 'ipdb'), output_path=test_attacks_path, selenium_webdriver_type="chrome", webdriver_path="/Users/lucasfaudman/Documents/SANS/internship/chromedriver") -> None:
        
        self.db_path = Path(db_path)
        if not self.db_path.exists():
            self.db_path.mkdir(parents=True)


        #self.output_path = Path(output_path)
        self.scraper = SoupScraper(selenium_webdriver_type=selenium_webdriver_type, 
                                   selenium_service_kwargs={"executable_path":webdriver_path}, 
                                   selenium_options_kwargs={}, 
                                   keep_alive=True)
        


    def __del__(self):
        self.scraper.quit()


    def get_empty_ouput(self, sharing_link, default_results={}, default_error=""):
        return {"sharing_link": sharing_link, 
                "results": default_results, 
                "error": default_error}


    def check_isc(self, ip):
        url = f"https://isc.sans.edu/api/ip/{ip}?json"
        response = requests.get(url)
        output = response.json()
        output["sharing_link"] = f"https://isc.sans.edu/ipinfo/{ip}"
        
        # TODO ADD ERROR TO output["error"] if in response
        # error key already added to output if error {"error":"bad IP address"}

        if not output.get("results"):
            output["results"] = {}
        
        return output
    


    def check_whois(self, ip):
        url = f"https://www.whois.com/whois/{ip}"
        output = {
            "sharing_link": url,
            "results": {},
            "error": ""
        }


        self.scraper.gotos(url)

        whois_data_elm = self.scraper.wait_for_visible_element(By.ID, "registryData")

        soup = self.scraper.soup
        if "Invalid domain name" in soup.text:
            output["error"] = "ERROR: Invalid domain name"
            return output
        
        
        if whois_data_elm and hasattr(whois_data_elm, "text"):
            whois_text = whois_data_elm.text 
        
            output["results"]["whois_text"] = whois_text
            output["results"]["whois_list"] = list(line.split(":", 1) for line in whois_text.split("\n") \
                                                if not line.startswith("%") 
                                                and ":" in line
                                            )
                # TODO improve whois parsing

        else:
            output["error"] = "ERROR: No whois data found. Uncaught error."
        
        
        return output
        

    def check_cybergordon(self, ip):
        url = 'https://cybergordon.com'
        output = {
            "sharing_link": url,
            "results": defaultdict(list),
            "error": ""
        }

        self.scraper.gotos(url)
        ip_input = self.scraper.wait_for_visible_element(By.ID, "obs")
        ip_input.send_keys(ip)
        analyze_button = self.scraper.find_element(By.ID, "button-addon2")
        analyze_button.click()
        sleep(5)
        self.scraper.wait_for_visible_element(By.ID, "request_info")

        soup = self.scraper.soup
        if not soup.find("kbd"):
            output["error"] = "ERROR: Failed to get results from CyberGordon"
            return output
        else:
            sharing_link = soup.find("kbd").text
            output["sharing_link"] = sharing_link

        
        result_table = soup.find("table", {"id": "gordon_result_table"})
        if not result_table:
            output["error"] = "ERROR: No results found"
            return output

        
        result_table_rows = result_table.find_all("tr")
        for row in result_table_rows[1:]:
            observable, _type, engine, result = row.find_all("td")
            if "table-danger" in observable["class"]:
                priority = "high"
            elif "table-warning" in observable["class"]:
                priority = "medium"
            elif result.text == "Not found ":
                priority = "none"   
            elif result.text == "Quota/Rate limit error ":
                priority = "error"
            else:
                priority = "low"
            
            output["results"][priority].append({
                #"priority": priority,
                "observable": observable.text,
                "type": _type.text,
                "engine": engine.text,
                "result": result.text,
                "url": result.find("a")["href"]
            })

        return output
    
    

    def check_threatfox(self, ip):
        url = f"https://threatfox.abuse.ch/browse"
        self.scraper.goto(url)
        url = f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{ip}"
        self.scraper.gotos(url)

        output = {"sharing_link": url, 
                  "results": [],
                  "error": ""
                  }


        self.scraper.wait_for_visible_element(By.ID, "iocs")
        soup = self.scraper.soup
        results_table = soup.find("table", {"id": "iocs"})

        if not results_table:
            output["error"] = "ERROR: No results table found:\n" + soup.text
            return output

        results_table_rows = results_table.find_all("tr")
        if len(results_table_rows) < 2:
            output["error"] = "ERROR: No results found in table:\n" + soup.text
            return output


        for row in results_table_rows[1:]:
            try:
                date, ioc, malware, tags, reporter = row.find_all("td")
            except:
                continue

            
            ioc_url = "https://threatfox.abuse.ch" + ioc.find("a")["href"]
            malware_url = "https://threatfox.abuse.ch" + malware.find("a")["href"]

            self.scraper.gotos(ioc_url, 4)
            self.scraper.wait_for_visible_element(By.ID, "ioc")
            soup = self.scraper.soup

            ioc_data = {tr.find("th").text.strip(": "): tr.find("td").text.strip() for tr in soup.find_all("tr")}

            self.scraper.gotos(malware_url, 4)
            self.scraper.wait_for_visible_element(By.ID, "malware_table_wrapper")
            soup = self.scraper.soup

            malware_data = {tr.find("th").text.strip(":"): tr.find("td").text.strip() for tr in soup.find("table").find_all("tr")}


            output["results"].append({
                "date": date.text,
                "ioc": ioc.text,
                "ioc_url": ioc_url,
                "ioc_data": ioc_data,
                "malware": malware.text.strip(), 
                "malware_url": malware_url,
                "malware_data": malware_data,
                "tags": tags.text.split(),
                "reporter": reporter.text
            })

        return output
    
    
    def check_shodan(self, ip):
        url = f"https://www.shodan.io/host/{ip}"

        output = {"sharing_link": url,
                 "results": defaultdict(dict),
                 "error": ""
                 }

        self.scraper.gotos(url)
        self.scraper.wait_for_visible_element(By.ID, "ports")
        soup = self.scraper.soup
        
        
        
        
        results_table = soup.find("table")

        # if '404: Not Found' in [span.text for span in soup.find_all("span")] or not results_table:
        if '404: Not Found' in soup.text:
            output["error"] = 'ERROR: 404: Not Found'
            return output
        
        elif "Please create an account to view more results." in soup.text:
            output["error"] = 'ERROR: (RATE LIMIT) Please create an account to view more results.'
            return output

        elif not results_table:
            output["error"] = 'ERROR: No results table found'
            return output


        for tr in results_table.find_all("tr"):
            key_td, val_td = tr.find_all("td")
            key = key_td.text.strip()    
            val = val_td.text.strip()
            output["results"]["general"][key] = val
        

        for a in soup.find("div", {"id": "ports"}).find_all("a"):
            port = a.text.strip()
            header_elm = soup.find("h6", {"id":port}) or soup.find("div", {"id":port})
            if not header_elm:
                continue

            header_text_list = header_elm.text.split()
            unix_epoch = int(header_text_list[0])
            timestamp = header_text_list[2]
            protocol = header_text_list[-1]

            header_siblings = header_elm.parent.contents
            port_data_elm = header_siblings[header_siblings.index(header_elm) + 2]
            
            try:
                service_name =  port_data_elm.find("h1").text.strip()
            except:
                service_name = "unknown" #port_data_elm.find("h1").text.strip()

            service_data_raw = port_data_elm.find("pre").text.strip()
            service_dict = {}
            current_key = "sig"
            

            for line_num, line in enumerate(service_data_raw.split("\n")):
                if line_num == 0:
                    service_dict[current_key] = line
                    continue
                
                if ":" in line:
                    split_line = line.split(":",1)
                    key = split_line[0]

                    if len(split_line) > 1 and split_line[1].strip() != "":
                        val = split_line[1].strip()
                    else:
                        val = []
                    
                    current_key = key
                    service_dict[current_key] = val

                elif line == "":
                     continue
                
                elif line.startswith("\t"):
                    service_dict[current_key].append(line.strip())

                else:
                     service_dict[current_key] += line

            
            output["results"]["ports"][port] = {
                "unix_epoch": unix_epoch,
                "timestamp": timestamp,
                "protocol": protocol,
                "service_name": service_name,
                "service_data": service_dict,
                "service_data_raw": service_data_raw
            }   

        return output



    def get_data(self, ips):
        data = {}
        for ip in ips:
            data[ip] = {}
            for source in ["isc", "whois", "cybergordon", "threatfox", "shodan"]:
                try:
                    saved_source_data = self.read_data_for_source(ip, source)
                    if saved_source_data:
                        data[ip][source] = saved_source_data
                        continue
                    
                    source_data = getattr(self, f"check_{source}")(ip)
                    data[ip][source] = source_data
                    self.write_data_for_source(ip, source, source_data)
                
                except Exception as e:
                    err_msg = f"ERROR: Error caught while getting data for {ip} from {source}: {e}"
                    data[ip][source] = self.get_empty_ouput("", {}, err_msg)
                    continue
        
        return data
    


    def read_data_for_source(self, ip, source):

        ip_source_file = self.db_path / f"{source}/{ip}.json"
        if ip_source_file.exists():
        
            with ip_source_file.open() as f:
                return json.loads(f.read())



    def write_data_for_source(self, ip, source, data):

        ip_source_file = self.db_path / f"{source}/{ip}.json"
        if not ip_source_file.parent.exists():
            ip_source_file.parent.mkdir(parents=True)
        
        with ip_source_file.open("w+") as f:
            json.dump(data, f, indent=2)
        


# if __name__ == "__main__":
#     analyzer = IPAnalyzer()
#     ips = ['80.94.92.20']
#     print(analyzer.check_shodan(ip))

#     # tfd = analyzer.check_threatfox(ips[0])
#     # print(tfd)
# #    #print(analyzer.check_whois(ip))
# #     #print(analyzer.check_isc(ip))
# #     #print(analyzer.check_cybergordon(ip))
# #     #print(analyzer.check_abuseipdb(ip))
# #     #print(analyzer.check_threatfox(ip))
# #     #print(analyzer.check_virustotal(ip))
#     data = analyzer.get_data(ips)
   
#     print(data)    
#     analyzer.scraper.quit()
#     print()
