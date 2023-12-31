from .osintbase import *


class IPAnalyzer(OSINTAnalyzerBase):
    SOURCES = ["isc", "whois", "cybergordon", "threatfox", "shodan"]

    def __init__(self, 
                 db_path=Path("tests/ipdb"), 
                 selenium_webdriver_type="chrome", 
                 webdriver_path="/Users/lucasfaudman/Documents/SANS/internship/chromedriver",
                 max_errors={
                        "isc": 5,
                        "whois": 2,
                        "cybergordon": 1,
                        "threatfox": 1,
                        "shodan": 1
                 }):
        
        super().__init__(db_path, selenium_webdriver_type, webdriver_path, max_errors)




    def check_isc(self, ip, arg_type="ip"):
        """Gets ISC data for ip"""

        url = f"https://isc.sans.edu/api/ip/{ip}?json"
        response = requests.get(url)

        
        output = response.json()
        output["sharing_link"] = f"https://isc.sans.edu/ipinfo/{ip}"
        

        # TODO ADD ERROR TO output["error"] if in response
        # error key already added to output if error {"error":"bad IP address"}

        output["results"] = output.pop("ip")
        
        return output
    

    
    def check_whois(self, ip, arg_type="ip"):
        """Gets whois data for ip"""
        url = f"https://www.whois.com/whois/{ip}"
        output = self.get_empty_ouput(url)


        self.scraper.gotos(url)



        whois_data_elm = self.scraper.wait_for_visible_element(By.ID, "registryData")

        soup = self.scraper.soup
        
        #if "Please respond to the question below to continue." in soup.text:
        if  "Security Check" in soup.text and not whois_data_elm:
            raise RateLimitError("ERROR: Captcha required")


        if "Invalid domain name" in soup.text:
            output["error"] = "ERROR: Invalid domain name"
            return output
        
        
        if whois_data_elm and hasattr(whois_data_elm, "text"):
            whois_text = whois_data_elm.text 
        
            output["results"]["whois_text"] = whois_text
            #output["results"]["whois_list"] = list(line.split(":", 1) for line in whois_text.split("\n") \
            #                                    if not line.startswith("%") 
            #                                    and ":" in line
            #                                )
                # TODO improve whois parsing

        else:
            output["error"] = "ERROR: No whois data found. Uncaught error."
        
        
        return output
        

    def check_cybergordon(self, ip, arg_type="ip"):
        """Gets CyberGordon data for ip"""

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
        if "HTTP 403 Forbidden" in soup.text:
            raise RateLimitError("HTTP 403 Forbidden")

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
    
    

    def check_threatfox(self, ip, arg_type="ip"):
        """Gets ThreatFox data for ip"""

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
    
    
    def check_shodan(self, ip, arg_type="ip"):
        """Gets Shodan data for ip"""

        url = f"https://www.shodan.io/host/{ip}"

        output = {"sharing_link": url,
                 "results": defaultdict(dict),
                 "error": ""
                 }

        self.scraper.gotos(url)
        self.scraper.wait_for_visible_element(By.ID, "ports")
        soup = self.scraper.soup
        
        
        results_table = soup.find("table")

        if '404: Not Found' in soup.text:
            output["error"] = 'ERROR: 404: Not Found'
            return output
        
        elif "Please create an account to view more results." in soup.text:
            output["error"] = 'ERROR: (RATE LIMIT) Please create an account to view more results.'
            raise RateLimitError("ERROR: (RATE LIMIT) Please create an account to view more results.")
            #return output

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



    
    def count_isc(self, data, ip):
        """Updates data["counts"] with counts from isc data for ip"""

        #ISC COUNTS
        isc_data = data[ip]["isc"]["results"]
        for key, val in isc_data.items():
            if val in [None, "number"]:
                continue

            if isinstance(val, int) and not key.startswith("as"):
                data["counts"]["isc"][key]["total"] += val

            if isinstance(val, (list, dict)):
                if key == "weblogs":
                    data["counts"]["isc"][key]["total"] += val.get("count", 0)
                else:
                    data["counts"]["isc"][key].update(list(val))
            else:
                data["counts"]["isc"][key][val] += 1
        
        return data


    def count_cybergordon(self, data, ip):
        """Updates data["counts"] with counts from cybergordon data for ip"""

        # CyberGordon COUNTS
        cybergordon_data = data[ip]["cybergordon"]["results"]
        for priority, results in cybergordon_data.items():
            for result in results:
                data["counts"]["cybergordon"][result["engine"]][priority] += 1
                data["counts"]["cybergordon"][result["engine"]]["total"] += 1
                
                if priority in ["high", "medium", "low"]:
                    data["counts"]["cybergordon"][result["engine"]]["alerts"] += 1
    
        return data

    def count_threatfox(self, data, ip):
        """Updates data["counts"] with counts from threatfox data for ip"""

        # ThreatFox COUNTS
        threatfox_data = data[ip]["threatfox"]["results"]
        for result in threatfox_data:
            for key in ["IOC ID", "IOC Type", "Threat Type", "Malware", "Confidence Level"]:
                data["counts"]["threatfox"][key][result["ioc_data"][key]] += 1
                
            data["counts"]["threatfox"]["tags"].update(result["tags"])
            aliases = result["malware_data"]["Malware alias"].split(", ")
            data["counts"]["threatfox"]["Malware alias"].update(aliases)
        
        return data

    def count_shodan(self, data, ip):
        """Updates data["counts"] with counts from shodan data for ip"""

        # Shodan COUNTS
        shodan_data = data[ip]["shodan"]["results"]

        for key, val in shodan_data.get("general", {}).items():
            data["counts"]["shodan"][key][val] += 1

        for port, port_data in shodan_data.get("ports", {}).items():
            data["counts"]["shodan"]["protocol"][port_data["protocol"]] += 1
            data["counts"]["shodan"]["service_name"][port_data["service_name"]] += 1
            data["counts"]["shodan"]["sig"][port_data["service_data"]["sig"]] += 1
            data["counts"]["shodan"]["service_data_raw"][port_data["service_data_raw"]] += 1
            data["counts"]["shodan"]["ports"][port] += 1

            for subkey, subval in port_data["service_data"].items():
                if isinstance(subval, (list, dict)):
                    subval = list(subval)
                    #data["counts"]["shodan"][subkey].update(subval)
                    data["counts"][f"port{port}"][subkey].update(subval)
                else:
                    #data["counts"]["shodan"][subkey][subval] += 1
                    data["counts"][f"port{port}"][subkey][subval] += 1

        return data


    def count_whois(self, data, ip):
        """Not implemented yet but needed to maintain check/count/reduce_{source} interface"""       
        #TODO add whois counts
        return data


    

    def get_attack_data_for_ips(self, attack, ips, sources=SOURCES):
        """
        TODO REFACTOR to base.get_reduced_data with self.reduce_<source> interface

        Attack Postprocessor method used by AI assistant in _do_tool_call. 
        Gets ipdata using get_data then reduces JSON structure to reduce tokens
        before passing to AI. 
        """
        
        # Get ipdata for all ips and sources to be reduced and returned to AI
        ipdata = self.get_data(args=ips, arg_type="ip", sources=sources, update_counts=False)
        # Copy full ipdata before reducing to attach to attack object 
        # full_ipdata = deepcopy(ipdata)

        for ip in ips:
            for source in sources:

                if ipdata[ip][source]['results']:
                    #Only leave results and reduce nesting by one level
                    ipdata[ip][source] = ipdata[ip][source]['results']

                else:
                    #Only leave error message
                    ipdata[ip][source] = ipdata[ip][source].get('error')
                    continue

                if source == "isc":
                    reduced_isc_data = {}
                    reduced_isc_data['total_reports'] = ipdata[ip][source].pop("count", None)
                    reduced_isc_data['honeypots_targeted'] = ipdata[ip][source].pop("attacks", None)
                    reduced_isc_data['firstseen'] = ipdata[ip][source].pop("mindate", None)
                    reduced_isc_data['lastseen'] = ipdata[ip][source].pop("maxdate", None)
                    reduced_isc_data['network'] = ipdata[ip][source].pop("network", None)
                    reduced_isc_data['asname'] = ipdata[ip][source].pop("asname", None)
                    reduced_isc_data['as_country_code'] = ipdata[ip][source].pop("ascountry")   , None 

                    weblogs = ipdata[ip][source].pop("weblogs", None)
                    if weblogs:
                        reduced_isc_data['weblogs'] = weblogs

                    reduced_isc_data['threatfeeds'] = ipdata[ip][source].pop("threatfeeds", None)

                    ipdata[ip][source] = reduced_isc_data



                if source == 'cybergordon':
                    reduced_cybergordon_data = {}
                    for priority in ["high", "medium"]:
                        for result in ipdata[ip][source][priority]:
                            reduced_cybergordon_data[result["engine"]] = result["result"]
                    
                    ipdata[ip][source] = reduced_cybergordon_data

                if source == "shodan":
                    reduced_shodan_data = {}
                    for port, port_data in ipdata[ip][source].get("ports", {}).items():
                        if port_data["service_name"] != "unknown":
                            del port_data["service_data_raw"]

                        del port_data["service_data"]
                        del port_data["timestamp"]
                        del port_data['unix_epoch']
                        
                        ipdata[ip][source][f"port{port}"] = port_data
                    
                    ipdata[ip][source].pop("ports", None)

                if source == "threatfox":
                    reduced_threatfox_data = []
                    for result in ipdata[ip][source]:
                        result["ioc_data"].pop('IOC ID', None)
                        result["ioc_data"].pop('UUID', None)
                        result["ioc_data"].pop('Reporter', None)
                        result["ioc_data"].pop('Reward', None)
                        result["ioc_data"].pop('Tags', None)
                        result["ioc_data"].pop('Reference', None)
                        

                        reduced_threatfox_data.append(result["ioc_data"])
                    
                    ipdata[ip][source] = reduced_threatfox_data


        # if attack:
        #     #attack.full_ipdata = full_ipdata
        #     attack.reduced_ipdata = ipdata

        return ipdata


        
if __name__ == "__main__":
    pass
