from .osintbase import *


class IPAnalyzer(OSINTAnalyzerBase):
    SOURCES = ["isc", "whois", "cybergordon", "threatfox", "shodan"]

    def __init__(self,
                 db_path=Path("./db/ipdb"),
                 selenium_webdriver_type="chrome",
                 webdriver_path="./resources/chromedriver",
                 sources=["isc", "whois", "cybergordon",
                          "threatfox", "shodan"],
                 max_errors={
                     "isc": 5,
                     "whois": 2,
                     "cybergordon": 1,
                     "threatfox": 1,
                     "shodan": 1
                 }):

        super().__init__(db_path, selenium_webdriver_type,
                         webdriver_path, sources, max_errors)

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
        output = self.get_output_template(url)

        self.scraper.gotos(url)
        whois_data_elm = self.scraper.wait_for_visible_element(
            By.ID, "registryData")
        soup = self.scraper.soup

        if "Security Check" in soup.text and not whois_data_elm:
            raise RateLimitError("ERROR: Captcha required")

        if "Invalid domain name" in soup.text:
            output["error"] = "ERROR: Invalid domain name"
            return output

        if whois_data_elm and hasattr(whois_data_elm, "text"):
            whois_text = whois_data_elm.text
            output["results"]["whois_text"] = whois_text
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
                # "priority": priority,
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
            malware_url = "https://threatfox.abuse.ch" + \
                malware.find("a")["href"]

            self.scraper.gotos(ioc_url, 4)
            self.scraper.wait_for_visible_element(By.ID, "ioc")
            soup = self.scraper.soup

            ioc_data = {tr.find("th").text.strip(": "): tr.find(
                "td").text.strip() for tr in soup.find_all("tr")}
            ioc_data["Malware alias"] = ioc_data.get("Malware alias", "")

            self.scraper.gotos(malware_url, 4)
            self.scraper.wait_for_visible_element(
                By.ID, "malware_table_wrapper")
            soup = self.scraper.soup

            malware_data = {tr.find("th").text.strip(":"): tr.find(
                "td").text.strip() for tr in soup.find("table").find_all("tr")}
            malware_data["Malware alias"] = malware_data.get(
                "Malware alias", "")

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
            raise RateLimitError(
                "ERROR: (RATE LIMIT) Please create an account to view more results.")
            # return output

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
            header_elm = soup.find("h6", {"id": port}) or soup.find(
                "div", {"id": port})
            if not header_elm:
                continue

            header_text_list = header_elm.text.split()
            unix_epoch = int(header_text_list[0])
            timestamp = header_text_list[2]
            protocol = header_text_list[-1]

            header_siblings = header_elm.parent.contents
            port_data_elm = header_siblings[header_siblings.index(
                header_elm) + 2]

            try:
                service_name = port_data_elm.find("h1").text.strip()
            except:
                # port_data_elm.find("h1").text.strip()
                service_name = "unknown"

            service_data_raw = port_data_elm.find("pre").text.strip()
            service_dict = {}
            current_key = "sig"

            for line_num, line in enumerate(service_data_raw.split("\n")):
                if line_num == 0:
                    service_dict[current_key] = line
                    continue

                if ":" in line:
                    split_line = line.split(":", 1)
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

        # ISC COUNTS
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
                    data["counts"][f"port{port}"][subkey].update(subval)
                else:
                    data["counts"][f"port{port}"][subkey][subval] += 1

        return data

    def count_whois(self, data, ip):
        """Not implemented yet but needed to maintain check/count/reduce_{source} interface"""
        # TODO add whois counts
        return data

    def reduce_isc(self, results):
        """
        Reduce isc results to only relevant fields to reduce tokens before passing to AI model.
        Also renames fields to be more verbose to improve AI comprehension.
        """
        reduced_results = {}
        reduced_results['total_reports'] = results.pop("count", None)
        reduced_results['honeypots_targeted'] = results.pop("attacks", None)
        reduced_results['firstseen'] = results.pop("mindate", None)
        reduced_results['lastseen'] = results.pop("maxdate", None)
        reduced_results['network'] = results.pop("network", None)
        reduced_results['asname'] = results.pop("asname", None)
        reduced_results['as_country_code'] = results.pop("ascountry"), None

        weblogs = results.pop("weblogs", None)
        if weblogs:
            reduced_results['weblogs'] = weblogs

        reduced_results['threatfeeds'] = results.pop("threatfeeds", None)
        return reduced_results

    def reduce_cybergordon(self, results):
        """
        Reduce cybergordon results to only relevant fields to reduce tokens before passing to AI model.
        Also renames fields to be more verbose to improve AI comprehension.
        """
        reduced_results = {}
        for priority in ["high", "medium"]:
            for result in results[priority]:
                reduced_results[result["engine"]] = result["result"]
        return reduced_results

    def reduce_shodan(self, results):
        """
        Reduce shodan results to only relevant fields to reduce tokens before passing to AI model.
        Also renames fields to be more verbose to improve AI comprehension.
        """
        reduced_results = {}
        for port, port_data in results.get("ports", {}).items():
            if port_data["service_name"] != "unknown":
                del port_data["service_data_raw"]

            del port_data["service_data"]
            del port_data["timestamp"]
            del port_data['unix_epoch']

            reduced_results[f"port{port}"] = port_data

        return reduced_results

    def reduce_threatfox(self, results):
        """
        Reduce threatfox results to only relevant fields to reduce tokens before passing to AI model.
        Also renames fields to be more verbose to improve AI comprehension.
        """

        remove_keys = ["IOC ID", "UUID", "Reporter",
                       "Reward", "Tags", "Reference"]
        reduced_results = recursive_pop(results, remove_keys=remove_keys)
        return reduced_results

    def reduce_whois(self, results):
        """
        Reduce whois results to only relevant fields to reduce tokens before passing to AI model.
        Also renames fields to be more verbose to improve AI comprehension.
        """
        # TODO: Implement reduce_whois after parsing whois data
        return results
