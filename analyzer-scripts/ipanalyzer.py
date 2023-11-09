import requests
import pathlib

from soupscraper import *
from time import sleep



class IPAnalyzer:
    def __init__(self, output_path="tests/attacks", selenium_webdriver_type="chrome", webdriver_path="/Users/lucasfaudman/Documents/SANS/internship/chromedriver") -> None:
        self.output_path = pathlib.Path(output_path)
        self.scraper = SoupScraper(selenium_webdriver_type=selenium_webdriver_type, 
                                   selenium_service_kwargs={"executable_path":webdriver_path}, 
                                   selenium_options_kwargs={}, 
                                   keep_alive=True)

    def check_isc(self, ip):
        url = f"https://isc.sans.edu/api/ip/{ip}?json"
        response = requests.get(url)
        return response.json()

    def check_whois(self, ip):
        url = f"https://www.whois.com/whois/{ip}"
        self.scraper.goto(url)
        sleep(5)

        whois_data = self.scraper.wait_for_visible_element(By.ID, "registryData")
        output = {
            "whois_data": whois_data.text,
            #"whois_png": whois_data.screenshot_as_png,
            "whois_list": list(line.split(":") for line in whois_data.text.split("\n") if not line.startswith("%") and ":" in line)
        }
        
        
        return output 
        
    def check_cybergordon(self, ip):
        url = 'https://cybergordon.com'
        self.scraper.goto(url)
        sleep(5)
        ip_input = self.scraper.wait_for_visible_element(By.ID, "obs")
        ip_input.send_keys(ip)
        analyze_button = self.scraper.find_element(By.ID, "button-addon2")
        analyze_button.click()
        sleep(5)
        self.scraper.wait_for_visible_element(By.ID, "request_info")

        soup = self.scraper.soup
        sharing_link = soup.find("kbd").text
        result_table = soup.find("table", {"id": "gordon_result_table"})
        result_table_rows = result_table.find_all("tr")
        
        output = {
            "sharing_link": sharing_link,
            "results":[]
            #"results_png": result_table.screenshot_as_png
        }

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
            
            output["results"].append({
                "priority": priority,
                "observable": observable.text,
                "type": _type.text,
                "engine": engine.text,
                "result": result.text,
                "url": result.find("a")["href"]
            })

        return output
    
    # def check_abuseipdb(self, ip):
    #     url = f"https://www.abuseipdb.com/check/{ip}"
    #     self.scraper.goto(url)
        
    #     soup = self.scraper.soup
    #     return 


    def check_threatfox(self, ip):
        url = f"https://threatfox.abuse.ch/browse"
        self.scraper.goto(url)
        url = f"https://threatfox.abuse.ch/browse.php?search=ioc%3A{ip}"
        self.scraper.goto(url)
        sleep(5)
        self.scraper.wait_for_visible_element(By.ID, "iocs")
        soup = self.scraper.soup
        results_table = soup.find("table", {"id": "iocs"})
        results_table_rows = results_table.find_all("tr")

        output = {"sharing_link": url, 
                  "results": []}
        for row in results_table_rows[1:]:
            date, ioc, malware, tags, reporter = row.find_all("td")     
            output["results"].append({
                "date": date.text,
                "ioc": ioc.text,
                "ioc_url": "https://threatfox.abuse.ch" + ioc.find("a")["href"],
                "malware": malware.text.strip(), 
                "malware_url": "https://threatfox.abuse.ch" + malware.find("a")["href"],
                "tags": tags.text.split(),
                "reporter": reporter.text
            })

        return output

if __name__ == "__main__":
    analyzer = IPAnalyzer()
    #ip = "2.237.57.70"
    ip = '80.94.92.20'
   #print(analyzer.check_whois(ip))
    #print(analyzer.check_isc(ip))
    #print(analyzer.check_cybergordon(ip))
    #print(analyzer.check_abuseipdb(ip))
    print(analyzer.check_threatfox(ip))

    analyzer.scraper.quit()
    print()
